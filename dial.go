package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var dnsClient = new(dns.Client)

func ipRedirect(logger *log.Logger, ip string) (string, *Policy) {
	policy := matchIP(ip)
	if policy == nil {
		return ip, nil
	}
	if policy.MapTo == "" {
		return ip, policy
	}
	mapTo := policy.MapTo
	var chain bool
	if mapTo[:1] == "^" {
		mapTo = mapTo[1:]
	} else {
		chain = true
	}
	if strings.Contains(mapTo, "/") {
		var err error
		mapTo, err = transformIP(ip, mapTo)
		if err != nil {
			panic(err)
		}
	}
	if ip == mapTo {
		return ip, policy
	}
	logger.Printf("Redirect %s to %s", ip, mapTo)
	if chain {
		return ipRedirect(logger, mapTo)
	}
	return mapTo, matchIP(mapTo)
}

func dnsQuery(domain string, qtype uint16) (string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", qtype)
	res, _, err := dnsClient.Exchange(msg, dnsAddr)
	if err != nil {
		return "", fmt.Errorf("error dns resolve: %v", err)
	}
	for _, ans := range res.Answer {
		switch qtype {
		case dns.TypeA:
			if record, ok := ans.(*dns.A); ok {
				return record.A.String(), nil
			}
		case dns.TypeAAAA:
			if record, ok := ans.(*dns.AAAA); ok {
				return record.AAAA.String(), nil
			}
		}
	}
	return "", errors.New("record not found")
}

func dial(logger *log.Logger, conn net.Conn, host string, port uint16) (dstConn net.Conn, policy *Policy, ttl int, ok bool) {
	var err error
	var ip string

	if isValidIP(host) {
		ip, policy = ipRedirect(logger, host)
		if policy == nil {
			policy = &defaultPolicy
		} else {
			policy = MergePolicies(defaultPolicy, *policy)
		}
	} else {
		domainPolicy := domainMatcher.Find(host)
		found := domainPolicy != nil
		if found {
			policy = MergePolicies(defaultPolicy, *domainPolicy)
		} else {
			policy = &defaultPolicy
		}
		if policy.IP == "" {
			if policy.IPv6First == nil || !*policy.IPv6First {
				ip, err = dnsQuery(host, dns.TypeA)
				if err != nil {
					if policy.ResolveRetry != nil && *policy.ResolveRetry {
						logger.Printf("Failed to resolve: %v. Trying IPv6.", err)
						ip, err = dnsQuery(host, dns.TypeAAAA)
						if err != nil {
							logger.Println("Retry failed:", err)
							sendReply(conn, 0x01, nil, 0)
							return nil, nil, 0, false
						}
					} else {
						logger.Println("Error resolve:", err)
						sendReply(conn, 0x01, nil, 0)
						return nil, nil, 0, false
					}
				}
			} else {
				ip, err = dnsQuery(host, dns.TypeAAAA)
				if err != nil {
					if policy.ResolveRetry != nil && *policy.ResolveRetry {
						logger.Printf("Failed to resolve: %v. Trying IPv4.", err)
						ip, err = dnsQuery(host, dns.TypeA)
						if err != nil {
							logger.Println("Retry failed:", err)
							sendReply(conn, 0x01, nil, 0)
							return nil, nil, 0, false
						}
					} else {
						logger.Println("Error resolve:", err)
						sendReply(conn, 0x01, nil, 0)
						return nil, nil, 0, false
					}
				}
			}
			logger.Printf("DNS %s -> %s", host, ip)
		} else {
			ip = policy.IP
		}
		var ipPolicy *Policy
		ip, ipPolicy = ipRedirect(logger, ip)
		if ipPolicy != nil {
			if found {
				policy = MergePolicies(defaultPolicy, *ipPolicy, *domainPolicy)
			} else {
				policy = MergePolicies(defaultPolicy, *ipPolicy)
			}
		}
	}
	if policy.Mode == "block" {
		logger.Println("Connection blocked")
		sendReply(conn, 0x02, nil, 0)
		return nil, nil, 0, false
	}
	if policy.Port != 0 {
		port = policy.Port
	}

	logger.Printf("%s -> %s", host, policy)
	target := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	if policy.Mode == "ttl-d" {
		if policy.FakeTTL == 0 {
			ttl, err = FindMinReachableTTL(target)
			if err != nil {
				logger.Println("Error find TTL:", err)
				sendReply(conn, 0x01, nil, 0)
				return nil, nil, 0, false
			}
			if ttl == -1 {
				logger.Println("Reachable TTL not found")
				sendReply(conn, 0x01, nil, 0)
				return nil, nil, 0, false
			}
			if fakeTTLRules != "" {
				ttl, err = calcTTL(fakeTTLRules, ttl)
				if err != nil {
					logger.Println("Error calculate TTL:", err)
					sendReply(conn, 0x01, nil, 0)
					return nil, nil, 0, false
				}
			} else {
				ttl -= 1
			}
		} else {
			ttl = policy.FakeTTL
		}
	}

	dstConn, err = net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		logger.Printf("Failed to connect to %s: %v", target, err)
		sendReply(conn, 0x01, nil, 0)
		return nil, nil, 0, false
	}
	sendReply(conn, 0x00, nil, 0)
	return dstConn, policy, ttl, true
}
