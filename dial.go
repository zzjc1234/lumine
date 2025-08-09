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
	policy := MatchIP(ip)
	if policy == nil {
		return ip, nil
	}
	if policy.MapTo == "" {
		return ip, policy
	}
	mapTo := policy.MapTo
	chain := true
	if mapTo[:1] == "^" {
		mapTo = mapTo[1:]
		chain = false
	}
	if strings.Contains(mapTo, "/") {
		mapTo_, err := TransformIP(ip, mapTo)
		if err != nil {
			panic(err)
		}
		mapTo = mapTo_
	}
	if ip == mapTo {
		return ip, policy
	}
	logger.Printf("Redirect %s to %s", ip, mapTo)
	if chain {
		return ipRedirect(logger, mapTo)
	}
	return mapTo, MatchIP(mapTo)
}

func dnsQuery(domain string, qtype uint16) (string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", qtype)
	res, _, err := dnsClient.Exchange(msg, conf.DNSAddr)
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

func Dial(logger *log.Logger, conn net.Conn, host string, port int) (dstConn net.Conn, policy Policy, ttl int, ok bool) {
	var err error
	if isValidIP(host) {
		target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		dstConn, err = net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			logger.Printf("Failed to connect to %s: %v", target, err)
			sendReply(conn, 0x07, nil, 0)
			var zero Policy
			return nil, zero, 0, false
		}
		return dstConn, conf.DefaultPolicy, 0, true
	}
	var ip string
	oldTarget := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	domainPolicy := domianMatcher.Find(host)
	if domainPolicy == nil {
		policy = conf.DefaultPolicy
	} else {
		policy = MergePolicies(conf.DefaultPolicy, *domainPolicy)
	}
	if policy.IP == "" {
		if policy.IPv6First == nil || !*policy.IPv6First {
			ip, err = dnsQuery(host, dns.TypeA)
			if err != nil {
				logger.Printf("resolve failed: %s. trying IPv6.", err)
				ip, err = dnsQuery(host, dns.TypeAAAA)
				if err != nil {
					logger.Println("resolve failed:", err)
				}
			}
		} else {
			ip, err = dnsQuery(host, dns.TypeAAAA)
			if err != nil {
				logger.Printf("resolve failed: %s. trying IPv4.", err)
				ip, err = dnsQuery(host, dns.TypeA)
				if err != nil {
					logger.Println("resolve failed:", err)
				}
			}
		}
		logger.Printf("DNS %s -> %s", host, ip)
	} else {
		ip = policy.IP
	}
	if policy.Port != 0 {
		port = policy.Port
	}

	ip, ipPolicy := ipRedirect(logger, ip)
	if ipPolicy != nil {
		if domainPolicy == nil {
			policy = MergePolicies(conf.DefaultPolicy, *ipPolicy)
		} else {
			policy = MergePolicies(conf.DefaultPolicy, *ipPolicy, *domainPolicy)
		}
	}
	logger.Printf("%s -> %s", host, policy)
	target := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	if (policy.SkipParse == nil) || (policy.SkipParse != nil && !*policy.SkipParse) {
		if policy.Mode == "ban" {
			logger.Println("Connection banned")
			sendReply(conn, 0x02, nil, 0)
			var zero Policy
			return nil, zero, 0, false
		}
		if policy.Mode == "ttl-d" && policy.FakeTTL <= 0 {
			ttl, err = FindMinReachableTTL(target)
			if err != nil {
				logger.Println("Error find TTL:", err)
				sendReply(conn, 0x01, nil, 0)
				var zero Policy
				return nil, zero, 0, false
			}
			if ttl == -1 {
				logger.Println("Reachable TTL not found")
				sendReply(conn, 0x01, nil, 0)
				var zero Policy
				return nil, zero, 0, false
			}
			if conf.FakeTTLRules != "" {
				ttl, err = CalcTTL(conf.FakeTTLRules, ttl)
				if err != nil {
					logger.Println("Error calculate TTL:", err)
					sendReply(conn, 0x01, nil, 0)
					var zero Policy
					return nil, zero, 0, false
				}
			} else {
				ttl -= 1
			}
		}
	}

	dstConn, err = net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		logger.Printf("Failed to connect to %s(%s): %v", oldTarget, target, err)
		sendReply(conn, 0x07, nil, 0)
		var zero Policy
		return nil, zero, ttl, false
	}
	return dstConn, policy, ttl, true
}
