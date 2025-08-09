package main

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"time"
)

var dnsClient = new(dns.Client)

func ipRedirect(logger *log.Logger, ip string) (string, *Policy) {
	policy := ipMatcher.Find(ip)
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
		chain = true
	}
	if ip == mapTo {
		return ip, policy
	}
	logger.Printf("Redirect %s to %s", ip, mapTo)
	if chain {
		return ipRedirect(logger, mapTo)
	}
	return mapTo, ipMatcher.Find(mapTo)
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
		msg := new(dns.Msg)
		msg.SetQuestion(host+".", dns.TypeA)
		res, _, err := dnsClient.Exchange(msg, conf.DNSAddr)
		if err != nil {
			logger.Println("Error DNS resolve:", err)
			sendReply(conn, 0x01, nil, 0)
			var zero Policy
			return nil, zero, 0, false
		}
		for _, ans := range res.Answer {
			if aRecord, ok := ans.(*dns.A); ok {
				ip = aRecord.A.String()
				break
			}
		}
		if ip == "" {
			logger.Println("No A record for", host)
			sendReply(conn, 0x01, nil, 0)
			var zero Policy
			return nil, zero, 0, false
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
