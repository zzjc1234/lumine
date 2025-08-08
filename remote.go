package main

import (
	"log"
	"net"
	"time"
	"fmt"
)

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
	oldTarget := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	domainPolicy := domianMatcher.Find(host)
	if domainPolicy == nil {
		policy = conf.DefaultPolicy
	} else {
		policy = MergePolicies(conf.DefaultPolicy, *domainPolicy)
	}
	logger.Printf("%s -> %+v", oldTarget, policy)
	if policy.IP == "" {
		ips, err := net.LookupIP(host)
		if err != nil {
			logger.Println("DNS lookup error:", err)
			return
		}
		for _, ip := range ips {
			host = ip.String()
			break
		}
	} else {
		host = policy.IP
	}
	if policy.Port != 0 {
		port = policy.Port
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	if policy.Mode == "ttl-d" && policy.FakeTTL <= 0 {
		ttl, err = FindMinReachableTTL(target)
		if err != nil {
			logger.Println("Error find TTL:", err)
			sendReply(conn, 0x01, nil, 0)
			var zero Policy
			return nil, zero, 0, false
		}
		if ttl == -1 {
			logger.Println("TTL not found")
			sendReply(conn, 0x01, nil, 0)
			var zero Policy
			return nil, zero, 0, false
		}
		ttl -= 1
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
