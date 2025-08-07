package main

import (
	"log"
	"net"
	"strconv"
	"time"
)

func Dial(logger *log.Logger, conn net.Conn, host string, port int) (dstConn net.Conn, policy Policy, ok bool) {
	oldTarget := net.JoinHostPort(host, strconv.Itoa(port))
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
		}
	} else {
		host = policy.IP
	}
	if policy.Port != 0 {
		port = policy.Port
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	dstConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		logger.Printf("Failed to connect to %s(%s): %v", oldTarget, target, err)
		sendReply(conn, 0x07, nil, 0)
		return
	}
	ok = true
	return
}
