package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
)

type Config struct {
	ServerAddr     string            `json:"server_address"`
	DNSAddr        string            `json:"udp_dns_addr"`
	DefaultPolicy  Policy            `json:"default_policy"`
	DomainPolicies map[string]Policy `json:"domain_policies"`
	//IpPolicies     map[string]Policy `json:"ip_policies"`
}

var conf Config
var domianMatcher *DomainMatcher

func LoadConfig(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &conf)
	if err != nil {
		return err
	}

	domianMatcher = NewDomainMatcher()
	for patterns, policy := range conf.DomainPolicies {
		p := policy
		for pattern := range strings.SplitSeq(patterns, ",") {
			domianMatcher.Add(pattern, &p)
		}
	}

	return nil
}
