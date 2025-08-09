package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
)

type Config struct {
	ServerAddr        string            `json:"server_address"`
	DNSAddr           string            `json:"udp_dns_addr"`
	DefaultHttpPolicy int               `json:"default_http_policy"`
	HttpPolicy        map[string]int    `json:"http_policy"`
	FakeTTLRules      string            `json:"fake_ttl_rules"`
	DefaultPolicy     Policy            `json:"default_policy"`
	DomainPolicies    map[string]Policy `json:"domain_policies"`
	IpPolicies        map[string]Policy `json:"ip_policies"`
}

var conf Config
var httpMatcher *DomainMatcher[int]
var domianMatcher *DomainMatcher[Policy]
var ipMatcher *BitTrie

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

	httpMatcher = NewDomainMatcher[int]()
	for patterns, policy := range conf.HttpPolicy {
		for _, elem := range strings.Split(patterns, ",") {
			for _, pattern := range ExpandPattern(elem) {
				httpMatcher.Add(pattern, policy)
			}
		}
	}

	domianMatcher = NewDomainMatcher[Policy]()
	for patterns, policy := range conf.DomainPolicies {
		for _, elem := range strings.Split(patterns, ",") {
			for _, pattern := range ExpandPattern(elem) {
				domianMatcher.Add(pattern, policy)
			}
		}
	}

	ipMatcher = NewBitTrie()
	for patterns, policy := range conf.IpPolicies {
		p := policy
		for _, elem := range strings.Split(patterns, ",") {
			for _, ipOrNet := range ExpandPattern(elem) {
				ipMatcher.Insert(ipOrNet, &p)
			}
		}
	}

	return nil
}
