package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/moi-si/addrtrie"
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
var httpMatcher *addrtrie.DomainMatcher[int]
var domianMatcher *addrtrie.DomainMatcher[Policy]
var ipMatcher *addrtrie.BitTrie[Policy]
var ipv6Matcher *addrtrie.BitTrie6[Policy]

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

	httpMatcher = addrtrie.NewDomainMatcher[int]()
	for patterns, policy := range conf.HttpPolicy {
		for _, elem := range strings.Split(patterns, ",") {
			for _, pattern := range ExpandPattern(elem) {
				httpMatcher.Add(pattern, policy)
			}
		}
	}

	domianMatcher = addrtrie.NewDomainMatcher[Policy]()
	for patterns, policy := range conf.DomainPolicies {
		for _, elem := range strings.Split(patterns, ",") {
			for _, pattern := range ExpandPattern(elem) {
				domianMatcher.Add(pattern, policy)
			}
		}
	}

	ipMatcher = addrtrie.NewBitTrie[Policy]()
	ipv6Matcher = addrtrie.NewBitTrie6[Policy]()
	for patterns, policy := range conf.IpPolicies {
		p := policy
		for _, elem := range strings.Split(patterns, ",") {
			for _, ipOrNet := range ExpandPattern(elem) {
				if strings.Contains(ipOrNet, ":") {
					ipv6Matcher.Insert(ipOrNet, &p)
				} else {
					ipMatcher.Insert(ipOrNet, &p)
				}
			}
		}
	}

	return nil
}

func MatchIP(ip string) *Policy {
	if strings.Contains(ip, ":") {
		policy, _ := ipv6Matcher.Find(ip)
		return policy
	} else {
		return ipMatcher.Find(ip)
	}
}
