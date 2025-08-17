package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/moi-si/addrtrie"
)

type Policy struct {
	IP           string  `json:"ip"`
	MapTo        string  `json:"map_to"`
	Port         uint16  `json:"port"`
	ResolveRetry *bool   `json:"resolve_retry"`
	IPv6First    *bool   `json:"ipv6_first"`
	HttpMode     string  `json:"http_mode"`
	TLS13Only    *bool   `json:"tls13_only"`
	Mode         string  `json:"mode"`
	NumRecords   int     `json:"num_records"`
	FakePacket   string  `json:"fake_packet"`
	FakeTTL      int     `json:"fake_ttl"`
	FakeSleep    float64 `json:"fake_sleep"`
}

func (p Policy) String() string {
	fields := []string{}
	if p.IP != "" {
		fields = append(fields, "IP: "+p.IP)
	}
	if p.Port != 0 {
		fields = append(fields, fmt.Sprintf("port=%d", p.Port))
	}
	if p.IPv6First != nil && *p.IPv6First {
		fields = append(fields, "ipv6_first")
	}
	if p.ResolveRetry != nil && *p.ResolveRetry {
		fields = append(fields, "resolve_retry")
	}
	fields = append(fields, fmt.Sprintf("http %s", p.HttpMode))
	fields = append(fields, p.Mode)
	switch p.Mode {
	case "tls-rf":
		fields = append(fields, fmt.Sprintf("%d records", p.NumRecords))
		if p.TLS13Only != nil && *p.TLS13Only {
			fields = append(fields, "tls13_only")
		}
	case "ttl-d":
		fields = append(fields, "fake_packet: "+escape(p.FakePacket))
		if p.FakeTTL == 0 {
			fields = append(fields, "auto_fake_ttl")
		} else {
			fields = append(fields, fmt.Sprintf("fake_ttl=%d", p.FakeTTL))
		}
		fields = append(fields, fmt.Sprintf("fake_sleep=%v", p.FakeSleep))
		if p.TLS13Only != nil && *p.TLS13Only {
			fields = append(fields, "tls13_only")
		}
	}
	return strings.Join(fields, " | ")
}

func MergePolicies(policies ...Policy) *Policy {
	var merged Policy
	for _, p := range policies {
		if p.IP != "" {
			merged.IP = p.IP
		}
		if p.MapTo != "" {
			merged.MapTo = p.MapTo
		}
		if p.ResolveRetry != nil {
			merged.ResolveRetry = p.ResolveRetry
		}
		if p.Port != 0 {
			merged.Port = p.Port
		}
		if p.HttpMode != "" {
			merged.HttpMode = p.HttpMode
		}
		if p.TLS13Only != nil {
			merged.TLS13Only = p.TLS13Only
		}
		if p.Mode != "" {
			merged.Mode = p.Mode
		}
		if p.NumRecords != 0 {
			merged.NumRecords = p.NumRecords
		}
		if p.FakePacket != "" {
			merged.FakePacket = p.FakePacket
		}
		if p.FakeSleep != 0 {
			merged.FakeSleep = p.FakeSleep
		}
		if p.FakeTTL != 0 {
			merged.FakeTTL = p.FakeTTL
		}
	}
	return &merged
}

type Config struct {
	ServerAddr        string            `json:"server_address"`
	DNSAddr           string            `json:"udp_dns_addr"`
	DefaultHttpPolicy int               `json:"default_http_policy"`
	FakeTTLRules      string            `json:"fake_ttl_rules"`
	DefaultPolicy     Policy            `json:"default_policy"`
	DomainPolicies    map[string]Policy `json:"domain_policies"`
	IpPolicies        map[string]Policy `json:"ip_policies"`
}

var (
	defaultPolicy         Policy
	dnsAddr, fakeTTLRules string
	domainMatcher         *addrtrie.DomainMatcher[Policy]
	ipMatcher             *addrtrie.BitTrie[Policy]
	ipv6Matcher           *addrtrie.BitTrie6[Policy]
)

func loadConfig(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var conf Config
	if err = decoder.Decode(&conf); err != nil {
		return "", err
	}
	defaultPolicy = conf.DefaultPolicy
	dnsAddr = conf.DNSAddr
	fakeTTLRules = conf.FakeTTLRules

	domainMatcher = addrtrie.NewDomainMatcher[Policy]()
	for patterns, policy := range conf.DomainPolicies {
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, pattern := range expandPattern(elem) {
				domainMatcher.Add(pattern, policy)
			}
		}
	}

	ipMatcher = addrtrie.NewBitTrie[Policy]()
	ipv6Matcher = addrtrie.NewBitTrie6[Policy]()
	for patterns, policy := range conf.IpPolicies {
		p := policy
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, ipOrNet := range expandPattern(elem) {
				if strings.Contains(ipOrNet, ":") {
					ipv6Matcher.Insert(ipOrNet, &p)
				} else {
					ipMatcher.Insert(ipOrNet, &p)
				}
			}
		}
	}

	return conf.ServerAddr, nil
}

func matchIP(ip string) *Policy {
	if strings.Contains(ip, ":") {
		policy, _ := ipv6Matcher.Find(ip)
		return policy
	}
	return ipMatcher.Find(ip)
}
