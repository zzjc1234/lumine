package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/moi-si/addrtrie"
)

const (
	HttpBlock    = -1
	HttpRedirect = 0
	HttpForward  = 1
)

type Policy struct {
	IP         string  `json:"ip"`
	MapTo      string  `json:"map_to"`
	Port       int     `json:"port"`
	IPv6First  *bool   `json:"ipv6_first"`
	SkipParse  *bool   `json:"skip_parse"`
	TLS13Only  *bool   `json:"tls13_only"`
	Mode       string  `json:"mode"`
	NumRecords int     `json:"num_records"`
	FakePacket string  `json:"fake_packet"`
	FakeTTL    int     `json:"fake_ttl"`
	FakeSleep  float64 `json:"fake_sleep"`
}

func escape(s string) string {
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

func (p Policy) String() string {
	fields := []string{}
	if p.IP != "" {
		fields = append(fields, "IP:"+p.IP)
	}
	if p.Port != 0 {
		fields = append(fields, fmt.Sprintf("Port:%d", p.Port))
	}
	if p.SkipParse != nil && *p.SkipParse {
		fields = append(fields, "SkipParse:true")
	} else {
		fields = append(fields, "Mode:"+p.Mode)
		switch p.Mode {
		case "tls-rf":
			fields = append(fields, fmt.Sprintf("NumRecords:%d", p.NumRecords))
		case "ttl-d":
			fields = append(fields, "FakePacket:"+escape(p.FakePacket))
			if p.FakeTTL == 0 {
				fields = append(fields, "FakeTTL:auto")
			} else {
				fields = append(fields, fmt.Sprintf("FakeTTL:%d", p.FakeTTL))
			}
			fields = append(fields, fmt.Sprintf("FakeSleep:%.2f", p.FakeSleep))
		}
		if p.TLS13Only != nil {
			fields = append(fields, fmt.Sprintf("TLS13Only:%v", *p.TLS13Only))
		}
	}
	return "{" + strings.Join(fields, ", ") + "}"
}

func MergePolicies(policies ...Policy) Policy {
	var merged Policy
	for _, p := range policies {
		if p.IP != "" {
			merged.IP = p.IP
		}
		if p.MapTo != "" {
			merged.MapTo = p.MapTo
		}
		if p.Port != 0 {
			merged.Port = p.Port
		}
		if p.SkipParse != nil {
			merged.SkipParse = p.SkipParse
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
	return merged
}

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

func matchIP(ip string) *Policy {
	if strings.Contains(ip, ":") {
		policy, _ := ipv6Matcher.Find(ip)
		return policy
	} else {
		return ipMatcher.Find(ip)
	}
}
