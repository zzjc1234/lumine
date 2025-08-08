package main

import (
	"fmt"
	"strings"
)

type Policy struct {
	TLS13Only       *bool   `json:"tls13_only"`
	IP              string  `json:"ip"`
	Port            int     `json:"port"`
	Mode            string  `json:"mode"`
	NumRecords      int     `json:"num_records"`
	FakePacket      string  `json:"fake_packet"`
	FakeTTL         int     `json:"fake_ttl"`
	FakeSleep       float64 `json:"fake_sleep"`
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
	return "{" + strings.Join(fields, ", ") + "}"
}

type LableNode struct {
	Children map[string]*LableNode
	Value    *Policy
}

type DomainMatcher struct {
	exactDomains map[string]*Policy
	root         *LableNode
}

func NewDomainMatcher() *DomainMatcher {
	return &DomainMatcher{
		exactDomains: make(map[string]*Policy),
		root:         &LableNode{Children: map[string]*LableNode{}},
	}
}

func splitAndReverse(domain string) []string {
	parts := strings.Split(domain, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}

func (m *DomainMatcher) insertTrie(domain string, value *Policy) {
	node := m.root
	lables := splitAndReverse(domain)
	for _, lable := range lables {
		if node.Children[lable] == nil {
			node.Children[lable] = &LableNode{Children: map[string]*LableNode{}}
		}
		node = node.Children[lable]
	}
	node.Value = value
}

func (m *DomainMatcher) Add(pattern string, value *Policy) error {
	if !strings.Contains(pattern, ".") {
		return fmt.Errorf("invalid pattern: %s", pattern)
	} else if strings.HasPrefix(pattern, "*.") {
		m.insertTrie(pattern[2:], value)
	} else if strings.HasPrefix(pattern, "*") {
		domain := pattern[1:]
		m.exactDomains[domain] = value
		m.insertTrie(domain, value)
	} else {
		m.exactDomains[pattern] = value
	}
	return nil
}

func (m *DomainMatcher) Find(domain string) *Policy {
	if value, ok := m.exactDomains[domain]; ok {
		return value
	}
	node := m.root
	lables := splitAndReverse(domain)
	var value *Policy
	for _, lable := range lables {
		child, ok := node.Children[lable]
		if !ok {
			break
		}
		node = child
		if node.Value != nil {
			value = node.Value
		}
	}
	return value
}

/*
type BinNode struct {
	Children [2]*BinNode
	Value    *Policy
}

type BinTrie struct {
	root *BinNode
}

func NewBinTrie() *BinTrie {
	return &BinTrie{root: &BinNode{}}
}

func (t *BinTrie) Add(ipOrNetwork string, value *Policy) {
	prefix, err := IPToBinaryPrefix(ipOrNetwork)
	if err != nil {
		panic(err)
	}
	cur := t.root
	for _, bit := range prefix {
		idx := bit - '0'
		if cur.Children[idx] == nil {
			cur.Children[idx] = &BinNode{}
		}
		cur = cur.Children[idx]
	}
	cur.Value = value
}

func (t *BinTrie) Find(ipOrNetwork string) *Policy {
	binaryIP, err := IPToBinaryPrefix(ipOrNetwork)
	if err != nil {
		panic(err)
	}
	cur := t.root
	var ans *Policy
	for _, ch := range binaryIP {
		idx := ch - '0'
		if cur.Children[idx] == nil {
			break
		}
		cur = cur.Children[idx]
		if cur.Value != nil {
			ans = cur.Value
		}
	}
	return ans
}
*/

func MergePolicies(policies ...Policy) Policy {
	var merged Policy
	for _, p := range policies {
		if p.TLS13Only != nil {
			merged.TLS13Only = p.TLS13Only
		}
		if p.IP != "" {
			merged.IP = p.IP
		}
		if p.Port != 0 {
			merged.Port = p.Port
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
