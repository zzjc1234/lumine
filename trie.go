package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
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

type lableNode[V any] struct {
	children map[string]*lableNode[V]
	value    *V
}

type DomainMatcher[V any] struct {
	exactDomains map[string]*V
	root         *lableNode[V]
}

func NewDomainMatcher[V any]() *DomainMatcher[V] {
	return &DomainMatcher[V]{
		exactDomains: make(map[string]*V),
		root:         &lableNode[V]{children: make(map[string]*lableNode[V])},
	}
}

func splitAndReverse(domain string) []string {
	parts := strings.Split(domain, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}

func (m *DomainMatcher[V]) insertTrie(domain string, value V) {
	node := m.root
	lables := splitAndReverse(domain)
	for _, lable := range lables {
		if node.children[lable] == nil {
			node.children[lable] = &lableNode[V]{children: make(map[string]*lableNode[V])}
		}
		node = node.children[lable]
	}
	tmp := new(V)
	*tmp = value
	node.value = tmp
}

func (m *DomainMatcher[V]) Add(pattern string, value V) error {
	if !strings.Contains(pattern, ".") {
		return fmt.Errorf("invalid pattern: %s", pattern)
	} else if strings.HasPrefix(pattern, "*.") {
		m.insertTrie(pattern[2:], value)
	} else if strings.HasPrefix(pattern, "*") {
		domain := pattern[1:]
		m.exactDomains[domain] = &value
		m.insertTrie(domain, value)
	} else {
		m.exactDomains[pattern] = &value
	}
	return nil
}

func (m *DomainMatcher[V]) Find(domain string) *V {
	if value, ok := m.exactDomains[domain]; ok {
		return value
	}
	node := m.root
	lables := splitAndReverse(domain)
	var value *V
	for _, lable := range lables {
		child, ok := node.children[lable]
		if !ok {
			break
		}
		node = child
		if node.value != nil {
			value = node.value
		}
	}
	return value
}

func parseIPorCIDR(s string) (ip uint32, bitLen int, err error) {
	if _, ipNet, e := net.ParseCIDR(s); e == nil {
		ip = binary.BigEndian.Uint32(ipNet.IP.To4())
		ones, bits := ipNet.Mask.Size()
		if bits != 32 {
			return 0, 0, net.InvalidAddrError("non-IPv4 mask")
		}
		if ones == 0 && bits == 0 {
			return 0, 0, net.InvalidAddrError("non-canonical mask")
		}
		return ip, ones, nil
	}
	parsed := net.ParseIP(s).To4()
	if parsed == nil {
		return 0, 0, net.InvalidAddrError("invalid IPv4 address")
	}
	ip = binary.BigEndian.Uint32(parsed)
	return ip, 32, nil
}

func getBit(v uint32, i int) int {
	shift := 31 - i
	return int((v >> shift) & 1)
}

type bitNode struct {
	children [2]*bitNode
	value    *Policy
}

type BitTrie struct {
	root *bitNode
}

func NewBitTrie() *BitTrie {
	return &BitTrie{root: &bitNode{children: [2]*bitNode{}}}
}

func (t *BitTrie) Insert(prefix string, value *Policy) error {
	ip, bitLen, err := parseIPorCIDR(prefix)
	if err != nil {
		panic(err)
	}

	cur := t.root
	for i := range bitLen {
		b := getBit(ip, i)
		if cur.children[b] == nil {
			cur.children[b] = &bitNode{children: [2]*bitNode{}}
		}
		cur = cur.children[b]
	}
	cur.value = value
	return nil
}

func (t *BitTrie) Find(ipStr string) *Policy {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return nil
	}
	ipUint := binary.BigEndian.Uint32(ip)

	var best *Policy
	cur := t.root
	for i := range 32 {
		if cur.value != nil {
			best = cur.value
		}
		b := getBit(ipUint, i)
		if cur.children[b] == nil {
			break
		}
		cur = cur.children[b]
	}
	if cur.value != nil {
		best = cur.value
	}
	return best
}

type ipv6Addr struct {
	hi uint64 // high 64 bits
	lo uint64 // low 64 bits
}

func newIPv6Addr(ip net.IP) ipv6Addr {
	ip16 := ip.To16()
	hi := binary.BigEndian.Uint64(ip16[0:8])
	lo := binary.BigEndian.Uint64(ip16[8:16])
	return ipv6Addr{hi: hi, lo: lo}
}

func (a ipv6Addr) getBit(i int) int {
	if i < 0 || i >= 128 {
		panic("bit index out of range")
	}
	if i < 64 {
		shift := 63 - i
		return int((a.hi >> shift) & 1)
	}
	shift := 63 - (i - 64)
	return int((a.lo >> shift) & 1)
}

func parseIPorCIDRIPv6(s string) (ipv6Addr, int, error) {
	if ip, ipNet, err := net.ParseCIDR(s); err == nil {
		ip = ip.To16()
		if ip == nil || ip.To4() != nil {
			return ipv6Addr{}, 0, net.InvalidAddrError("non-IPv6 CIDR")
		}
		ones, bits := ipNet.Mask.Size()
		if bits != 128 {
			return ipv6Addr{}, 0, net.InvalidAddrError("non-IPv6 mask")
		}
		if ones == 0 && bits == 0 {
			return ipv6Addr{}, 0, net.InvalidAddrError("non-canonical mask")
		}
		return newIPv6Addr(ip), ones, nil
	}

	ip := net.ParseIP(s).To16()
	if ip == nil || ip.To4() != nil {
		return ipv6Addr{}, 0, net.InvalidAddrError("invalid IPv6 address")
	}
	return newIPv6Addr(ip), 128, nil
}

type bitNode6 struct {
	children [2]*bitNode6
	value    *Policy
}

type BitTrie6 struct {
	root *bitNode6
}

func NewBitTrie6() *BitTrie6 {
	return &BitTrie6{root: &bitNode6{}}
}

func (t *BitTrie6) Insert(prefix string, value *Policy) error {
	addr, bitLen, err := parseIPorCIDRIPv6(prefix)
	if err != nil {
		return err
	}
	if bitLen < 0 || bitLen > 128 {
		return errors.New("invalid prefix length")
	}

	cur := t.root
	for i := range bitLen {
		b := addr.getBit(i)
		if cur.children[b] == nil {
			cur.children[b] = &bitNode6{}
		}
		cur = cur.children[b]
	}
	cur.value = value
	return nil
}

func (t *BitTrie6) Find(ipStr string) *Policy {
	ip := net.ParseIP(ipStr).To16()
	if ip == nil || ip.To4() != nil {
		return nil
	}
	addr := newIPv6Addr(ip)

	var best *Policy
	cur := t.root
	for i := range 128 {
		if cur.value != nil {
			best = cur.value
		}
		b := addr.getBit(i)
		if cur.children[b] == nil {
			break
		}
		cur = cur.children[b]
	}
	if cur.value != nil {
		best = cur.value
	}
	return best
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
