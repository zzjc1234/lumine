package main

import (
	"fmt"
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
