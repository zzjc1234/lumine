package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"math/big"

	"golang.org/x/text/encoding/charmap"
)

var encoder = charmap.ISO8859_1.NewEncoder()

func isValidIP(s string) bool {
	return net.ParseIP(s) != nil
}

func ParseClientHello(data []byte) (prtVer []byte, sniPos int, sniLen int, hasKeyShare bool, err error) {
	const (
		recordHeaderLen          = 5
		handshakeHeaderLen       = 4
		handshakeTypeClientHello = 0x01
		extTypeSNI               = 0x0000
		extTypeKeyShare          = 0x0033
	)

	prtVer = nil
	sniPos = -1
	sniLen = 0

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < recordHeaderLen+recordLen {
		return prtVer, sniPos, sniLen, false, errors.New("record length exceeds data size")
	}
	offset := recordHeaderLen

	if recordLen < handshakeHeaderLen {
		return prtVer, sniPos, sniLen, false, errors.New("handshake message too short")
	}
	if data[offset] != handshakeTypeClientHello {
		return prtVer, sniPos, sniLen, false, fmt.Errorf("not a ClientHello handshake (type=%d)", data[offset])
	}
	handshakeLen := int(uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3]))
	if handshakeLen+handshakeHeaderLen > recordLen {
		return prtVer, sniPos, sniLen, false, errors.New("handshake length exceeds record length")
	}
	offset += handshakeHeaderLen

	if handshakeLen < 2+32+1 {
		return prtVer, sniPos, sniLen, false, errors.New("ClientHello too short for mandatory fields")
	}
	prtVer = data[offset : offset+2]
	offset += 2
	offset += 32
	if offset >= len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("unexpected end after Random")
	}
	sessionIDLen := int(data[offset])
	offset++
	if offset+sessionIDLen > len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("session_id length exceeds data")
	}
	offset += sessionIDLen

	if offset+2 > len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("cannot read cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+csLen > len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("cipher_suites exceed data")
	}
	offset += csLen

	if offset >= len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("cannot read compression_methods length")
	}
	compMethodsLen := int(data[offset])
	offset++
	if offset+compMethodsLen > len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("compression_methods exceed data")
	}
	offset += compMethodsLen

	// Extensions
	if offset+2 > len(data) {
		return prtVer, sniPos, sniLen, false, nil
	}
	extTotalLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+extTotalLen > len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("extensions length exceeds data")
	}
	extensionsEnd := offset + extTotalLen

	for offset+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		extDataStart := offset + 4
		extDataEnd := extDataStart + extLen

		if extDataEnd > extensionsEnd {
			return prtVer, sniPos, sniLen, false, errors.New("extension length exceeds extensions block")
		}

		if extType == extTypeKeyShare {
			hasKeyShare = true
			if sniPos != -1 {
				return prtVer, sniPos, sniLen, hasKeyShare, nil
			}
		}

		if sniPos == -1 && extType == extTypeSNI {
			if extLen < 2 {
				return prtVer, sniPos, sniLen, hasKeyShare, errors.New("malformed SNI extension (too short for list length)")
			}
			listLen := int(binary.BigEndian.Uint16(data[extDataStart : extDataStart+2]))
			if listLen+2 != extLen {
				return prtVer, sniPos, sniLen, hasKeyShare, errors.New("SNI list length field mismatch")
			}
			cursor := extDataStart + 2
			if cursor+3 > extDataEnd {
				return prtVer, sniPos, sniLen, hasKeyShare, errors.New("SNI entry too short")
			}
			nameType := data[cursor]
			if nameType != 0 {
				return prtVer, sniPos, sniLen, hasKeyShare, errors.New("unsupported SNI name type")
			}
			nameLen := int(binary.BigEndian.Uint16(data[cursor+1 : cursor+3]))
			nameStart := cursor + 3
			nameEnd := nameStart + nameLen
			if nameEnd > extDataEnd {
				return prtVer, sniPos, sniLen, hasKeyShare, errors.New("SNI name length exceeds extension")
			}
			sniPos = nameStart
			sniLen = nameLen
			if hasKeyShare {
				return prtVer, sniPos, sniLen, hasKeyShare, nil
			}
		}
		offset = extDataEnd
	}
	return prtVer, sniPos, sniLen, hasKeyShare, nil
}

func GenTLSAlert(prtVer []byte, desc byte, level byte) []byte {
	return []byte{0x15, prtVer[0], prtVer[1], 0x00, 0x02, level, desc}
}

func Encode(s string) ([]byte, error) {
	b, err := encoder.Bytes([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("encoding ISO-8859-1 failed: %v", err)
	}
	return b, nil
}

func ExpandPattern(s string) []string {
	left := -1
	right := -1
	for i, ch := range s {
		if ch == '(' && left == -1 {
			left = i
		}
		if ch == ')' && right == -1 {
			right = i
		}
	}
	if left == -1 && right == -1 {
		return splitByPipe(s)
	}

	prefix := s[:left]
	suffix := s[right+1:]
	inner := s[left+1 : right]

	parts := splitByPipe(inner)
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		result = append(result, prefix+part+suffix)
	}
	return result
}

func splitByPipe(s string) []string {
	if s == "" {
		return []string{""}
	}
	result := []string{}
	curr := ""
	for _, ch := range s {
		if ch == '|' {
			result = append(result, curr)
			curr = ""
		} else {
			curr += string(ch)
		}
	}
	result = append(result, curr)
	return result
}

type rule struct {
	threshold int // a
	typ       byte // '-' or '='
	val       int // b
}

func parseRules(conf string) ([]rule, error) {
	if len(conf) == 0 {
		return nil, errors.New("empty config")
	}
	if conf[0] != 'q' {
		return nil, nil
	}
	b := []byte(conf[1:])

	var rules []rule
	i := 0
	for i < len(b) {
		start := i
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
		if start == i {
			return nil, errors.New("invalid rule: missing left number")
		}
		a := 0
		for _, c := range b[start:i] {
			a = a*10 + int(c-'0')
		}

		if i >= len(b) {
			return nil, errors.New("invalid rule: missing operator")
		}
		op := b[i] // '-' or '='
		if op != '-' && op != '=' {
			return nil, errors.New("invalid operator")
		}
		i++

		start = i
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
		if start == i {
			return nil, errors.New("invalid rule: missing right number")
		}
		val := 0
		for _, c := range b[start:i] {
			val = val*10 + int(c-'0')
		}

		rules = append(rules, rule{
			threshold: a,
			typ:       op,
			val:       val,
		})

		if i < len(b) && b[i] == ';' {
			i++
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].threshold > rules[j].threshold
	})
	return rules, nil
}

func CalcTTL(conf string, dist int) (int, error) {
	rules, err := parseRules(conf)
	if err != nil {
		return 0, err
	}
	if rules == nil {
		val := 0
		for i := 0; i < len(conf); i++ {
			c := conf[i]
			if c < '0' || c > '9' {
				return 0, errors.New("invalid integer config")
			}
			val = val*10 + int(c-'0')
		}
		return val, nil
	}

	for _, r := range rules {
		if dist >= r.threshold {
			if r.typ == '-' {
				return dist - r.val, nil
			}
			// r.typ == '='
			return r.val, nil
		}
	}
	return 0, errors.New("no matching TTL rule")
}

func TransformIP(ipStr string, targetNetStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", errors.New("invalid IP")
	}
	_, targetNet, err := net.ParseCIDR(targetNetStr)
	if err != nil {
		return "", fmt.Errorf("invalid target network: %v", err)
	}

	isIPv4 := ip.To4() != nil
	isIPv4Target := targetNet.IP.To4() != nil
	if (isIPv4 && !isIPv4Target) || (!isIPv4 && isIPv4Target) {
		return "", errors.New("IP version mismatch between source IP and target network")
	}

	var maxLen int
	if isIPv4 {
		maxLen = 32
	} else {
		maxLen = 128
	}

	prefixLen, _ := targetNet.Mask.Size()

	hostBits := maxLen - prefixLen

	fullMask := new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), uint(maxLen)),
		big.NewInt(1),
	)

	hostMask := new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), uint(hostBits)),
		big.NewInt(1),
	)
	networkMask := new(big.Int).Xor(fullMask, hostMask)
	toBigInt := func(ip net.IP) *big.Int {
		if isIPv4 {
			ip = ip.To4()
		} else {
			ip = ip.To16()
		}
		return new(big.Int).SetBytes(ip)
	}

	ipInt    := toBigInt(ip)
	netInt   := toBigInt(targetNet.IP)

	newIPInt := new(big.Int).Or(
		new(big.Int).And(netInt, networkMask),
		new(big.Int).And(ipInt, hostMask),
	)

	expectedLen := 4
	if !isIPv4 {
		expectedLen = 16
	}
	newIPBytes := newIPInt.Bytes()
	if len(newIPBytes) < expectedLen {
		padded := make([]byte, expectedLen)
		copy(padded[expectedLen-len(newIPBytes):], newIPBytes)
		newIPBytes = padded
	}

	return net.IP(newIPBytes).String(), nil
}