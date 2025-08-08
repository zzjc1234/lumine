package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"golang.org/x/text/encoding/charmap"
	//"strings"
)

var encoder = charmap.ISO8859_1.NewEncoder()

func isValidIP(s string) bool {
	return net.ParseIP(s) != nil
}

/*
func IPToBinaryPrefix(ipOrNetwork string) (string, error) {
	if _, ipnet, err := net.ParseCIDR(ipOrNetwork); err == nil {
		return binaryFromIPNet(ipnet)
	}
	if ip := net.ParseIP(ipOrNetwork); ip != nil {
		return binaryFromIP(ip)
	}
	return "", fmt.Errorf("invalid IP or network: %s", ipOrNetwork)
}

func binaryFromIPNet(n *net.IPNet) (string, error) {
	ip := n.IP
	ones, _ := n.Mask.Size()
	return binaryFromIPWithLen(ip, ones)
}

func binaryFromIP(ip net.IP) (string, error) {
	if ip.To4() != nil {
		return binaryFromIPWithLen(ip, 32)
	}
	if ip.To16() != nil {
		return binaryFromIPWithLen(ip, 128)
	}
	return "", fmt.Errorf("invalid IP format")
}

func binaryFromIPWithLen(ip net.IP, bits int) (string, error) {
	ip = ip.To16()
	if ip == nil {
		return "", fmt.Errorf("invalid IP")
	}
	var sb strings.Builder
	for i := 0; i < bits/8; i++ {
		fmt.Fprintf(&sb, "%08b", ip[i])
	}
	remain := bits % 8
	if remain > 0 {
		fmt.Fprintf(&sb, "%08b", ip[bits/8])
		s := sb.String()
		return s[:bits], nil
	}
	return sb.String(), nil
}
*/

func ParseClientHello(data []byte) (prtVer []byte, sniPos int, sniLen int, hasKeyShare bool, err error) {
	const (
		recordHeaderLen          = 5
		handshakeHeaderLen       = 4
		handshakeTypeClientHello = 0x01
		extTypeSNI               = 0x0000
		extTypeKeyShare          = 0x0033
	)

	prtVer = []byte{}
	sniPos = -1
	sniLen = 0

	if len(data) < recordHeaderLen {
		return prtVer, sniPos, sniLen, false, errors.New("data too short for TLS record header")
	}
	if data[0] != 22 {
		return prtVer, sniPos, sniLen, false, fmt.Errorf("unexpected record type %d, want Handshake(22)", data[0])
	}
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
