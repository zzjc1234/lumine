package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"
)

var rnd = rand.New(rand.NewSource(time.Now().UnixNano()))

func SendRecords(conn net.Conn, data []byte, offset, length, num int) error {
	if len(data) < 5 {
		return errors.New("data too short")
	}
	if num <= 0 {
		return errors.New("invalid num")
	}
	if length < 4 {
		return errors.New("invalid length")
	}
	if num == 1 {
		if _, err := conn.Write(data); err != nil {
			return errors.New("failed to send data directly")
		}
		return nil
	}

	header := data[:3]
	payload := data[5:]
	offset -= 5
	if offset < -1 {
		return errors.New("adjusted offset < -1, impossible")
	}

	start := offset + 1
	end := offset + length
	if start < 0 || end > len(payload) {
		return errors.New("slice out of payload bounds")
	}
	idx := offset + 1 + rnd.Intn(length-1)

	leftChunks := num / 2
	rightChunks := num - leftChunks
	leftData := payload[:idx]
	rightData := payload[idx:]

	leftParts, err := splitEvenly(leftData, leftChunks)
	if err != nil {
		return err
	}
	rightParts, err := splitEvenly(rightData, rightChunks)
	if err != nil {
		return err
	}
	allParts := append(leftParts, rightParts...)
	tcpData := []byte{}
	for _, part := range allParts {
		tcpData = append(tcpData, header...)
		if len(part) > 0xFFFF {
			return errors.New("single chunk exceeds 65535 bytes, cannot fit into uint16")
		}
		var lenBytes [2]byte
		binary.BigEndian.PutUint16(lenBytes[:], uint16(len(part)))
		tcpData = append(tcpData, lenBytes[:]...)
		tcpData = append(tcpData, part...)
	}

	if _, err := conn.Write(tcpData); err != nil {
		return fmt.Errorf("error send record: %v", err)
	}
	return nil
}

func splitEvenly(data []byte, n int) ([][]byte, error) {
	if n < 0 {
		return nil, errors.New("chunk count must be non-negative")
	}
	if n == 0 {
		return [][]byte{}, nil
	}
	if len(data) == 0 {
		empty := make([][]byte, n)
		for i := range empty {
			empty[i] = []byte{}
		}
		return empty, nil
	}

	baseSize := len(data) / n
	parts := make([][]byte, n)
	pos := 0
	for i := 0; i < n; i++ {
		size := baseSize
		if i == n-1 {
			size = len(data) - pos
		}
		if size < 0 {
			size = 0
		}
		end := pos + size
		if end > len(data) {
			end = len(data)
		}
		parts[i] = data[pos:end]
		pos = end
	}
	if pos != len(data) {
		return nil, errors.New("splitEvenly internal error: leftover bytes")
	}
	return parts, nil
}
