package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync/atomic"
)

var connID uint32

func makeLogger() *log.Logger {
	id := atomic.AddUint32(&connID, 1)
	if id > 0xFFFF {
		atomic.StoreUint32(&connID, 0)
		id = 0
	}
	return log.New(os.Stdout, fmt.Sprintf("%04x ", id), log.LstdFlags)
}

func readN(conn net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

func sendReply(conn net.Conn, rep byte, bindIP net.IP, bindPort uint16) error {
	if bindIP == nil {
		bindIP = net.IPv4zero
	}
	resp := []byte{0x05, rep, 0x00, 0x01}
	resp = append(resp, bindIP.To4()...)
	portBytes := make([]byte, 2)
	binary.BigEndian.AppendUint16(portBytes, bindPort)
	resp = append(resp, portBytes...)
	_, err := conn.Write(resp)
	return err
}

func handleClient(clientConn net.Conn) {
	logger := makeLogger()
	clientAddr := clientConn.RemoteAddr().String()
	logger.Printf("Accepted connection from %s", clientAddr)
	defer clientConn.Close()

	header, err := readN(clientConn, 2)
	if err != nil {
		logger.Printf("Header error: %v", err)
		return
	}
	if header[0] != 0x05 {
		logger.Printf("Not SOCKS5: %d", header[0])
		return
	}
	nMethods := int(header[1])
	methods, err := readN(clientConn, nMethods)
	if err != nil {
		logger.Printf("Methods error: %v", err)
		return
	}
	var authMethod byte = 0xFF // No acceptable methods
	for _, m := range methods {
		if m == 0x00 {
			authMethod = 0x00
			break
		}
	}
	_, err = clientConn.Write([]byte{0x05, authMethod})
	if err != nil {
		logger.Printf("Error sending auth method: %v", err)
		return
	}
	if authMethod == 0xFF {
		logger.Printf("No `no auth` method was given")
		return
	}

	header, err = readN(clientConn, 4)
	if err != nil {
		logger.Printf("Error reading request header: %v", err)
		return
	}
	if header[0] != 0x05 {
		logger.Printf("Invalid version: %d", header[0])
		return
	}
	if header[1] != 0x01 {
		logger.Printf("Not CONNECT: %d", header[1])
		sendReply(clientConn, 0x07, nil, 0)
		return
	}

	var dstAddr string
	switch header[3] {
	case 0x01: // IPv4 address
		ipBytes, err := readN(clientConn, 4)
		if err != nil {
			logger.Printf("Error reading IPv4 dest address: %v", err)
			return
		}
		dstAddr = net.IP(ipBytes).String()
	case 0x03: // Domain name
		lenByte, err := readN(clientConn, 1)
		if err != nil {
			logger.Printf("Error reading domain length: %v", err)
			return
		}
		domainBytes, err := readN(clientConn, int(lenByte[0]))
		if err != nil {
			logger.Printf("Error reading domain: %v", err)
			return
		}
		dstAddr = string(domainBytes)
	case 0x04: // IPv6 address
		ipBytes, err := readN(clientConn, 16)
		if err != nil {
			logger.Printf("Error reading IPv6 dest address: %v", err)
			return
		}
		dstAddr = net.IP(ipBytes).String()
	default:
		logger.Printf("Invalid address type: %d", header[3])
		return
	}
	portByte, err := readN(clientConn, 2)
	if err != nil {
		logger.Printf("Error reading port: %v", err)
		return
	}
	dstPort := int(binary.BigEndian.Uint16(portByte))
	target := net.JoinHostPort(dstAddr, strconv.Itoa(dstPort))
	logger.Printf("CONNECT %s", target)

	dstConn, policy, ok := Dial(logger, clientConn, dstAddr, dstPort)
	if !ok {
		return
	}
	defer dstConn.Close()
	sendReply(clientConn, 0x00, nil, 0)

	buf := make([]byte, 4096)
	n, err := clientConn.Read(buf)
	if err != nil {
		logger.Println("Failed to read first packet from client:", err)
		return
	}
	firstPacket := buf[:n]
	_, sniPos, sniLen, hasKeyShare, err := ParseClientHello(firstPacket)
	if err != nil {
		logger.Println("Error parse ClientHello:", err)
		return
	}
	if policy.Tls13Only != nil && *policy.Tls13Only && !hasKeyShare {
		logger.Println("Not a TLS 1.3 ClientHello, connection blocked")
		return
	}
	sniStr := string(firstPacket[sniPos : sniPos+sniLen])
	logger.Printf("Server name: %s", sniStr)

	switch policy.Mode {
	case "DIRECT":
		if _, err = dstConn.Write(firstPacket); err != nil {
			logger.Println("Failed to send first packet directly:", err)
			return
		}
		logger.Println("Sent first packet directly")
	case "TLSfrag":
		err = SendRecords(dstConn, firstPacket, sniPos, sniLen, policy.NumRecords)
		if err != nil {
			logger.Println("Error TLS fragmentation:", err)
			return
		}
	}

	go io.Copy(dstConn, clientConn)
	io.Copy(clientConn, dstConn)
}

func main() {
	configPath := flag.String("config", "config.json", "Config file path")
	flag.Parse()
	if err := LoadConfig(*configPath); err != nil {
		panic(fmt.Sprintf("Failed to load config: %v", err))
	}

	listenAddr := conf.ServerAddr
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		panic(fmt.Sprintf("Listen error: %v", err))
	}
	fmt.Printf("SOCKS5 server listening on %s\n", listenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleClient(conn)
	}
}
