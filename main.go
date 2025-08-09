package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"sync/atomic"
)

var connID uint32

func makeLogger() *log.Logger {
	id := atomic.AddUint32(&connID, 1)
	if id > 0xFFFF {
		atomic.StoreUint32(&connID, 0)
		id = 0
	}
	return log.New(os.Stdout, fmt.Sprintf("[%04x]", id), log.LstdFlags)
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
	defer clientConn.Close()
	logger := makeLogger()
	clientAddr := clientConn.RemoteAddr().String()
	logger.Println("Accepted connection from", clientAddr)

	header, err := readN(clientConn, 2)
	if err != nil {
		logger.Println("Method selection message error:", err)
		return
	}
	if header[0] != 0x05 {
		logger.Println("Not SOCKS5:", header[0])
		return
	}
	nMethods := int(header[1])
	methods, err := readN(clientConn, nMethods)
	if err != nil {
		logger.Println("Methods error:", err)
		return
	}
	var authMethod byte = 0xFF // No acceptable methods
	if slices.Contains(methods, 0x00) {
		authMethod = 0x00
	}
	_, err = clientConn.Write([]byte{0x05, authMethod})
	if err != nil {
		logger.Println("Error sending auth method:", err)
		return
	}
	if authMethod == 0xFF {
		logger.Println("No `no auth` method was given")
		return
	}

	header, err = readN(clientConn, 4)
	if err != nil {
		logger.Println("Error reading request header:", err)
		return
	}
	if header[0] != 0x05 {
		logger.Println("Invalid version:", header[0])
		return
	}
	if header[1] != 0x01 {
		logger.Println("Not CONNECT:", header[1])
		sendReply(clientConn, 0x07, nil, 0)
		return
	}

	var dstAddr string
	switch header[3] {
	case 0x01: // IPv4 address
		ipBytes, err := readN(clientConn, 4)
		if err != nil {
			logger.Println("Error reading IPv4 dest address:", err)
			return
		}
		dstAddr = net.IP(ipBytes).String()
	case 0x03: // Domain name
		lenByte, err := readN(clientConn, 1)
		if err != nil {
			logger.Println("Error reading domain length:", err)
			return
		}
		domainBytes, err := readN(clientConn, int(lenByte[0]))
		if err != nil {
			logger.Println("Error reading domain:", err)
			return
		}
		dstAddr = string(domainBytes)
	case 0x04: // IPv6 address
		ipBytes, err := readN(clientConn, 16)
		if err != nil {
			logger.Println("Error reading IPv6 dest address:", err)
			return
		}
		dstAddr = net.IP(ipBytes).String()
	default:
		logger.Println("Invalid address type:", header[3])
		return
	}
	portByte, err := readN(clientConn, 2)
	if err != nil {
		logger.Println("Error reading port:", err)
		return
	}
	dstPort := int(binary.BigEndian.Uint16(portByte))
	target := net.JoinHostPort(dstAddr, fmt.Sprintf("%d", dstPort))
	logger.Println("CONNECT", target)

	dstConn, policy, ttl, ok := Dial(logger, clientConn, dstAddr, dstPort)
	if !ok {
		return
	}
	defer dstConn.Close()
	sendReply(clientConn, 0x00, nil, 0)

	if policy.SkipParse != nil && *policy.SkipParse {
		go io.Copy(clientConn, dstConn)
		io.Copy(dstConn, clientConn)
		return
	}

	br := bufio.NewReader(clientConn)
	peekBytes, err := br.Peek(5)
	if err != nil {
		if errors.Is(err, io.EOF) {
			logger.Println("Client sent nothing in tunnel")
		} else {
			logger.Println("Failed to read first packet from client:", err)
		}
		return
	}
	switch peekBytes[0] {
	case 'G', 'P', 'D', 'O', 'T', 'H':
		req, err := http.ReadRequest(br)
		if err != nil {
			logger.Println("parse HTTP request:", err)
			return
		}
		defer req.Body.Close()

		host := req.Host
		if host == "" {
			host = req.URL.Host
		}
		if host == "" {
			logger.Println("cannot determine target host")
			return
		}
		logger.Printf("%s %s => %s", req.Method, req.URL, host)

		ptr := httpMatcher.Find(host)
		var httpMode int
		if ptr == nil {
			httpMode = conf.DefaultHttpPolicy
		} else {
			httpMode = *ptr
		}
		switch httpMode {
		case HttpBlock:
			resp := &http.Response{
				Status:        "403 Forbidden",
				StatusCode:    403,
				Proto:         req.Proto,
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        make(http.Header),
				ContentLength: 0,
				Close:         true,
			}
			err = resp.Write(clientConn)
			if err != nil {
				logger.Println("failed to send 403 response:", err)
			} else {
				logger.Printf("HTTP request to %s blocked", host)
			}
			return
		case HttpRedirect:
			httpsURL := "https://" + host + req.URL.RequestURI()
			resp := &http.Response{
				Status:        "302 Found",
				StatusCode:    302,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        make(http.Header),
				ContentLength: 0,
				Close:         true,
			}
			resp.Header.Set("Location", httpsURL)
			if err = resp.Write(clientConn); err != nil {
				logger.Println("failed to send 302 response:", err)
			} else {
				logger.Println("Redirect HTTP to HTTPS for", host)
			}
			return
		case HttpForward:
			if err := req.Write(dstConn); err != nil {
				logger.Printf("forward request to %s failed: %v", host, err)
				return
			}
		}
	case 0x16:
		payloadLen := binary.BigEndian.Uint16(peekBytes[3:5])
		record := make([]byte, 5+payloadLen)
		_, err = io.ReadFull(br, record)
		if err != nil {
			logger.Println("failed to read record:", err)
			return
		}
		prtVer, sniPos, sniLen, hasKeyShare, err := ParseClientHello(record)
		if err != nil {
			logger.Println("Error parse ClientHello:", err)
			return
		}
		if policy.TLS13Only != nil && *policy.TLS13Only && !hasKeyShare {
			logger.Println("Not a TLS 1.3 ClientHello, connection blocked")
			_, err := clientConn.Write(GenTLSAlert(prtVer, 0x46, 0x02))
			if err != nil {
				log.Println("failed to write TLS Alert:", err)
			}
			return
		}
		sniStr := string(record[sniPos : sniPos+sniLen])
		logger.Printf("Server name: %s", sniStr)

		switch policy.Mode {
		case "direct":
			if _, err = dstConn.Write(record); err != nil {
				logger.Println("Failed to send first packet directly:", err)
				return
			}
			logger.Println("Sent first packet directly")
		case "tls-rf":
			err = SendRecords(dstConn, record, sniPos, sniLen, policy.NumRecords)
			if err != nil {
				logger.Println("Error TLS fragmentation:", err)
				return
			}
			logger.Println("Successfully sent ClientHello")
		case "ttl-d":
			logger.Println("Fake TTL:", ttl)
			fakePacketBytes, err := Encode(policy.FakePacket)
			if err != nil {
				logger.Println("failed to encode fake packet:", err)
				return
			}
			err = DesyncSend(
				logger,
				dstConn,
				record,
				sniPos,
				sniLen,
				fakePacketBytes,
				policy.FakeSleep,
				ttl,
			)
			if err != nil {
				logger.Println("Error TTL desync:", err)
			}
			logger.Println("Successfully sent ClientHello")
		default:
			logger.Println("Unknown traffic mode:", policy.Mode)
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
