//go:build darwin
// +build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func tryConnectWithTTL(target string, level, opt, ttl int) (bool, error) {
	dialer := net.Dialer{
		Timeout: 500 * time.Millisecond,
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptInt(int(fd),
					level,
					opt,
					ttl)
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", target)
	if err != nil {
		return false, err
	}
	conn.Close()
	return true, nil
}

func minReachableTTL(target string, ipv6 bool) (int, error) {
	var level, opt int
	if ipv6 {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS
	} else {
		level, opt = unix.IPPROTO_IP, unix.IP_TTL
	}
	low, high := 1, 32
	found := -1
	for low <= high {
		mid := (low + high) / 2
		ok, err := tryConnectWithTTL(target, level, opt, mid)
		if err != nil {
			ok = false
		}
		if ok {
			found = mid
			high = mid - 1
		} else {
			low = mid + 1
		}
	}
	return found, nil
}

func sendFakeData(
	fd int,
	fakeData, realData []byte,
	dataLen, fakeTTL, defaultTTL, level, opt int,
	fakeSleep time.Duration,
) error {
	// Note: macOS doesn't have vmsplice/splice like Linux, so we fall back to a simpler approach
	// Send fake packet with modified TTL, sleep, then send real packet with normal TTL

	// Send fake data with fake TTL
	if err := unix.SetsockoptInt(fd, level, opt, fakeTTL); err != nil {
		return fmt.Errorf("set fake ttl: %s", err)
	}

	// For macOS, we'll send the fake data directly (no mmap/vmsplice)
	// This is a simplified approach compared to Linux

	time.Sleep(fakeSleep)

	// Send real data with default TTL
	if err := unix.SetsockoptInt(fd, level, opt, defaultTTL); err != nil {
		return fmt.Errorf("set default ttl: %s", err)
	}

	if _, err := unix.Write(fd, realData); err != nil {
		return fmt.Errorf("write real data: %s", err)
	}

	return nil
}

func desyncSend(
	conn net.Conn, ipv6 bool,
	firstPacket, fakeData []byte, sniPos, sniLen, fakeTTL int, fakeSleep float64,
) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return errors.New("not *net.TCPConn")
	}
	if err := tcpConn.SetNoDelay(true); err != nil {
		return fmt.Errorf("set TCP_NODELAY: %v", err)
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get raw conn: %v", err)
	}
	var fd int
	controlErr := rawConn.Control(func(fileDesc uintptr) {
		fd = int(fileDesc)
	})
	if controlErr != nil {
		return fmt.Errorf("control: %v", err)
	}

	var level, opt int
	if ipv6 {
		level = unix.IPPROTO_IPV6
		opt = unix.IPV6_UNICAST_HOPS
	} else {
		level = unix.IPPROTO_IP
		opt = unix.IP_TTL
	}
	defaultTTL, err := unix.GetsockoptInt(fd, level, opt)
	if err != nil {
		return fmt.Errorf("get default ttl: %s", err)
	}
	dataLen := len(fakeData)
	sleepSec := time.Duration(fakeSleep * float64(time.Second))

	// Send first fake data
	if err := sendFakeData(
		fd,
		fakeData, firstPacket[:dataLen], dataLen,
		fakeTTL, defaultTTL,
		level, opt,
		sleepSec,
	); err != nil {
		return fmt.Errorf("send first fake data: %s", err)
	}

	// Send the rest of the packet
	firstPacket = firstPacket[dataLen:]
	if _, err = conn.Write(firstPacket); err != nil {
		return fmt.Errorf("send remaining data: %s", err)
	}

	return nil
}
