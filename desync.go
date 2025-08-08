//go:build windows
// +build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

func FindMinReachableTTL(addr string) (int, error) {
	low, high := 1, 32
	found := -1

	for low <= high {
		mid := (low + high) / 2
		ok, err := tryConnectWithTTL(addr, mid)
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

func tryConnectWithTTL(address string, ttl int) (bool, error) {
	dialer := net.Dialer{
		Timeout: 500 * time.Millisecond,
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = windows.SetsockoptInt(windows.Handle(fd),
					windows.IPPROTO_IP,
					windows.IP_TTL,
					ttl)
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}

	conn, err := dialer.DialContext(context.Background(), "tcp4", address)
	if err != nil {
		return false, err
	}
	_ = conn.Close()
	return true, nil
}

func sendDataWithFake(
	sockHandle windows.Handle,
	fakeData, realData []byte,
	dataLen, fakeTTL, defaultTTL int,
	fakeSleep float64,
) error {
	if fakeSleep < 0.1 {
		fakeSleep = 0.1
	}
	toWrite := uint32(dataLen)

	tmpFile := filepath.Join(os.TempDir(), uuid.New().String())
	defer os.Remove(tmpFile)
	ptr, err := windows.UTF16PtrFromString(tmpFile)
	if err != nil {
		return err
	}
	fileHandle, err := windows.CreateFile(
		ptr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_DELETE_ON_CLOSE,
		windows.InvalidHandle,
	)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}

	var ov windows.Overlapped
	eventHandle, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("failed to create event: %v", err)
	}
	ov.HEvent = eventHandle

	var zero *int32
	_, err = windows.SetFilePointer(fileHandle, 0, zero, 0)
	if err != nil {
		return fmt.Errorf("failed to set file pointer: %v", err)
	}
	err = windows.WriteFile(
		fileHandle,
		fakeData,
		nil,
		&ov,
	)
	if err != nil {
		return fmt.Errorf("failed to write fake data: %v", err)
	}
	if err = windows.SetEndOfFile(fileHandle); err != nil {
		return fmt.Errorf("failed to set end of file: %v", err)
	}
	err = windows.SetsockoptInt(
		sockHandle,
		windows.IPPROTO_IP,
		windows.IP_TTL,
		fakeTTL,
	)
	if err != nil {
		return fmt.Errorf("failed to set fake TTL: %v", err)
	}

	_, err = windows.SetFilePointer(fileHandle, 0, zero, 0)
	if err != nil {
		return fmt.Errorf("failed to set file pointer: %v", err)
	}
	_ = windows.TransmitFile(
		sockHandle,
		fileHandle,
		toWrite,
		toWrite,
		&ov,
		nil,
		windows.TF_USE_KERNEL_APC|windows.TF_WRITE_BEHIND,
	)
	time.Sleep(time.Duration(fakeSleep * float64(time.Second)))

	_, err = windows.SetFilePointer(fileHandle, 0, zero, 0)
	if err != nil {
		return fmt.Errorf("failed to set file pointer: %v", err)
	}
	err = windows.WriteFile(
		fileHandle,
		realData,
		nil,
		&ov,
	)
	if err != nil {
		return fmt.Errorf("failed to write real data: %v", err)
	}
	if err = windows.SetEndOfFile(fileHandle); err != nil {
		return fmt.Errorf("failed to set end of file: %v", err)
	}
	_, err = windows.SetFilePointer(fileHandle, 0, zero, 0)
	if err != nil {
		return fmt.Errorf("failed to set file pointer: %v", err)
	}
	err = windows.SetsockoptInt(
		sockHandle,
		windows.IPPROTO_IP,
		windows.IP_TTL,
		defaultTTL,
	)
	if err != nil {
		return fmt.Errorf("failed to set default TTL: %v", err)
	}

	val, err := windows.WaitForSingleObject(ov.HEvent, 5000)
	if err != nil {
		return fmt.Errorf("TransmitFile call failed on waiting for event: %v", err)
	}
	if val != 0 {
		return errors.New("TransmitFile call fialed")
	}
	return nil
}

func DesyncSend(
	logger *log.Logger,
	conn net.Conn,
	firstPacket []byte,
	sniPos, sniLen int,
	fakeData []byte,
	fakeSleep float64,
	fakeTTL int,
) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return errors.New("not *net.TCPConn")
	}
	if err := tcpConn.SetNoDelay(true); err != nil {
		return fmt.Errorf("failed to set TCP_NODELAY: %v", err)
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get rawConn: %v", err)
	}
	var sockHandle windows.Handle
	controlErr := rawConn.Control(func(fd uintptr) {
		sockHandle = windows.Handle(fd)
	})
	if controlErr != nil {
		return fmt.Errorf("control error: %v", err)
	}

	defaultTTL, err := windows.GetsockoptInt(
		sockHandle,
		windows.IPPROTO_IP,
		windows.IP_TTL,
	)
	if err != nil {
		return fmt.Errorf("failed to get default TTL: %v", err)
	}
	dataLen := len(fakeData)
	err = sendDataWithFake(
		sockHandle,
		fakeData,
		firstPacket[:dataLen],
		dataLen,
		fakeTTL,
		defaultTTL,
		fakeSleep,
	)
	if err != nil {
		return fmt.Errorf("failed to send first fake data: %v", err)
	}
	firstPacket = firstPacket[dataLen:]
	offset := sniLen/2 + sniPos - dataLen
	if _, err = conn.Write(firstPacket[:offset]); err != nil {
		return fmt.Errorf("failed to send data after first fake packet: %v", err)
	}
	firstPacket = firstPacket[offset:]
	err = sendDataWithFake(
		sockHandle,
		fakeData,
		firstPacket[:dataLen],
		dataLen,
		fakeTTL,
		defaultTTL,
		fakeSleep,
	)
	if err != nil {
		return fmt.Errorf("failed to send second fake data: %v", err)
	}
	if _, err = conn.Write(firstPacket[dataLen:]); err != nil {
		return fmt.Errorf("failed to send remaining data: %v", err)
	}

	return nil
}
