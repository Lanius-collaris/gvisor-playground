package utils

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const SO_EE_ORIGIN_ICMP = 2
const SO_EE_ORIGIN_ICMP6 = 3

func ToNumber(e error) syscall.Errno {
	cause := e
	for {
		if unwrap, ok := cause.(interface{ Unwrap() error }); ok {
			cause = unwrap.Unwrap()
		} else {
			break
		}
	}
	n, ok := cause.(syscall.Errno)
	if ok {
		return n
	}
	return syscall.Errno(0)
}

func Ioctl(fd int, req uint64, data []byte) (int, error) {
	p := unsafe.Pointer(&data[0])
	r1, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(p))
	if errno == 0 {
		return int(r1), nil
	} else {
		return int(r1), errno
	}
}
func OpenTUN(name string) (int, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 600)
	if err != nil {
		return fd, err
	}
	var req [64]byte
	copy(req[:15], []byte(name))
	flags := uint16(syscall.IFF_TUN | syscall.IFF_NO_PI)
	binary.NativeEndian.PutUint16(req[16:], flags)
	_, err = Ioctl(fd, syscall.TUNSETIFF, req[:])
	if err != nil {
		defer syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func GenFDCmsg(fds []uint32) []byte {
	cmsgLen := 16 + len(fds)*4
	cmsg := make([]byte, cmsgLen)
	binary.NativeEndian.PutUint64(cmsg[:], uint64(cmsgLen))
	binary.NativeEndian.PutUint32(cmsg[8:], syscall.SOL_SOCKET)
	binary.NativeEndian.PutUint32(cmsg[12:], syscall.SCM_RIGHTS)

	offset := 16
	for _, v := range fds {
		binary.NativeEndian.PutUint32(cmsg[offset:], v)
		offset += 4
	}
	return cmsg
}

func IsReadable(raw syscall.RawConn, deadline time.Time) bool {
	t := 0
	raw.Read(func(fd uintptr) bool {
		if t == 0 {
			t += 1
			return false
		} else {
			return true
		}
	})
	if time.Now().Sub(deadline) < 0 {
		return true
	} else {
		return false
	}
}

type MyTCPConn struct {
	*net.TCPConn
	Raw syscall.RawConn
}

func TCPConnToMyTCPConn(tcpConn *net.TCPConn) MyTCPConn {
	raw, _ := tcpConn.SyscallConn()
	return MyTCPConn{tcpConn, raw}
}
func (conn *MyTCPConn) IsReadable(deadline time.Time) bool {
	return IsReadable(conn.Raw, deadline)
}
func (conn *MyTCPConn) Recvmsg(buf []byte, cmsgBuf []byte, flags int) (n, cmsgLen int, recvflags int, from syscall.Sockaddr, err error) {
	conn.Raw.Control(func(t uintptr) {
		n, cmsgLen, recvflags, from, err = syscall.Recvmsg(int(t), buf, cmsgBuf, flags)
	})
	if n == 0 {
		err = &net.OpError{
			Op:     "read",
			Net:    "tcp",
			Source: conn.TCPConn.LocalAddr(),
			Addr:   conn.TCPConn.RemoteAddr(),
			Err:    io.EOF,
		}
	}
	return
}
func (conn *MyTCPConn) GetsockoptInt(level int, opt int) (int, error) {
	var (
		val int
		err error = nil
	)
	conn.Raw.Control(func(fd uintptr) {
		val, err = syscall.GetsockoptInt(int(fd), level, opt)
	})
	return val, err
}

type MyUDPConn struct {
	*net.UDPConn
	Raw syscall.RawConn
}

func UDPConnToMyUDPConn(udpConn *net.UDPConn) MyUDPConn {
	raw, _ := udpConn.SyscallConn()
	return MyUDPConn{udpConn, raw}
}
func FdToUDPConn(fd int) MyUDPConn {
	defer syscall.Close(fd)
	conn, _ := net.FilePacketConn(os.NewFile(uintptr(fd), ""))
	return UDPConnToMyUDPConn(conn.(*net.UDPConn))
}
func (conn *MyUDPConn) IsReadable(deadline time.Time) bool {
	return IsReadable(conn.Raw, deadline)
}
func (conn *MyUDPConn) Recvmsg(buf []byte, cmsgBuf []byte, flags int) (n, cmsgLen int, recvflags int, from syscall.Sockaddr, err error) {
	conn.Raw.Control(func(t uintptr) {
		n, cmsgLen, recvflags, from, err = syscall.Recvmsg(int(t), buf, cmsgBuf, flags)
	})
	return
}

func ClearHigh16(n uint32) uint32 {
	for n > 0xffff {
		n = (n >> 16) + (n & 0xffff)
	}
	return n
}
func Uint16Sum(data []byte) uint32 {
	t := uint32(0)
	l := len(data)
	for i := 0; i < l-1; i += 2 {
		t += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if l%2 != 0 {
		t += uint32(data[l-1]) << 8
	}
	return t
}
