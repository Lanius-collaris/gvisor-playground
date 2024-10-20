package utils

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

func ToNumber(e error) syscall.Errno {
	cause := e
	for {
		if unwrap, ok := cause.(interface{ Unwrap() error }); ok {
			cause = unwrap.Unwrap()
			continue
		}
		break
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
