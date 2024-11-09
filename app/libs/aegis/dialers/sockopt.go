package dialers

import (
	"golang.org/x/sys/unix"
	"net"
)

func GetFDFromTCPConn(conn *net.TCPConn) int {
	var fd int
	raw, _ := conn.SyscallConn()
	raw.Control(func(t uintptr) {
		fd = int(t)
	})
	return fd
}
func GetFDFromUDPConn(conn *net.UDPConn) int {
	var fd int
	raw, _ := conn.SyscallConn()
	raw.Control(func(t uintptr) {
		fd = int(t)
	})
	return fd
}

func SetTCPKeepAlive(conn *net.TCPConn, count int, idle int, intvl int) {
	fd := GetFDFromTCPConn(conn)
	unix.SetsockoptInt(fd, unix.SOL_TCP, unix.TCP_KEEPCNT, count)
	unix.SetsockoptInt(fd, unix.SOL_TCP, unix.TCP_KEEPIDLE, idle)
	unix.SetsockoptInt(fd, unix.SOL_TCP, unix.TCP_KEEPINTVL, intvl)
}
