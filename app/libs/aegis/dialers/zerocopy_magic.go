package dialers

import (
	"crypto/rand"
	"golang.org/x/sys/unix"
	"localhost/aegis/utils"
	"localhost/aegis/utils/cache"
	"log"
	mathrand "math/rand"
	"net"
	"net/netip"
	"time"
)

const probeSize = 8
const HTTP1_1Str = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 999999\r\n\r\n"

/*
type SockExtendedErr struct {
	Errno  uint32
	Origin uint8
	Type   uint8
	Code   uint8
	Pad    uint8
	Info   uint32
	Data   uint32
}
*/

// https://www.rfc-editor.org/rfc/rfc4443.html#section-3.3
func exceedHopLimit(cmsgArr []unix.SocketControlMessage) bool {
	for _, cmsg := range cmsgArr {
		if cmsg.Header.Level == unix.IPPROTO_IPV6 && cmsg.Header.Type == unix.IPV6_RECVERR {
			eeOrigin := cmsg.Data[4]
			if eeOrigin == unix.SO_EE_ORIGIN_ICMP6 {
				eeType := cmsg.Data[5]
				eeCode := cmsg.Data[6]
				if eeType == 3 && eeCode == 0 {
					return true
				}
			}
		}
	}
	return false
}

// https://www.rfc-editor.org/rfc/rfc792.html#page-6
func exceedTTL(cmsgArr []unix.SocketControlMessage) bool {
	for _, cmsg := range cmsgArr {
		if cmsg.Header.Level == unix.IPPROTO_IP && cmsg.Header.Type == unix.IP_RECVERR {
			eeOrigin := cmsg.Data[4]
			if eeOrigin == unix.SO_EE_ORIGIN_ICMP {
				eeType := cmsg.Data[5]
				eeCode := cmsg.Data[6]
				if eeType == 11 && eeCode == 0 {
					return true
				}
			}
		}
	}
	return false
}

func SendTTLProbe(conn *net.UDPConn, dstIP netip.Addr, maxTTL int) (int, error) {
	basePort := 1 + mathrand.Intn(65535-maxTTL)
	isIPv6 := dstIP.Is6()
	fd := GetFDFromUDPConn(conn)
	var err error
	if isIPv6 {
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1)
	} else {
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1)
	}
	if err != nil {
		return 0, err
	}

	var buf [probeSize]byte
	for ttl := 2; ttl <= maxTTL; ttl++ {
		rand.Read(buf[:])
		if isIPv6 {
			err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
		} else {
			err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl)
		}
		if err != nil {
			return 0, err
		}
		_, err = conn.WriteToUDPAddrPort(buf[:], netip.AddrPortFrom(
			dstIP,
			uint16(basePort+ttl)))
		if err != nil {
			return 0, err
		}
	}
	return basePort, nil
}

// the socket must be non-blocking
func GetTTLProbeResult(conn *net.UDPConn, dstIP netip.Addr, basePort int, maxTTL int) uint8 {
	isIPv6 := dstIP.Is6()
	fd := GetFDFromUDPConn(conn)
	ttl := 1
	var buf [probeSize]byte
	var cmsgBuf [128]byte
	for i := 2; i <= maxTTL; i++ {
		_, cmsgN, flags, from, err := unix.Recvmsg(fd, buf[:], cmsgBuf[:], unix.MSG_ERRQUEUE)
		if err != nil {
			break
		}
		if flags&unix.MSG_ERRQUEUE == 0 {
			continue
		}
		cmsgArr, err := unix.ParseSocketControlMessage(cmsgBuf[:cmsgN])
		if err != nil {
			continue
		}
		if isIPv6 {
			if exceedHopLimit(cmsgArr) {
				soAddr := from.(*unix.SockaddrInet6)
				if soAddr.Addr != dstIP.As16() {
					continue
				}
				t := soAddr.Port - basePort
				if t > ttl && t <= maxTTL {
					ttl = t
				}
			}
		} else {
			if exceedTTL(cmsgArr) {
				soAddr := from.(*unix.SockaddrInet4)
				if soAddr.Addr != dstIP.As4() {
					continue
				}
				t := soAddr.Port - basePort
				if t > ttl && t <= maxTTL {
					ttl = t
				}
			}
		}
	}
	return uint8(ttl)
}

type OverwriteConn struct {
	utils.MyTCPConn
	Payload []byte
	Used    bool
	TTL     uint8
}

// Inspired by byedpi
func (conn *OverwriteConn) Write(b []byte) (int, error) {
	if conn.Used {
		return conn.MyTCPConn.Write(b)
	}
	conn.Used = true
	if len(b) <= len(conn.Payload) {
		return conn.MyTCPConn.Write(b)
	}
	isIPv6 := conn.RemoteAddr().(*net.TCPAddr).IP.To4() == nil
	sockFD := GetFDFromTCPConn(conn.TCPConn)

	fileFD, err := unix.MemfdCreate("", 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fileFD)
	err = unix.Ftruncate(fileFD, int64(len(conn.Payload)))
	if err != nil {
		return 0, err
	}
	firstSegment, err := unix.Mmap(fileFD, 0, len(conn.Payload), unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return 0, err
	}
	defer unix.Munmap(firstSegment)

	copy(firstSegment, conn.Payload)
	if isIPv6 {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, int(conn.TTL))
	} else {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IP, unix.IP_TTL, int(conn.TTL))
	}
	if err != nil {
		return 0, err
	}
	offset := int64(0)
	n1, err := unix.Sendfile(sockFD, fileFD, &offset, len(conn.Payload))
	if err != nil {
		return n1, err
	}
	time.Sleep(time.Microsecond * 20)

	copy(firstSegment, b[:len(conn.Payload)])
	if isIPv6 {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, 64)
	} else {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IP, unix.IP_TTL, 64)
	}
	if err != nil {
		return n1, err
	}

	n2, err := conn.MyTCPConn.Write(b[len(conn.Payload):])
	return n1 + n2, err
}
func OverwriteDial1(dst netip.AddrPort, maxTTL int, payload []byte) (*OverwriteConn, error) {
	log.Printf("payload: %v", payload)
	tcpAddr := net.TCPAddr{
		IP:   dst.Addr().AsSlice(),
		Port: int(dst.Port()),
	}
	payloadCopy := append([]byte{}, payload...)
	ttl, ok := cache.GetHops(dst.Addr())
	if ok {
		log.Printf("found cached ttl: %d for %v", ttl, dst.Addr())
		tcpConn, err := net.DialTCP("tcp", nil, &tcpAddr)
		if err != nil {
			return nil, err
		}
		return &OverwriteConn{utils.TCPConnToMyTCPConn(tcpConn), payloadCopy, false, ttl}, nil
	}

	isIPv6 := dst.Addr().Is6()
	var network string
	udpAddr := net.UDPAddr{Port: 0}
	if isIPv6 {
		network = "udp6"
		var t [16]byte
		udpAddr.IP = t[:]
	} else {
		network = "udp4"
		var t [4]byte
		udpAddr.IP = t[:]
	}
	udpConn, err := net.ListenUDP(network, &udpAddr)
	if err != nil {
		return nil, err
	}
	defer udpConn.Close()
	basePort, err := SendTTLProbe(udpConn, dst.Addr(), maxTTL)
	if err != nil {
		return nil, err
	}

	tcpConn, err := net.DialTCP("tcp", nil, &tcpAddr)
	if err != nil {
		return nil, err
	}
	SetTCPKeepAlive(tcpConn, 5, 120, 1)
	conn2 := utils.TCPConnToMyTCPConn(tcpConn)

	ttl = GetTTLProbeResult(udpConn, dst.Addr(), basePort, maxTTL)
	log.Printf("traceroute result: %d for %v", ttl, dst.Addr())
	cache.PutHops(dst.Addr(), ttl)
	return &OverwriteConn{conn2, payloadCopy, false, ttl}, nil
}
