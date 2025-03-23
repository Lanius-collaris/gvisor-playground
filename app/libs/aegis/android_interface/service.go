package android_interface

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"io"
	"localhost/aegis/dialers"
	"localhost/aegis/dns"
	mystack "localhost/aegis/stack"
	"localhost/aegis/utils"
	"log"
	"net"
	"net/netip"
	"reflect"
	"sync"
)

type Haha struct {
	sync.RWMutex
	Stack        *stack.Stack
	TCPForwarder *tcp.Forwarder
	UDPNAT       *mystack.NAT
	DNSProxy     dns.DNSProxy
	UDPForwarder *udp.Forwarder
	LogWriter    io.Writer
	StatusCode   int8
}
type tlsFragOption struct {
	Size uint16 `json:"size"`
}
type overwriteOption struct {
	Payload string `json:"payload"` //base64
	MaxTTL  uint8  `json:"maxTTL"`
}
type config_t struct {
	MTU       int32           `json:"mtu"`
	Strategy  string          `json:"strategy"`
	TLSFrag   tlsFragOption   `json:"tlsFrag"`
	Overwrite overwriteOption `json:"overwrite"`
	DoHURL    string
	DoHIP     string
}

const (
	StatusStop    = 0
	StatusRunning = 1
)

var state1 Haha = Haha{
	LogWriter: io.Discard,
}

func dialTCP(dstIP tcpip.Address, dstPort uint16) (mystack.TCPLike, error) {
	dst := net.TCPAddr{
		IP:   dstIP.AsSlice(),
		Port: int(dstPort),
	}
	tcpConn, err := net.DialTCP("tcp", nil, &dst)
	if err != nil {
		return nil, err
	}
	dialers.SetTCPKeepAlive(tcpConn, 5, 120, 1)
	conn2 := utils.TCPConnToMyTCPConn(tcpConn)
	return &conn2, nil
}
func listenUDP(network string, laddr *net.UDPAddr) (mystack.UDPLike, error) {
	udpConn, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}
	conn2 := utils.UDPConnToMyUDPConn(udpConn)
	return &conn2, nil
}

func DryRun(conf string) string {
	var cfg config_t
	err := json.Unmarshal([]byte(conf), &cfg)
	if err != nil {
		return err.Error()
	}
	return ""
}
func DontLog(a bool) {
	if reflect.TypeOf(log.Writer()).String() != reflect.TypeOf(io.Discard).String() {
		state1.LogWriter = log.Writer()
	}
	if a {
		log.SetOutput(io.Discard)
	} else {
		log.SetOutput(state1.LogWriter)
	}
}
func Start(fd int32, conf string) int8 {
	var status int8
	state1.RLock()
	status = state1.StatusCode
	state1.RUnlock()
	if status != StatusStop {
		return status
	}

	state1.Lock()
	defer state1.Unlock()

	config := config_t{
		Strategy: "none",
	}
	err := json.Unmarshal([]byte(conf), &config)
	if err != nil {
		return status
	}

	log.SetFlags(log.Lshortfile)
	DontLog(true)

	state1.Stack = mystack.NewStack()
	defer func() {
		if status != StatusRunning {
			state1.Stack.Destroy()
		}
	}()

	var tcpfn mystack.DialTCPFn
	switch config.Strategy {
	case "tlsfrag":
		tcpfn = func(dstIP tcpip.Address, dstPort uint16) (mystack.TCPLike, error) {
			dst := net.TCPAddr{
				IP:   dstIP.AsSlice(),
				Port: int(dstPort),
			}
			tcpConn, err := net.DialTCP("tcp", nil, &dst)
			if err != nil {
				return nil, err
			}
			dialers.SetTCPKeepAlive(tcpConn, 5, 120, 1)
			conn2 := utils.TCPConnToMyTCPConn(tcpConn)
			return &dialers.TLSFragConn{conn2, config.TLSFrag.Size, false}, nil
		}
	case "overwrite":
		payload, err := base64.StdEncoding.DecodeString(config.Overwrite.Payload)
		if err != nil {
			payload = []byte(dialers.HTTP1_1Str)
		}
		tcpfn = func(dstIP tcpip.Address, dstPort uint16) (mystack.TCPLike, error) {
			t1, _ := netip.AddrFromSlice(dstIP.AsSlice())
			if t1.IsPrivate() {
				return dialTCP(dstIP, dstPort)
			}
			return dialers.OverwriteDial1(
				netip.AddrPortFrom(t1, dstPort),
				int(config.Overwrite.MaxTTL),
				payload)
		}
	default:
		tcpfn = dialTCP
	}

	bufPool := sync.Pool{
		New: func() any {
			return make([]byte, 65536)
		},
	}
	for i := 0; i < 8; i++ {
		bufPool.Put(make([]byte, 65536))
	}

	tcpHandler := mystack.NewTCPReqHandler(tcpfn, &bufPool)
	state1.TCPForwarder = tcp.NewForwarder(state1.Stack, 0, 10000, tcpHandler)
	state1.Stack.SetTransportProtocolHandler(tcp.ProtocolNumber, state1.TCPForwarder.HandlePacket)

	dialer := net.Dialer{}
	var dialContextFn1 dns.DialContextFn
	switch config.Strategy {
	case "overwrite":
		payload, err := base64.StdEncoding.DecodeString(config.Overwrite.Payload)
		if err != nil {
			payload = []byte(dialers.HTTP1_1Str)
		}
		dialContextFn1 = func(ctx context.Context, network, addr string) (net.Conn, error) {
			t1 := netip.MustParseAddrPort(addr)
			if t1.Addr().IsPrivate() {
				conn, err := dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				tcpConn := conn.(*net.TCPConn)
				dialers.SetTCPKeepAlive(tcpConn, 5, 120, 1)
				return conn, nil
			}
			return dialers.OverwriteDial1(
				t1,
				int(config.Overwrite.MaxTTL),
				payload)
		}
	default:
		dialContextFn1 = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tcpConn := conn.(*net.TCPConn)
			dialers.SetTCPKeepAlive(tcpConn, 5, 120, 1)
			conn2 := utils.TCPConnToMyTCPConn(tcpConn)
			return &dialers.TLSFragConn{conn2, config.TLSFrag.Size, false}, nil
		}
	}
	dialContextFn2 := func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4", "tcp6":
			return dialContextFn1(ctx, network, addr)
		default:
			return dialer.DialContext(ctx, network, addr)
		}
	}
	state1.DNSProxy = dns.NewDNSProxy(dialContextFn2, config.DoHURL, config.DoHIP)

	state1.UDPNAT = mystack.NewUDPNAT(&bufPool)
	linkEP, err := mystack.NewLinkEP(fd, uint32(config.MTU))
	if err != nil {
		return status
	}
	udpHandler := mystack.NewUDPReqHandler(state1.Stack, linkEP, state1.UDPNAT, listenUDP, state1.DNSProxy.Hijack, mystack.DefaultReadTimeout)
	state1.UDPForwarder = udp.NewForwarder(state1.Stack, udpHandler)
	state1.Stack.SetTransportProtocolHandler(udp.ProtocolNumber, state1.UDPForwarder.HandlePacket)

	icmpHack := mystack.NewICMPHackTarget(linkEP, &bufPool, mystack.DNSTimeout)
	mystack.DropICMP(state1.Stack, &icmpHack)

	err = mystack.CreateNIC(state1.Stack, 1, linkEP)
	if err != nil {
		return status
	}

	status = StatusRunning
	state1.StatusCode = status
	return status
}
func Stop() {
	var status int8
	state1.RLock()
	status = state1.StatusCode
	state1.RUnlock()
	if status != StatusRunning {
		return
	}

	state1.Lock()
	defer state1.Unlock()

	state1.Stack.Destroy()
	state1.TCPForwarder = nil
	state1.UDPForwarder = nil
	state1.DNSProxy = dns.DNSProxy{}
	state1.UDPNAT = nil

	state1.StatusCode = StatusStop
}
