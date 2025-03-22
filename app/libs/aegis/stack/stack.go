package stack

import (
	"bytes"
	"errors"
	"fmt"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"net"
)

func NewStack() *stack.Stack {
	opt := stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv6.NewProtocol,
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
		HandleLocal: false,
	}
	netStack := stack.New(opt)

	sack := tcpip.TCPSACKEnabled(true)
	netStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	return netStack
}

func NewLinkEP(tunFD int32, mtu uint32) (stack.LinkEndpoint, error) {
	opt := fdbased.Options{
		FDs:               []int{int(tunFD)},
		MTU:               mtu,
		RXChecksumOffload: true,
	}
	return fdbased.New(&opt)
}

func CreateNIC(s *stack.Stack, id tcpip.NICID, ep stack.LinkEndpoint) error {
	opt := stack.NICOptions{Disabled: true}
	stackErr := s.CreateNICWithOptions(id, ep, opt)
	if stackErr != nil {
		return fmt.Errorf("failed to create NIC: %v", stackErr)
	}

	routes := [2]tcpip.Route{
		{NIC: id, Destination: header.IPv6EmptySubnet},
		{NIC: id, Destination: header.IPv4EmptySubnet},
	}
	s.SetRouteTable(routes[:])
	stackErr = s.SetSpoofing(id, true)
	if stackErr != nil {
		return fmt.Errorf("failed to SetSpoofing: %v", stackErr)
	}
	stackErr = s.SetPromiscuousMode(id, true)
	if stackErr != nil {
		return fmt.Errorf("failed to SetPromiscuousMode: %v", stackErr)
	}

	stackErr = s.EnableNIC(id)
	if stackErr != nil {
		return fmt.Errorf("failed to enable NIC: %v", stackErr)
	}

	return nil
}

func FullToUDPAddr(addr tcpip.FullAddress) net.UDPAddr {
	return net.UDPAddr{
		IP:   addr.Addr.AsSlice(),
		Port: int(addr.Port),
	}
}
func GenerateErrForEP(ep tcpip.Endpoint, op string, gErr tcpip.Error) error {
	FinalErr := net.OpError{
		Op:  op,
		Net: "tcpip.Endpoint",
		Err: errors.New(gErr.String()),
	}
	addr, err := ep.GetLocalAddress()
	if err == nil {
		t := FullToUDPAddr(addr)
		FinalErr.Source = &t
	}
	addr, err = ep.GetRemoteAddress()
	if err == nil {
		t := FullToUDPAddr(addr)
		FinalErr.Addr = &t
	}
	return &FinalErr
}
func ReadFromEP(buf []byte, ep tcpip.Endpoint) (tcpip.ReadResult, error) {
	w := tcpip.SliceWriter(buf)
	opt := tcpip.ReadOptions{
		NeedRemoteAddr: true,
	}
	res, gErr := ep.Read(&w, opt)
	if gErr == nil {
		return res, nil
	}
	return res, GenerateErrForEP(ep, "read", gErr)
}
func WriteToEP(buf []byte, opt tcpip.WriteOptions, ep tcpip.Endpoint, writableCh <-chan struct{}) (int, error) {
	var (
		r       bytes.Reader
		written int = 0
	)
	for written < len(buf) {
		r.Reset(buf[written:])
		n, gErr := ep.Write(&r, opt)
		written += int(n)
		if gErr != nil {
			switch gErr.(type) {
			case *tcpip.ErrWouldBlock:
				<-writableCh
			default:
				return written, GenerateErrForEP(ep, "write", gErr)
			}
		}
	}
	return written, nil
}
