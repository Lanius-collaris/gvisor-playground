package stack

import (
	"fmt"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
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
