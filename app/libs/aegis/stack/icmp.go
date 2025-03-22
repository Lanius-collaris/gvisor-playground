package stack

import (
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"log"
)

/*
Drop ICMP packets to disable fake ICMP echo
https://github.com/google/gvisor/blob/release-20231023.0/pkg/tcpip/network/ipv6/ipv6.go#L1125
https://github.com/google/gvisor/blob/release-20231023.0/pkg/tcpip/network/ipv4/ipv4.go#L853
*/
func DropICMP(s *stack.Stack, target stack.Target) {
	ipt := s.IPTables()

	table := ipt.GetTable(stack.MangleID, true)
	index := table.BuiltinChains[stack.Prerouting]
	rules := table.Rules
	rules[index].Filter.Protocol = header.ICMPv6ProtocolNumber
	rules[index].Filter.CheckProtocol = true
	rules[index].Target = target
	ipt.ReplaceTable(stack.MangleID, table, true)

	table = ipt.GetTable(stack.MangleID, false)
	index = table.BuiltinChains[stack.Prerouting]
	rules = table.Rules
	rules[index].Filter.Protocol = header.ICMPv4ProtocolNumber
	rules[index].Filter.CheckProtocol = true
	rules[index].Target = target
	ipt.ReplaceTable(stack.MangleID, table, false)
}

func LookICMPPacket(pkt *stack.PacketBuffer) {
	log.Printf("handle one packet\nNetworkHeader: %v\nTransportHeader: %v",
		pkt.NetworkHeader().Slice(),
		pkt.TransportHeader().Slice(),
	)
	d := pkt.Data()
	s1, ok := d.PullUp(d.Size())
	if ok {
		log.Printf("Data: %v\n", s1)
	}
}

type ICMPHackTarget struct{}

func (t *ICMPHackTarget) Action(pkt *stack.PacketBuffer, hook stack.Hook, r *stack.Route, _ stack.AddressableEndpoint) (stack.RuleVerdict, int) {
	//LookICMPPacket(pkt)
	return stack.RuleDrop, 0
}
