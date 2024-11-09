package stack

import (
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

/*
Drop ICMP packets to disable fake ICMP echo
https://github.com/google/gvisor/blob/release-20231023.0/pkg/tcpip/network/ipv6/ipv6.go#L1125
https://github.com/google/gvisor/blob/release-20231023.0/pkg/tcpip/network/ipv4/ipv4.go#L853
*/
func DropICMP(s *stack.Stack) {
	ipt := s.IPTables()

	table := ipt.GetTable(stack.MangleID, true)
	index := table.BuiltinChains[stack.Prerouting]
	rules := table.Rules
	rules[index].Filter.Protocol = header.ICMPv6ProtocolNumber
	rules[index].Filter.CheckProtocol = true
	rules[index].Target = &stack.DropTarget{NetworkProtocol: header.IPv6ProtocolNumber}
	ipt.ReplaceTable(stack.MangleID, table, true)

	table = ipt.GetTable(stack.MangleID, false)
	index = table.BuiltinChains[stack.Prerouting]
	rules = table.Rules
	rules[index].Filter.Protocol = header.ICMPv4ProtocolNumber
	rules[index].Filter.CheckProtocol = true
	rules[index].Target = &stack.DropTarget{NetworkProtocol: header.IPv4ProtocolNumber}
	ipt.ReplaceTable(stack.MangleID, table, false)
}
