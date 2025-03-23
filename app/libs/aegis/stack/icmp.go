package stack

import (
	"encoding/binary"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"localhost/aegis/utils"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
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

func mySendICMPv6(ep stack.LinkWriter, data []byte, src *syscall.SockaddrInet6, dst IPPort, hopLimit uint8) (int, tcpip.Error) {
	view := buffer.NewViewSize(40 + len(data))
	ref1 := view.AsSlice()
	copy(ref1[40:], data)

	copy(ref1[:8], IPv6HeaderForUDP[:8])
	iph := header.IPv6(ref1[:40])
	iph.SetPayloadLength(uint16(len(data)))
	iph.SetNextHeader(0x3a)
	iph.SetHopLimit(hopLimit)
	copy(iph[8:24], src.Addr[:])
	iph.SetDestinationAddress(dst.IP)

	icmph := header.ICMPv6(ref1[40:48])
	chksum := L4OverIPv6Checksum(0x3a, src.Addr[:], dst.IP.AsSlice(), ref1[40:])
	icmph.SetChecksum(chksum)
	return writeView(ep, view)
}
func mySendICMPv4(ep stack.LinkWriter, data []byte, src *syscall.SockaddrInet4, dst IPPort, ttl uint8) (int, tcpip.Error) {
	view := buffer.NewViewSize(20 + len(data))
	ref1 := view.AsSlice()
	copy(ref1[20:], data)

	copy(ref1[:12], IPv4HeaderForUDP[:12])
	iph := header.IPv4(ref1[:20])
	iph.SetTotalLength(uint16(20 + len(data)))
	iph.SetTTL(ttl)
	iph[9] = 1
	copy(iph[12:16], src.Addr[:])
	iph.SetDestinationAddress(dst.IP)
	chksum := 0xffff - uint16(utils.ClearHigh16(utils.Uint16Sum(iph)))
	iph.SetChecksum(chksum)

	icmph := header.ICMPv4(ref1[20:28])
	chksum = 0xffff - uint16(utils.ClearHigh16(utils.Uint16Sum(data)))
	icmph.SetChecksum(chksum)
	return writeView(ep, view)
}

type ICMPHackTarget struct {
	EP          stack.LinkWriter
	NAT         *NAT
	ReadTimeout time.Duration
}

func NewICMPHackTarget(ep stack.LinkWriter, bufPool *sync.Pool, readTimeout time.Duration) ICMPHackTarget {
	return ICMPHackTarget{ep, NewUDPNAT(bufPool), readTimeout}
}
func (t *ICMPHackTarget) Action(pkt *stack.PacketBuffer, hook stack.Hook, r *stack.Route, _ stack.AddressableEndpoint) (stack.RuleVerdict, int) {
	isIPv6 := pkt.NetworkProtocolNumber == header.IPv6ProtocolNumber
	networkH := pkt.NetworkHeader().Slice()
	transportH := pkt.TransportHeader().Slice()
	if len(transportH) < 8 {
		return stack.RuleDrop, 0
	}

	var src IPPort
	if isIPv6 {
		if len(networkH) < 40 {
			return stack.RuleDrop, 0
		}
		if transportH[0] != 128 {
			return stack.RuleDrop, 0
		}
		ip6h := header.IPv6(networkH)
		src.IP = ip6h.SourceAddress()
		icmp6h := header.ICMPv6(transportH)
		src.Port = icmp6h.Ident()
	} else {
		if len(networkH) < 20 {
			return stack.RuleDrop, 0
		}
		if transportH[0] != 8 {
			return stack.RuleDrop, 0
		}
		ip4h := header.IPv4(networkH)
		src.IP = ip4h.SourceAddress()
		icmp4h := header.ICMPv4(transportH)
		src.Port = icmp4h.Ident()
	}

	t.NAT.RLock()
	state, ok := t.NAT.State[src]
	t.NAT.RUnlock()

	var (
		sockFD int
		err    error
	)
	if !ok {
		if isIPv6 {
			sockFD, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMPV6)
		} else {
			sockFD, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
		}
		if err != nil {
			log.Printf("failed to open ICMP socket: %v", err)
			return stack.RuleDrop, 0
		}
		if isIPv6 {
			err = syscall.Bind(sockFD, &syscall.SockaddrInet6{})
		} else {
			err = syscall.Bind(sockFD, &syscall.SockaddrInet4{})
		}
		if err != nil {
			log.Printf("bind() error: %v", err)
			return stack.RuleDrop, 0
		}
		if isIPv6 {
			syscall.SetsockoptInt(sockFD, syscall.SOL_IPV6, syscall.IPV6_RECVHOPLIMIT, 1)
		} else {
			syscall.SetsockoptInt(sockFD, syscall.SOL_IP, syscall.IP_RECVTTL, 1)
		}

		rConn := utils.FdToUDPConn(sockFD)
		state = &UDPConnState{LastSend: time.Now(), Conn: &rConn}
		go ForwardInboundICMPEcho(t.EP, t.NAT, src, state, t.ReadTimeout)
		t.NAT.Lock()
		t.NAT.State[src] = state
		t.NAT.Unlock()
	}

	state.WG.Add(1)
	defer state.WG.Done()

	dst := net.UDPAddr{Port: 0}
	if isIPv6 {
		dst.IP = networkH[24:40]
	} else {
		dst.IP = networkH[16:20]
	}
	msg := stack.PayloadSince(pkt.TransportHeader()).AsSlice()
	//clear checksum and identifier
	for i := 2; i < 6; i++ {
		msg[i] = 0
	}

	now1 := time.Now()
	state.Lock()
	state.LastSend = now1
	state.Unlock()

	_, _, err = state.Conn.WriteMsgUDP(msg, nil, &dst)
	if err != nil {
		log.Printf("failed to send data: %v", err)
	}

	return stack.RuleDrop, 0
}
func ForwardInboundICMPEcho(
	ep stack.LinkWriter,
	nat *NAT,
	dst IPPort,
	state *UDPConnState,
	readTimeout time.Duration,
) {
	defer state.Conn.Close()

	isIPv6 := dst.IP.Len() == 16
out1:
	for {
		now1 := time.Now()
		state.RLock()
		lastSend := state.LastSend
		state.RUnlock()
		if now1.Sub(lastSend) > readTimeout {
			log.Printf("timeout, delete mapping: %v", dst)
			break
		}
		deadline := now1.Add(readTimeout)
		state.Conn.SetReadDeadline(deadline)

		buf := nat.BufPool.Get().([]byte)
		var cmsgBuf [256]byte
	in_data:
		for {
			n, cmsgLen, _, from, err := state.Conn.Recvmsg(buf, cmsgBuf[:], 0)
			if err != nil {
				switch utils.ToNumber(err) {
				case syscall.EAGAIN:
					break in_data
				default:
					nat.BufPool.Put(buf)
					log.Printf("failed to Recvmsg: %v", err)
					break out1
				}
			}
			if n >= 8 {
				icmph := header.ICMPv6(buf[:8])
				icmph.SetIdent(dst.Port)
				icmph.SetChecksum(0)
			}
			ttl := uint8(64)
			if cmsgLen >= 20 {
				ttl = uint8(binary.NativeEndian.Uint32(cmsgBuf[16:]))
			}

			var gErr tcpip.Error
			if isIPv6 {
				_, gErr = mySendICMPv6(ep, buf[:n], from.(*syscall.SockaddrInet6), dst, ttl)
			} else {
				_, gErr = mySendICMPv4(ep, buf[:n], from.(*syscall.SockaddrInet4), dst, ttl)
			}
			if gErr != nil {
				nat.BufPool.Put(buf)
				log.Printf("failed to WritePackets: %v", gErr)
				break out1
			}
		}

		if !state.Conn.IsReadable(deadline) {
			log.Printf("wait for readable events: timeout")
			break
		}
	}

	state.WG.Wait()
	nat.Lock()
	delete(nat.State, dst)
	nat.Unlock()

	log.Printf("ForwardInboundICMPEcho() return, dst: %v", dst)
}
