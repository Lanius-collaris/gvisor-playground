package stack

import (
	"localhost/aegis/utils"
	"encoding/binary"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"log"
	"net"
	"sync"
	"time"
)

const DefaultReadTimeout = 240 * time.Second
const DNSTimeout = 10 * time.Second

var IPv6HeaderForUDP = [40]byte{
	0x60, 0, 0, 0,
	0, 0, 17, 64,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
}
var IPv4HeaderForUDP = [20]byte{
	0x45, 0, 0, 0,
	0, 0, 0, 0,
	64, 17, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
}

type IPPort struct {
	IP   tcpip.Address
	Port uint16
}
type UDPConnState struct {
	sync.RWMutex
	WG       sync.WaitGroup
	Conn     net.PacketConn
	LastSend time.Time
}
type NAT struct {
	sync.RWMutex
	State map[IPPort]*UDPConnState
}

func NewUDPNAT() *NAT {
	return &NAT{
		State: make(map[IPPort]*UDPConnState),
	}
}

// All net.Addr in this file are *net.UDPAddr
type ListenUDPFn func(network string, laddr *net.UDPAddr) (net.PacketConn, error)
type HijackDNSFn func(packet []byte, conn net.Conn, wg *sync.WaitGroup)

func UDP6Checksum(srcIP []byte, dstIP []byte, p []byte) uint16 {
	var pseudoHeader [40]byte
	copy(pseudoHeader[:16], srcIP)
	copy(pseudoHeader[16:32], dstIP)
	binary.BigEndian.PutUint32(pseudoHeader[32:], uint32(len(p)))
	pseudoHeader[39] = 17

	t := utils.Uint16Sum(pseudoHeader[:]) + utils.Uint16Sum(p)
	return 0xffff - uint16(utils.ClearHigh16(t))
}
func UDP4Checksum(srcIP []byte, dstIP []byte, p []byte) uint16 {
	var pseudoHeader [12]byte
	copy(pseudoHeader[:4], srcIP)
	copy(pseudoHeader[4:8], dstIP)
	pseudoHeader[9] = 17
	binary.BigEndian.PutUint16(pseudoHeader[10:], uint16(len(p)))

	t := utils.Uint16Sum(pseudoHeader[:]) + utils.Uint16Sum(p)
	return 0xffff - uint16(utils.ClearHigh16(t))
}

func mySendUDP6(ep stack.LinkWriter, data []byte, src *net.UDPAddr, dst IPPort) (int, tcpip.Error) {
	view := buffer.NewViewSize(48 + len(data))
	ref1 := view.AsSlice()
	copy(ref1[48:], data)

	copy(ref1[:8], IPv6HeaderForUDP[:8])
	iph := header.IPv6(ref1[:40])
	iph.SetPayloadLength(uint16(8 + len(data)))
	copy(iph[8:24], src.IP)
	iph.SetDestinationAddress(dst.IP)

	udph := header.UDP(ref1[40:48])
	udph.SetSourcePort(uint16(src.Port))
	udph.SetDestinationPort(dst.Port)
	udph.SetLength(uint16(8 + len(data)))
	chksum := UDP6Checksum(src.IP, dst.IP.AsSlice(), ref1[40:])
	udph.SetChecksum(chksum)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 0,
		Payload:            buffer.MakeWithView(view),
	})
	var pktList stack.PacketBufferList
	pktList.PushBack(pkt)
	defer pktList.DecRef()

	return ep.WritePackets(pktList)
}
func mySendUDP4(ep stack.LinkWriter, data []byte, src *net.UDPAddr, dst IPPort) (int, tcpip.Error) {
	view := buffer.NewViewSize(28 + len(data))
	ref1 := view.AsSlice()
	copy(ref1[28:], data)

	copy(ref1[:12], IPv4HeaderForUDP[:12])
	iph := header.IPv4(ref1[:20])
	iph.SetTotalLength(uint16(28 + len(data)))
	copy(iph[12:16], src.IP)
	iph.SetDestinationAddress(dst.IP)
	chksum := 0xffff - uint16(utils.ClearHigh16(utils.Uint16Sum(iph)))
	iph.SetChecksum(chksum)

	udph := header.UDP(ref1[20:28])
	udph.SetSourcePort(uint16(src.Port))
	udph.SetDestinationPort(dst.Port)
	udph.SetLength(uint16(8 + len(data)))
	chksum = UDP4Checksum(src.IP, dst.IP.AsSlice(), ref1[20:])
	udph.SetChecksum(chksum)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 0,
		Payload:            buffer.MakeWithView(view),
	})
	var pktList stack.PacketBufferList
	pktList.PushBack(pkt)
	defer pktList.DecRef()

	return ep.WritePackets(pktList)
}
func ForwardInboundUDP(
	ep stack.LinkWriter,
	nat *NAT,
	dst IPPort,
	state *UDPConnState,
	readTimeout time.Duration,
) {
	defer state.Conn.Close()

	isIPv6 := dst.IP.Len() == 16
	var buf [65536]byte
	for {
		now1 := time.Now()
		state.RLock()
		lastSend := state.LastSend
		state.RUnlock()
		if now1.Sub(lastSend) > readTimeout {
			log.Printf("timeout, delete mapping: %v", dst)
			break
		}
		state.Conn.SetReadDeadline(now1.Add(readTimeout))
		n, from, err := state.Conn.ReadFrom(buf[:])
		if err != nil {
			log.Printf("failed to ReadFrom: %v", err)
			break
		}
		remoteAddr := from.(*net.UDPAddr)

		var gErr tcpip.Error
		if isIPv6 {
			n, gErr = mySendUDP6(ep, buf[:n], remoteAddr, dst)
		} else {
			n, gErr = mySendUDP4(ep, buf[:n], remoteAddr, dst)
		}
		if gErr != nil {
			log.Printf("failed to WritePackets: %v", gErr)
			break
		}
	}

	state.WG.Wait()
	nat.Lock()
	delete(nat.State, dst)
	nat.Unlock()

	log.Printf("ForwardInboundUDP() return, dst: %v",dst)
}
func NewUDPReqHandler(
	s *stack.Stack,
	linkEP stack.LinkWriter,
	nat *NAT,
	listen ListenUDPFn,
	hijack HijackDNSFn,
	readTimeout time.Duration,
) func(*udp.ForwarderRequest) {
	h := func(req *udp.ForwarderRequest) {
		timeout2 := readTimeout
		reqID := req.ID()
		isIPv6 := reqID.RemoteAddress.Len() == 16
		var wq waiter.Queue
		ep, gErr := req.CreateEndpoint(&wq)
		if gErr != nil {
			log.Printf("failed to create endpoint: %v", gErr)
			return
		}
		xConn := gonet.NewUDPConn(s,&wq, ep)

		if reqID.LocalPort == 53 {
			timeout2 = DNSTimeout
		}
		src := IPPort{reqID.RemoteAddress, reqID.RemotePort}
		nat.RLock()
		state, ok := nat.State[src]
		nat.RUnlock()

		if !ok {
			var network string
			localAddr := net.UDPAddr{Port: 0}
			if isIPv6 {
				network = "udp6"
				var t [16]byte
				localAddr.IP = t[:]
			} else {
				network = "udp4"
				var t [4]byte
				localAddr.IP = t[:]
			}
			rConn, err := listen(network, &localAddr)
			if err != nil {
				log.Printf("failed to listen UDP: %v", err)
				return
			}

			state = &UDPConnState{LastSend: time.Now(),Conn: rConn}
			go ForwardInboundUDP(linkEP, nat, src, state, timeout2)
			nat.Lock()
			nat.State[src] = state
			nat.Unlock()
		}

		state.WG.Add(1)
		go func() {
			defer func() {
				xConn.Close()
				state.WG.Done()
			}()

			dst := net.UDPAddr{
				IP:   reqID.LocalAddress.AsSlice(),
				Port: int(reqID.LocalPort),
			}
			var buf [65536]byte
			var myWG sync.WaitGroup
			for {
				now1 := time.Now()
				state.Lock()
				state.LastSend = now1
				state.Unlock()
				xConn.SetReadDeadline(now1.Add(timeout2))
				n, err := xConn.Read(buf[:])
				if err != nil {
					log.Printf("failed to read data: %v", err)
					break
				}

				if hijack != nil && dst.Port == 53 {
					dataCopy := append([]byte{}, buf[:n]...)
					myWG.Add(1)
					go hijack(dataCopy, xConn, &myWG)
					continue
				}

				_, err = state.Conn.WriteTo(buf[:n], &dst)
				if err != nil {
					log.Printf("failed to send data: %v", err)
					break
				}
			}

			myWG.Wait()

			log.Printf("myWG.Wait() return, reqID: %v",reqID)
		}()
	}
	return h
}

func LookPacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	log.Printf("handle one packet\nTransportEndpointID: %v\nAsSlices: %v", id, pkt.AsSlices())
	d := pkt.Data()
	s1, ok := d.PullUp(d.Size())
	if ok {
		log.Printf("Data: %v\n", s1)
	}
	return true
}
