package stack

import (
	"encoding/binary"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"localhost/aegis/utils"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
)

const DefaultReadTimeout = 240 * time.Second
const DNSTimeout = 10 * time.Second

type IPPort struct {
	IP   tcpip.Address
	Port uint16
}
type UDPLike interface {
	net.Conn
	IsReadable(deadline time.Time) bool
	Recvmsg(buf []byte, cmsgBuf []byte, flags int) (n, cmsgLen int, recvflags int, from syscall.Sockaddr, err error)
	WriteMsgUDP(b []byte, cmsg []byte, addr *net.UDPAddr) (n, cmsgN int, err error)
}
type UDPConnState struct {
	sync.RWMutex
	WG       sync.WaitGroup
	Conn     UDPLike
	LastSend time.Time
}
type NAT struct {
	sync.RWMutex
	State   map[IPPort]*UDPConnState
	BufPool *sync.Pool
}

func NewUDPNAT(bufPool *sync.Pool) *NAT {
	return &NAT{
		State:   make(map[IPPort]*UDPConnState),
		BufPool: bufPool,
	}
}

// All net.Addr in this file are *net.UDPAddr
type ListenUDPFn func(network string, laddr *net.UDPAddr) (UDPLike, error)
type HijackDNSFn func(packet []byte, conn net.Conn, wg *sync.WaitGroup)

func L4OverIPv6Checksum(proto uint8, srcIP []byte, dstIP []byte, p []byte) uint16 {
	var pseudoHeader [40]byte
	copy(pseudoHeader[:16], srcIP)
	copy(pseudoHeader[16:32], dstIP)
	binary.BigEndian.PutUint32(pseudoHeader[32:], uint32(len(p)))
	pseudoHeader[39] = proto

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
func AddUDPHeader(buf []byte, srcPort uint16, dstPort uint16) header.UDP {
	udph := header.UDP(buf[:8])
	udph.SetSourcePort(srcPort)
	udph.SetDestinationPort(dstPort)
	udph.SetLength(uint16(len(buf)))
	return udph
}

func writeView(ep stack.LinkWriter, view *buffer.View) (int, tcpip.Error) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 0,
		Payload:            buffer.MakeWithView(view),
	})
	var pktList stack.PacketBufferList
	pktList.PushBack(pkt)
	defer pktList.DecRef()

	return ep.WritePackets(pktList)
}
func mySendUDP6(ep stack.LinkWriter, data []byte, src *syscall.SockaddrInet6, dst IPPort) (int, tcpip.Error) {
	view := buffer.NewViewSize(48 + len(data))
	ref1 := view.AsSlice()
	copy(ref1[48:], data)

	copy(ref1[:8], IPv6HeaderForUDP[:8])
	iph := header.IPv6(ref1[:40])
	iph.SetPayloadLength(uint16(8 + len(data)))
	copy(iph[8:24], src.Addr[:])
	iph.SetDestinationAddress(dst.IP)

	udph := AddUDPHeader(ref1[40:], uint16(src.Port), dst.Port)
	chksum := L4OverIPv6Checksum(17, src.Addr[:], dst.IP.AsSlice(), ref1[40:])
	udph.SetChecksum(chksum)
	return writeView(ep, view)
}
func mySendUDP4(ep stack.LinkWriter, data []byte, src *syscall.SockaddrInet4, dst IPPort) (int, tcpip.Error) {
	view := buffer.NewViewSize(28 + len(data))
	ref1 := view.AsSlice()
	copy(ref1[28:], data)

	copy(ref1[:12], IPv4HeaderForUDP[:12])
	iph := header.IPv4(ref1[:20])
	iph.SetTotalLength(uint16(28 + len(data)))
	copy(iph[12:16], src.Addr[:])
	iph.SetDestinationAddress(dst.IP)
	chksum := 0xffff - uint16(utils.ClearHigh16(utils.Uint16Sum(iph)))
	iph.SetChecksum(chksum)

	udph := AddUDPHeader(ref1[20:], uint16(src.Port), dst.Port)
	chksum = UDP4Checksum(src.Addr[:], dst.IP.AsSlice(), ref1[20:])
	udph.SetChecksum(chksum)
	return writeView(ep, view)
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
	in1:
		for {
			n, _, _, from, err := state.Conn.Recvmsg(buf, nil, 0)
			if err != nil {
				switch utils.ToNumber(err) {
				case syscall.EAGAIN:
					break in1
				default:
					nat.BufPool.Put(buf)
					log.Printf("failed to Recvmsg: %v", err)
					break out1
				}
			}

			var gErr tcpip.Error
			if isIPv6 {
				n, gErr = mySendUDP6(ep, buf[:n], from.(*syscall.SockaddrInet6), dst)
			} else {
				n, gErr = mySendUDP4(ep, buf[:n], from.(*syscall.SockaddrInet4), dst)
			}
			if gErr != nil {
				nat.BufPool.Put(buf)
				log.Printf("failed to WritePackets: %v", gErr)
				break out1
			}
		}
		nat.BufPool.Put(buf)

		if !state.Conn.IsReadable(deadline) {
			log.Printf("wait for readable events: timeout")
			break
		}
	}

	state.WG.Wait()
	nat.Lock()
	delete(nat.State, dst)
	nat.Unlock()

	log.Printf("ForwardInboundUDP() return, dst: %v", dst)
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
		xConn := gonet.NewUDPConn(s, &wq, ep)

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

			state = &UDPConnState{LastSend: time.Now(), Conn: rConn}
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
			var myWG sync.WaitGroup
			readTimer := time.NewTimer(timeout2)
			defer readTimer.Stop()

			waitEntry, readableCh := waiter.NewChannelEntry(waiter.ReadableEvents)
			wq.EventRegister(&waitEntry)
			defer wq.EventUnregister(&waitEntry)

		out1:
			for {
				buf := nat.BufPool.Get().([]byte)
			in1:
				for {
					now1 := time.Now()
					state.Lock()
					state.LastSend = now1
					state.Unlock()

					res, err := ReadFromEP(buf[:], ep)
					if err != nil {
						switch err.(*net.OpError).Err.Error() {
						case "operation would block":
							break in1
						default:
							nat.BufPool.Put(buf)
							log.Printf("failed to read data: %v", err)
							break out1
						}
					}

					if hijack != nil && dst.Port == 53 {
						dataCopy := append([]byte{}, buf[:res.Count]...)
						myWG.Add(1)
						go hijack(dataCopy, xConn, &myWG)
						continue
					}

					_, _, err = state.Conn.WriteMsgUDP(buf[:res.Count], nil, &dst)
					if err != nil {
						nat.BufPool.Put(buf)
						log.Printf("failed to send data: %v", err)
						break out1
					}
				}
				nat.BufPool.Put(buf)

				readTimer.Reset(timeout2)
				select {
				case <-readableCh:
				case <-readTimer.C:
					log.Printf("failed to read data: %v", net.OpError{
						Op:   "read",
						Net:  "udp",
						Addr: &dst,
						Err:  syscall.ETIMEDOUT,
					})
					break out1
				}
			}

			myWG.Wait()

			log.Printf("myWG.Wait() return, reqID: %v", reqID)
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
