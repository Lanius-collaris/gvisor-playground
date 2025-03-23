package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"localhost/aegis/dialers"
	"localhost/aegis/stack"
	"localhost/aegis/utils"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
)

type TLSFragOption struct {
	Size uint16 `json:"size"`
}
type OverwriteOption struct {
	Payload string `json:"payload"` //base64
	MaxTTL  uint8  `json:"maxTTL"`
}
type Config struct {
	MTU       int32           `json:"mtu"`
	Strategy  string          `json:"strategy"`
	TLSFrag   TLSFragOption   `json:"tlsFrag"`
	Overwrite OverwriteOption `json:"overwrite"`
	DoHURL    string
	DoHIP     string
}

func p(e error) {
	if e != nil {
		panic(e)
	}
}
func dialTCP(dstIP tcpip.Address, dstPort uint16) (stack.TCPLike, error) {
	dst := net.TCPAddr{
		IP:   dstIP.AsSlice(),
		Port: int(dstPort),
	}
	tcpConn, err := net.DialTCP("tcp", nil, &dst)
	if err != nil {
		return nil, err
	}
	conn2 := utils.TCPConnToMyTCPConn(tcpConn)
	return &conn2, nil
}
func listenUDP(network string, laddr *net.UDPAddr) (stack.UDPLike, error) {
	udpConn, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}
	conn2 := utils.UDPConnToMyUDPConn(udpConn)
	return &conn2, nil
}
func sendTUN(name string) {
	sock := int(3)
	defer syscall.Close(sock)
	syscall.SetNonblock(sock, true)
	tun, err := utils.OpenTUN(name)
	p(err)
	defer syscall.Close(tun)

	ifInfo, err := net.InterfaceByName(name)
	p(err)
	var msg [4]byte
	binary.NativeEndian.PutUint32(msg[:], uint32(ifInfo.MTU))
	cmsg := utils.GenFDCmsg([]uint32{uint32(tun)})
	err = syscall.Sendmsg(sock, msg[:], cmsg, nil, 0)
	p(err)
}
func demo(targetPid int, tunName string, config *Config) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	p(err)
	defer func() {
		syscall.Close(pair[0])
		syscall.Close(pair[1])
	}()
	syscall.SetNonblock(pair[0], true)

	elfPath, err := os.Executable()
	p(err)
	c1 := exec.Command("/usr/bin/nsenter", "--target", fmt.Sprintf("%d", targetPid), "--user", "--net",
		"--preserve-credentials", "--keep-caps",
		elfPath, "-mode", "sendfd", "-tun", tunName)
	c1.ExtraFiles = []*os.File{os.NewFile(uintptr(pair[1]), "")}
	fmt.Println("starting child...")
	output, err := c1.CombinedOutput()
	if len(output) > 0 {
		fmt.Printf("child's output:\n%s\n", string(output))
	}
	p(err)

	var buf [4]byte
	var cmsgBuf [20]byte
	n, cmsgN, msgFlag, _, err := syscall.Recvmsg(pair[0], buf[:], cmsgBuf[:], 0)
	p(err)
	fmt.Printf("msg: %v\ncmsg: %v\nflag: %d\n", buf[:n], cmsgBuf[:cmsgN], msgFlag)
	tun := int(binary.NativeEndian.Uint32(cmsgBuf[16:]))
	defer syscall.Close(tun)
	mtu := binary.NativeEndian.Uint32(buf[:])

	netStack := stack.NewStack()
	defer netStack.Destroy()

	var tcpfn stack.DialTCPFn
	switch config.Strategy {
	case "tlsfrag":
		tcpfn = func(dstIP tcpip.Address, dstPort uint16) (stack.TCPLike, error) {
			dst := net.TCPAddr{
				IP:   dstIP.AsSlice(),
				Port: int(dstPort),
			}
			tcpConn, err := net.DialTCP("tcp", nil, &dst)
			if err != nil {
				return nil, err
			}
			conn2 := utils.TCPConnToMyTCPConn(tcpConn)
			return &dialers.TLSFragConn{conn2, config.TLSFrag.Size, false}, nil
		}
	case "overwrite":
		payload, err := base64.StdEncoding.DecodeString(config.Overwrite.Payload)
		if err != nil {
			fmt.Printf("decode error: %v, use default payload\n", err)
			payload = []byte(dialers.HTTP1_1Str)
		}
		tcpfn = func(dstIP tcpip.Address, dstPort uint16) (stack.TCPLike, error) {
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

	tcpHandler := stack.NewTCPReqHandler(tcpfn, &bufPool)
	tcpForwarder := tcp.NewForwarder(netStack, 0, 10000, tcpHandler)
	netStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpNAT := stack.NewUDPNAT(&bufPool)
	linkEP, err := stack.NewLinkEP(int32(tun), mtu)
	p(err)
	udpHandler := stack.NewUDPReqHandler(netStack, linkEP, udpNAT, listenUDP, nil, stack.DefaultReadTimeout)
	udpForwarder := udp.NewForwarder(netStack, udpHandler)
	netStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	icmpHack := stack.NewICMPHackTarget(linkEP, &bufPool, stack.DNSTimeout)
	stack.DropICMP(netStack, &icmpHack)

	err = stack.CreateNIC(netStack, 1, linkEP)
	p(err)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	wait1 := <-ch
	fmt.Printf("received %v signal, exiting\n", wait1)
}

func main() {
	var mode string
	flag.StringVar(&mode, "mode", "main", "main or sendfd")
	var tunName string
	flag.StringVar(&tunName, "tun", "tun0", "")
	var pid int
	flag.IntVar(&pid, "target", -1, "target process to get namespaces from")
	var configPath string
	flag.StringVar(&configPath, "config", "config.json", "path to configuration file")
	flag.Parse()

	log.SetFlags(log.Lshortfile)

	switch mode {
	case "main":
		config := Config{
			Strategy: "none",
		}
		data, err := os.ReadFile(configPath)
		if err == nil {
			err = json.Unmarshal(data, &config)
			if err != nil {
				fmt.Printf("decode error: %v\n", err)
			}
		}
		fmt.Printf("config: %v\n", &config)
		demo(pid, tunName, &config)
	case "sendfd":
		sendTUN(tunName)
	default:
		fmt.Printf("unknown mode: %s\n", mode)
	}
}
