package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"localhost/aegis/stack"
	"localhost/aegis/utils"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

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
	return net.DialTCP("tcp", nil, &dst)
}
func listenUDP(network string, laddr *net.UDPAddr) (net.PacketConn, error) {
	return net.ListenUDP(network, laddr)
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
func demo(targetPid int, tunName string) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	p(err)
	defer func() {
		syscall.Close(pair[0])
		syscall.Close(pair[1])
	}()
	syscall.SetNonblock(pair[0], true)

	elfPath, err := os.Executable()
	p(err)
	c1 := exec.Command("/usr/bin/nsenter", "--target", fmt.Sprintf("%d", targetPid), "--user", "--net", "--preserve-credentials",
		elfPath, "-mode", "sendfd", "-tun", tunName)
	c1.ExtraFiles = []*os.File{os.NewFile(uintptr(pair[1]), "")}
	fmt.Println("starting child...")
	output, err := c1.CombinedOutput()
	p(err)
	fmt.Printf("child's output:\n%s\n", string(output))

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

	tcpHandler := stack.NewTCPReqHandler(dialTCP)
	tcpForwarder := tcp.NewForwarder(netStack, 0, 64, tcpHandler)
	netStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpNAT := stack.NewUDPNAT()
	linkEP, err := stack.NewLinkEP(int32(tun), mtu)
	p(err)
	udpHandler := stack.NewUDPReqHandler(netStack,linkEP, udpNAT, listenUDP, nil, stack.DefaultReadTimeout)
	udpForwarder := udp.NewForwarder(netStack, udpHandler)
	netStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	err = stack.CreateNIC(netStack, 1, linkEP)
	p(err)

	for {
		time.Sleep(time.Hour)
	}
}

func main() {
	var mode string
	flag.StringVar(&mode, "mode", "main", "main or sendfd")
	var tunName string
	flag.StringVar(&tunName, "tun", "tun0", "")
	var pid int
	flag.IntVar(&pid, "target", -1, "target process to get namespaces from")
	flag.Parse()

	log.SetFlags(log.Lshortfile)

	switch mode {
	case "main":
		demo(pid, tunName)
	case "sendfd":
		sendTUN(tunName)
	default:
		fmt.Printf("unknown mode: %s\n", mode)
	}
}
