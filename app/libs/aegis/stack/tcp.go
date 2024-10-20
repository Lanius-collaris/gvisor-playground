package stack

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
	"localhost/aegis/utils"
	"log"
	"net"
	"sync"
	"syscall"
)

type TCPLike interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
}

type DialTCPFn func(dstIP tcpip.Address, dstPort uint16) (TCPLike, error)

func TCPForward(input TCPLike, output TCPLike) {
	defer func() {
		output.CloseWrite()
		input.CloseRead()
	}()

	var buf [65536]byte
	for {
		n, err := input.Read(buf[:])
		if err != nil {
			break
		}
		_, err = output.Write(buf[:n])
		if err != nil {
			break
		}
	}
}

func NewTCPReqHandler(fn DialTCPFn) func(*tcp.ForwarderRequest) {
	h := func(req *tcp.ForwarderRequest) {
		id := req.ID()
		go func() {
			rConn, err := fn(id.LocalAddress, id.LocalPort)
			if err != nil {
				if utils.ToNumber(err) == syscall.ECONNREFUSED {
					req.Complete(true)
				} else {
					req.Complete(false)
				}
				return
			}
			defer rConn.Close()

			var wq waiter.Queue
			ep, gErr := req.CreateEndpoint(&wq)
			if gErr != nil {
				req.Complete(false)
				log.Printf("failed to create endpoint: %v", gErr)
				return
			}
			req.Complete(false)
			xConn := gonet.NewTCPConn(&wq, ep)
			defer xConn.Close()

			var myWG sync.WaitGroup
			myWG.Add(1)
			go func() {
				defer myWG.Done()
				TCPForward(rConn, xConn)
			}()
			TCPForward(xConn, rConn)
			myWG.Wait()
		}()
	}
	return h
}
