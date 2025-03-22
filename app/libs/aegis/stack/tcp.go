package stack

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
	"localhost/aegis/utils"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
)

type TCPLike interface {
	net.Conn
	IsReadable(deadline time.Time) bool
	Recvmsg(buf []byte, cmsgBuf []byte, flags int) (n, cmsgLen int, recvflags int, from syscall.Sockaddr, err error)
	GetsockoptInt(level int, opt int) (int, error)
	CloseRead() error
	CloseWrite() error
}

type DialTCPFn func(dstIP tcpip.Address, dstPort uint16) (TCPLike, error)

func IsConnected(state uint32) bool {
	t1 := tcp.EndpointState(state)
	switch t1 {
	case tcp.StateEstablished, tcp.StateFinWait1, tcp.StateFinWait2, tcp.StateTimeWait, tcp.StateCloseWait, tcp.StateLastAck, tcp.StateClosing:
		return true
	default:
		return false
	}
}
func ForwardInboundTCP(input TCPLike, output tcpip.Endpoint, writableCh <-chan struct{}, bufPool *sync.Pool) {
	sendRST := false
	defer func(sendRST *bool) {
		if *sendRST {
			output.Abort()
		} else {
			output.Shutdown(tcpip.ShutdownWrite)
		}
		input.CloseRead()
	}(&sendRST)

out1:
	for {
		buf := bufPool.Get().([]byte)
	in_data:
		for {
			n, _, _, _, err := input.Recvmsg(buf, nil, 0)
			if err != nil {
				num1 := utils.ToNumber(err)
				switch num1 {
				case syscall.EAGAIN:
					break in_data
				default:
					if num1 == syscall.ECONNRESET {
						sendRST = true
					}
					bufPool.Put(buf)
					log.Printf("TCPLike error: %v", err)
					break out1
				}
			}

			_, err = WriteToEP(buf[:n], tcpip.WriteOptions{}, output, writableCh)
			if err != nil {
				bufPool.Put(buf)
				log.Printf("TCP endpoint error: %v", err)
				break out1
			}
		}
		bufPool.Put(buf)

		input.IsReadable(time.Now().Add(2400 * time.Hour))
	}
}
func ForwardOutboundTCP(input tcpip.Endpoint, readableCh <-chan struct{}, output TCPLike, bufPool *sync.Pool) {
	defer func() {
		output.CloseWrite()
		if IsConnected(input.State()) {
			input.Shutdown(tcpip.ShutdownRead)
		}
	}()

out1:
	for {
		buf := bufPool.Get().([]byte)
	in_data:
		for {
			res, err := ReadFromEP(buf, input)
			if err != nil {
				switch err.(*net.OpError).Err.Error() {
				case "operation would block":
					break in_data
				default:
					bufPool.Put(buf)
					log.Printf("TCP endpoint error: %v", err)
					break out1
				}
			}

			_, err = output.Write(buf[:res.Count])
			if err != nil {
				bufPool.Put(buf)
				log.Printf("TCPLike error: %v", err)
				break out1
			}
		}
		bufPool.Put(buf)

		<-readableCh
	}
}

func NewTCPReqHandler(fn DialTCPFn, bufPool *sync.Pool) func(*tcp.ForwarderRequest) {
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
			defer ep.Close()

			readEntry, readableCh := waiter.NewChannelEntry(waiter.ReadableEvents)
			wq.EventRegister(&readEntry)
			defer wq.EventUnregister(&readEntry)
			writeEntry, writableCh := waiter.NewChannelEntry(waiter.WritableEvents)
			wq.EventRegister(&writeEntry)
			defer wq.EventUnregister(&writeEntry)

			var myWG sync.WaitGroup
			myWG.Add(1)
			go func() {
				defer myWG.Done()
				ForwardInboundTCP(rConn, ep, writableCh, bufPool)

				log.Printf("ForwardInboundTCP() return, reqID: %v", id)
			}()
			ForwardOutboundTCP(ep, readableCh, rConn, bufPool)
			myWG.Wait()

			log.Printf("myWG.Wait() return, reqID: %v", id)
		}()
	}
	return h
}
