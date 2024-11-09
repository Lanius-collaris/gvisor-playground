package android_interface

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"localhost/aegis/stack"
	"net"
	"net/http"
	"sync"
)

type DNSProxy struct {
	Client *http.Client
	URL    string
}
type DialContextFn func(ctx context.Context, network, addr string) (net.Conn, error)

func NewDNSProxy(dialFn DialContextFn, DoHURL string, ip string) DNSProxy {
	tran := http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			return dialFn(ctx, network, net.JoinHostPort(ip, port))
		},
		ForceAttemptHTTP2: true,
	}
	return DNSProxy{
		&http.Client{Transport: &tran},
		DoHURL,
	}
}
func (proxy *DNSProxy) Hijack(packet []byte, conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()

	id := binary.BigEndian.Uint16(packet)
	//use a DNS ID of 0
	binary.BigEndian.PutUint16(packet, 0)
	bodyReader := bytes.NewReader(packet)

	ctx, cancel := context.WithTimeout(context.Background(), stack.DNSTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", proxy.URL, bodyReader)
	if err != nil {
		return
	}
	req.Header.Set("user-agent", "")
	req.Header.Set("accept", "application/dns-message")
	req.Header.Set("content-type", "application/dns-message")

	res, err := proxy.Client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return
	}
	var buf [1232]byte
	n, err := io.ReadAtLeast(res.Body, buf[:], 16)
	if err != nil {
		return
	}

	binary.BigEndian.PutUint16(buf[:], id)
	conn.Write(buf[:n])
}
