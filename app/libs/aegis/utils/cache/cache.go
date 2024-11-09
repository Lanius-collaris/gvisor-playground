package cache

import (
	sieve "github.com/opencoff/go-sieve"
	"net/netip"
	"time"
)

const (
	defaultCapacity = 512
	defaultStaleTtl = 60 // in seconds
)

type result struct {
	expiration int64
	hops       uint8
}

var ipv4Cache = sieve.New[[4]byte, result](defaultCapacity)
var ipv6Cache = sieve.New[[8]byte, result](defaultCapacity)

func GetHops(ip netip.Addr) (uint8, bool) {
	var (
		r  result
		ok bool
	)
	if ip.Is6() {
		var key [8]byte
		t := ip.As16()
		copy(key[:], t[:8])
		r, ok = ipv6Cache.Get(key)
	} else {
		r, ok = ipv4Cache.Get(ip.As4())
	}
	if !ok || time.Now().Unix() > r.expiration {
		return 0, false
	}
	return r.hops, true
}

func PutHops(ip netip.Addr, hops uint8) {
	v := result{
		expiration: time.Now().Unix() + defaultStaleTtl,
		hops:       hops,
	}
	if ip.Is6() {
		var key [8]byte
		t := ip.As16()
		copy(key[:], t[:8])
		ipv6Cache.Add(key, v)
	} else {
		ipv4Cache.Add(ip.As4(), v)
	}
}

func ResetCache() {
	ipv4Cache.Purge()
	ipv6Cache.Purge()
}
