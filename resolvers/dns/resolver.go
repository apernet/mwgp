package dns

import (
	"context"
	"fmt"
	"github.com/haruue-net/mwgp"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"time"
)

const resolverName = "dns"

func init() {
	mwgp.UDPAddrResolverCreators[resolverName] = creator
}

func creator(s string) (resolver mwgp.UDPAddrResolver, err error) {
	rand.Seed(time.Now().UnixNano())
	realURL := strings.TrimPrefix(s, resolverName+"+")
	var u *url.URL
	u, err = url.Parse(realURL)
	if err != nil {
		err = fmt.Errorf("cannot parse resolver as url: %s", err.Error())
		return
	}
	switch u.Scheme {
	case "udp":
		resolver = newUDPResolver(u.Hostname(), u.Port())
	default:
		err = fmt.Errorf("unsupported dns protocol: %s", u.Scheme)
	}
	return
}

type udpResolver struct {
	resolver *net.Resolver
}

func newUDPResolver(host, port string) (resolver *udpResolver) {
	resolver = &udpResolver{}
	dialer := &net.Dialer{}
	resolver.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (conn net.Conn, e error) {
			return dialer.DialContext(ctx, "udp", net.JoinHostPort(host, port))
		},
	}
	return
}

func (r *udpResolver) ResolveUDPAddr(ctx context.Context, address string) (addr *net.UDPAddr, err error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return
	}
	ips, err := r.resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		err = fmt.Errorf("cannot resolve host %s: %s", host, err.Error())
		return
	}
	if len(ips) == 0 {
		err = fmt.Errorf("no ip found for %s", host)
		return
	}
	ip := ips[rand.Int()%len(ips)]
	portNumber, err := r.resolver.LookupPort(ctx, "udp", port)
	if err != nil {
		err = fmt.Errorf("cannot resolve port %s: %s", port, err.Error())
		return
	}
	addr = &net.UDPAddr{
		IP:   ip,
		Port: portNumber,
	}
	return
}
