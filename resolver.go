package mwgp

import (
	"context"
	"fmt"
	"net"
	"strings"
)

type UDPAddrResolver interface {
	ResolveUDPAddr(ctx context.Context, address string) (addr *net.UDPAddr, err error)
}

type UDPAddrResolverCreator = func(url string) (resolver UDPAddrResolver, err error)

var UDPAddrResolverCreators = map[string]UDPAddrResolverCreator{} // Type => Creator

type defaultUDPAddrResolver struct{}

func (d *defaultUDPAddrResolver) ResolveUDPAddr(ctx context.Context, address string) (addr *net.UDPAddr, err error) {
	return net.ResolveUDPAddr("udp", address)
}

func newUDPAddrResolver(url string) (resolver UDPAddrResolver, err error) {
	if url == "" {
		resolver = &defaultUDPAddrResolver{}
		return
	}
	resolverType := strings.SplitN(url, "+", 2)[0]
	if creator, ok := UDPAddrResolverCreators[resolverType]; ok {
		resolver, err = creator(url)
		return
	}
	err = fmt.Errorf("unknown resolver type: %s", resolverType)
	return
}
