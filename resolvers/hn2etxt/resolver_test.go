package dns

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"net"
	"strconv"
	"testing"
)

const (
	testSecret = "49e47888-652c-45d4-bbb6-f9690b824b82"
)

type fakeNetResolver struct {
}

func (r *fakeNetResolver) LookupTXT(ctx context.Context, name string) (results []string, err error) {
	encrypt := func(plaintext string, secret string) string {
		key := sha256.Sum256([]byte(secret))
		aead, err := chacha20poly1305.New(key[:])
		if err != nil {
			panic(err)
		}
		nonce := make([]byte, aead.NonceSize())
		_, err = rand.Read(nonce)
		if err != nil {
			panic(err)
		}
		ciphertext := aead.Seal(nil, nonce, []byte(plaintext), nil)
		return base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(append(nonce, ciphertext...))
	}

	switch name {
	case "normal.test":
		results = append(results, encrypt("hn2etxt addr=192.0.2.3", testSecret))
	case "mixed.test":
		results = append(results, encrypt("nothn2etxt", testSecret))
		results = append(results, encrypt("hn2etxt without addr", testSecret))
		results = append(results, encrypt("hn2etxt addr=192.0.2.2 time=1600000000", testSecret))
		results = append(results, encrypt("hn2etxt addr=192.0.2.3 time=1600000001", testSecret))
		results = append(results, encrypt("hn2etxt addr=192.0.2.4 time=1600000001", "invalid secret"))
		results = append(results, "v=spf1 include:192.0.2.5 ~all")
	default:
		err = fmt.Errorf("fake resolver: no record found for %s", name)
	}
	return
}

func (r *fakeNetResolver) LookupIP(ctx context.Context, network, host string) (results []net.IP, err error) {
	ip := net.ParseIP(host)
	if ip == nil {
		err = fmt.Errorf("fake resolver: invalid ip: %s", host)
		return
	}
	results = append(results, ip)
	return
}

func (r *fakeNetResolver) LookupPort(ctx context.Context, network, service string) (port int, err error) {
	u64port, err := strconv.ParseInt(service, 10, 16)
	if err != nil {
		err = fmt.Errorf("fake resolver: invalid port %s: %w", service, err)
		return
	}
	port = int(u64port)
	return
}

func TestEtxtResolver_ResolveUDPAddr(t *testing.T) {
	resolver := newResolver("192.0.2.53", "53", testSecret)
	resolver.resolver = &fakeNetResolver{}

	addr, err := resolver.ResolveUDPAddr(context.Background(), "normal.test:2333")
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "192.0.2.3:2333" {
		t.Fatalf("unexpected addr: %s", addr)
	}
	addr, err = resolver.ResolveUDPAddr(context.Background(), "mixed.test:2333")
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "192.0.2.3:2333" {
		t.Fatalf("unexpected addr: %s", addr)
	}
}
