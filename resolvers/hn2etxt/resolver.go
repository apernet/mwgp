package dns

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/haruue-net/mwgp"
	"golang.org/x/crypto/chacha20poly1305"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const resolverName = "hn2etxt"

func init() {
	mwgp.UDPAddrResolverCreators[resolverName] = creator
}

func creator(s string) (resolver mwgp.UDPAddrResolver, err error) {
	rand.Seed(time.Now().UnixNano())
	realURL := strings.TrimPrefix(s, resolverName+"+")
	var u *url.URL
	u, err = url.Parse(realURL)
	if err != nil {
		err = fmt.Errorf("cannot parse resolver as url: %w", err)
		return
	}
	switch u.Scheme {
	case "udp":
		resolver = newResolver(u.Hostname(), u.Port(), u.Query().Get("secret"))
	default:
		err = fmt.Errorf("unsupported dns protocol: %s", u.Scheme)
	}
	return
}

type netResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupPort(ctx context.Context, network, service string) (port int, err error)
}

type etxtResolver struct {
	resolver netResolver
	aead     cipher.AEAD
}

func newResolver(host, port, secret string) (resolver *etxtResolver) {
	key := sha256.Sum256([]byte(secret))
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	resolver = &etxtResolver{
		aead: aead,
	}
	dialer := &net.Dialer{}
	resolver.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (conn net.Conn, e error) {
			return dialer.DialContext(ctx, "udp", net.JoinHostPort(host, port))
		},
	}
	return
}

type etxtRecord struct {
	addr string
	time time.Time
}

func (r *etxtRecord) parse(s string) (err error) {
	tokens := strings.Split(s, " ")
	m := map[string]string{}
	for _, token := range tokens {
		kv := strings.SplitN(token, "=", 2)
		var key, value string
		if len(kv) >= 1 {
			key = kv[0]
		}
		if len(kv) >= 2 {
			value = kv[1]
		}
		if key != "" {
			m[key] = value
		}
	}
	if _, ok := m["hn2etxt"]; !ok {
		err = fmt.Errorf("not a hn2etxt record")
		return
	}
	if addr, ok := m["addr"]; ok {
		r.addr = addr
	} else {
		err = fmt.Errorf("no addr found in hn2etxt record")
		return
	}
	if timeStr, ok := m["time"]; ok {
		ts, terr := strconv.ParseInt(timeStr, 10, 64)
		if terr == nil {
			r.time = time.Unix(ts, 0)
		}
		// ignore time parse error
	}
	return
}

func (r *etxtResolver) ResolveUDPAddr(ctx context.Context, address string) (addr *net.UDPAddr, err error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return
	}
	txts, err := r.resolver.LookupTXT(ctx, host)
	if err != nil {
		err = fmt.Errorf("cannot resolve txt record for %s: %s", host, err.Error())
		return
	}
	if len(txts) == 0 {
		err = fmt.Errorf("no TXT record found for %s", host)
		return
	}
	var lastErr error
	var latestRecord *etxtRecord
	for _, txtRecord := range txts {
		s, err := r.tryDecrypt(txtRecord)
		if err != nil {
			lastErr = err
			continue
		}
		var record etxtRecord
		err = record.parse(s)
		if err != nil {
			lastErr = err
			continue
		}
		if latestRecord == nil || record.time.After(latestRecord.time) {
			latestRecord = &record
		}
	}
	if latestRecord == nil {
		if lastErr != nil {
			err = lastErr
		} else {
			err = fmt.Errorf("no valid hn2etxt record found for %s", host)
		}
		return
	}
	addr, err = r.resolveHostPort(ctx, latestRecord.addr, port)
	if err != nil {
		err = fmt.Errorf("cannot resolve addr %s:%s in latest hn2etxt record: %w", latestRecord.addr, port, err)
	}
	return
}

func (r *etxtResolver) tryDecrypt(record string) (result string, err error) {
	bs, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(record)
	if err != nil {
		return
	}
	if len(bs) < r.aead.NonceSize() {
		err = fmt.Errorf("invalid record length")
		return
	}
	nonce, ciphertext := bs[:r.aead.NonceSize()], bs[r.aead.NonceSize():]
	plaintext, err := r.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return
	}
	result = string(plaintext)
	return
}

func (r *etxtResolver) resolveHostPort(ctx context.Context, host, port string) (addr *net.UDPAddr, err error) {
	ips, err := r.resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		err = fmt.Errorf("cannot resolve host %s: %w", host, err)
		return
	}
	if len(ips) == 0 {
		err = fmt.Errorf("no ip found for %s", host)
		return
	}
	ip := ips[rand.Int()%len(ips)]
	portNumber, err := r.resolver.LookupPort(ctx, "udp", port)
	if err != nil {
		err = fmt.Errorf("cannot resolve port %s: %w", port, err)
		return
	}
	addr = &net.UDPAddr{
		IP:   ip,
		Port: portNumber,
	}
	return
}
