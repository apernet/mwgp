package mwgp

import (
	"context"
	"log"
	"net"
	"time"
)

type ClientConfig struct {
	Server  string `json:"server"`
	ID      int    `json:"id"`
	Listen  string `json:"listen"`
	Timeout int    `json:"timeout"`
	XORKey  string `json:"xor_key"`
	DNS     string `json:"dns"`
}

type Client struct {
	id         int
	server     string
	listenAddr *net.UDPAddr
	fwTable    *forwardTable
	xorKey     []byte
}

func NewClientWithConfig(config *ClientConfig) (outClient *Client, err error) {
	if config.DNS != "" {
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", config.DNS)
			},
		}
	}
	listenAddr, rerr := net.ResolveUDPAddr("udp", config.Listen)
	if rerr != nil {
		err = ErrResolveAddr{Type: "listen", Addr: config.Listen, Cause: rerr}
		return
	}
	if config.ID < 0 || config.ID >= kMaxPeersCount {
		err = ErrInvalidPeerID{ID: config.ID}
		return
	}
	var xorKeyBs []byte
	if len(config.XORKey) > 0 {
		xorKeyBs = []byte(config.XORKey)
	}
	client := Client{
		id:         config.ID,
		server:     config.Server,
		listenAddr: listenAddr,
		fwTable:    newForwardTable(time.Duration(config.Timeout) * time.Second),
		xorKey:     xorKeyBs,
	}
	outClient = &client
	return
}

func (c *Client) Start() (err error) {
	var conn *net.UDPConn
	conn, err = net.ListenUDP("udp", c.listenAddr)
	if err != nil {
		return
	}
	defer conn.Close()

	var serverAddr *net.UDPAddr

	go func() {
		for {
			sa, rerr := net.ResolveUDPAddr("udp", c.server)
			if rerr != nil {
				log.Printf("[error] failed to resolve server addr %s: %s, retry in 10 seconds", c.server, rerr.Error())
				time.Sleep(10 * time.Second)
				continue
			}
			serverAddr = sa
			time.Sleep(5 * time.Minute)
		}
	}()

	for {
		var recvBuffer [kMTU]byte
		readLen, srcAddr, err := conn.ReadFromUDP(recvBuffer[:])
		if err != nil {
			log.Printf("[error] failed when read udp from main conn: %s", err.Error())
			break
		}
		packet := recvBuffer[:readLen]
		mangledPacket, err := c.manglePacket(packet)
		if err != nil {
			log.Printf("[warn] failed to mangle packet from %s: %s", srcAddr, err.Error())
			continue
		}
		if serverAddr == nil {
			// drop silently
			continue
		}
		err = c.fwTable.forwardPacket(srcAddr, serverAddr, conn, mangledPacket)
		if err != nil {
			log.Printf("[error] failed to process packet forward from %s to %s: %s", srcAddr, serverAddr, err.Error())
		}
	}
	return
}

func (c *Client) manglePacket(packet []byte) (outPacket []byte, err error) {
	if len(packet) < 4 {
		err = ErrPacketTooShort{Length: len(packet)}
	}
	packet[1] = byte(c.id)
	if c.xorKey != nil {
		for i := 0; i < len(packet); i++ {
			packet[i] ^= c.xorKey[i%len(c.xorKey)]
		}
	}
	outPacket = packet
	return
}
