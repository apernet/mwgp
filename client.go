package mwgp

import (
	"log"
	"net"
	"time"
)

type ClientConfig struct {
	Server  string `json:"server"`
	ID      int    `json:"id"`
	Listen  string `json:"listen"`
	Timeout int    `json:"timeout"`
}

type Client struct {
	id         int
	serverAddr *net.UDPAddr
	listenAddr *net.UDPAddr
	fwTable    *forwardTable
}

func NewClientWithConfig(config *ClientConfig) (outClient *Client, err error) {
	serverAddr, rerr := net.ResolveUDPAddr("udp", config.Server)
	if rerr != nil {
		err = ErrResolveAddr{Type: "server", Addr: config.Server, Cause: rerr}
		return
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
	client := Client{
		id:         config.ID,
		serverAddr: serverAddr,
		listenAddr: listenAddr,
		fwTable:    newForwardTable(time.Duration(config.Timeout) * time.Second),
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
	for {
		var recvBuffer [kMTU]byte
		readLen, srcAddr, err := conn.ReadFromUDP(recvBuffer[:])
		packet := recvBuffer[:readLen]
		mangledPacket, err := c.manglePacket(packet)
		if err != nil {
			log.Printf("[warn] failed to mangle packet from %s: %s", srcAddr, err.Error())
			continue
		}
		err = c.fwTable.forwardPacket(srcAddr, c.serverAddr, conn, mangledPacket)
		if err != nil {
			log.Printf("[error] failed to process packet forward from %s to %s: %s", srcAddr, c.serverAddr, err.Error())
		}
	}
}

func (c *Client) manglePacket(packet []byte) (outPacket []byte, err error) {
	if len(packet) < 4 {
		err = ErrPacketTooShort{Length: len(packet)}
	}
	packet[1] = byte(c.id)
	outPacket = packet
	return
}
