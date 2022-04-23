package mwgp

import (
	"log"
	"net"
	"time"
)

const (
	kMaxPeersCount = 1 << 8
	kMTU           = 1500
)

type ServerConfigPeer struct {
	ID        int    `json:"id"`
	ForwardTo string `json:"forward_to"`
}

type ServerConfig struct {
	Listen  string             `json:"listen"`
	Timeout int                `json:"timeout"`
	Peers   []ServerConfigPeer `json:"peers"`
}

type serverPeer struct {
	serverAddr *net.UDPAddr
}

type Server struct {
	listen  *net.UDPAddr
	peers   [kMaxPeersCount]*serverPeer
	fwTable *forwardTable
}

func NewServerWithConfig(config *ServerConfig) (outServer *Server, err error) {
	listenAddr, rerr := net.ResolveUDPAddr("udp", config.Listen)
	if rerr != nil {
		err = ErrResolveAddr{Type: "listen", Addr: config.Listen, Cause: rerr}
		return
	}
	server := Server{
		listen:  listenAddr,
		fwTable: newForwardTable(time.Duration(config.Timeout) * time.Second),
	}
	for _, peer := range config.Peers {
		if peer.ID < 0 || peer.ID >= kMaxPeersCount {
			err = ErrInvalidPeerID{ID: peer.ID}
			return
		}
		serverAddr, rerr := net.ResolveUDPAddr("udp", peer.ForwardTo)
		if rerr != nil {
			err = ErrResolveAddr{Type: "forward_to", Addr: peer.ForwardTo, Cause: rerr}
			return
		}
		server.peers[peer.ID] = &serverPeer{
			serverAddr: serverAddr,
		}
	}
	outServer = &server
	return
}

func (s *Server) Start() (err error) {
	var conn *net.UDPConn
	conn, err = net.ListenUDP("udp", s.listen)
	if err != nil {
		return
	}
	defer conn.Close()
	for {
		var recvBuffer [kMTU]byte
		readLen, srcAddr, err := conn.ReadFromUDP(recvBuffer[:])
		if err != nil {
			log.Printf("[error] failed when read udp from main conn: %s", err.Error())
			break
		}
		packet := recvBuffer[:readLen]
		demangledPacket, peerID, err := s.demanglePacket(packet)
		if err != nil {
			log.Printf("[warn] failed to unmangle packet from %s: %s", srcAddr, err)
			continue
		}
		peer := s.peers[peerID]
		if peer == nil {
			log.Printf("[warn] received packet from %s with unknown peer id %d", srcAddr, peerID)
			continue
		}
		err = s.fwTable.forwardPacket(srcAddr, peer.serverAddr, conn, demangledPacket)
		if err != nil {
			log.Printf("[error] failed to process packet forward from %s to %s: %s", srcAddr, peer.serverAddr, err.Error())
		}
	}
	return
}

func (s *Server) demanglePacket(packet []byte) (outPacket []byte, peerID int, err error) {
	if len(packet) < 4 {
		err = ErrPacketTooShort{Length: len(packet)}
	}
	peerID = int(packet[1])
	packet[1] = 0
	outPacket = packet
	return
}
