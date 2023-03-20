package mwgp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.zx2c4.com/wireguard/device"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Peer struct {
	// the index the client told us whom CLIENT is
	// in MessageInitiation.Sender (client -> us, register)
	// in MessageResponse.Receiver (us -> client, translate)
	// in MessageCookieReply.Receiver (us -> client, translate)
	// in MessageTransport(s->c).Receiver (us -> client, translate)
	clientOriginIndex uint32

	// the index we told server whom CLIENT is
	// in MessageInitiation.Sender (us -> server, translate)
	// in MessageResponse.Receiver (server -> us, match)
	// in MessageCookieReply.Receiver (server -> us, match)
	// in MessageTransport(s->c).Receiver (server -> us, match)
	clientProxyIndex uint32

	// the index the server told us whom SERVER is
	// in MessageResponse.Sender (server -> us, register)
	// in MessageTransport(c->s).Receiver (us -> server, translate)
	serverOriginIndex uint32

	// the index we told client whom SERVER is
	// in MessageResponse.Sender (us -> client, translate)
	// in MessageTransport(c->s).Receiver (client -> us, match)
	serverProxyIndex uint32

	// the cookie generator initialized with the server public key
	// used to generate mac{1,2} for MessageInitialize(c->s)
	clientCookieGenerator device.CookieGenerator
	clientPublicKey       NoisePublicKey

	// the cookie generator initialized with the client public key
	// used to generate mac{1,2} for MessageResponse(s->c)
	serverCookieGenerator device.CookieGenerator
	serverPublicKey       NoisePublicKey

	clientDestination *net.UDPAddr
	serverDestination *net.UDPAddr
	lastActive        atomic.Value // time.Time

	clientSourceValidateLevel int
	serverSourceValidateLevel int

	obfuscateEnabled bool
}

func (p *Peer) IsServerReplied() bool {
	return p.serverProxyIndex != 0
}

type WireGuardIndexTranslationTable struct {
	// client <-> us
	clientConn            *net.UDPConn
	ClientListen          *net.UDPAddr
	ClientReadFromUDPFunc func(conn *net.UDPConn, packet *Packet) (err error)
	ClientWriteToUDPFunc  func(conn *net.UDPConn, packet *Packet) (err error)
	clientReadChan        chan *Packet
	clientWriteChan       chan *Packet

	// us <-> server
	serverConn            *net.UDPConn
	ServerListen          *net.UDPAddr
	ServerReadFromUDPFunc func(conn *net.UDPConn, packet *Packet) (err error)
	ServerWriteToUDPFunc  func(conn *net.UDPConn, packet *Packet) (err error)
	serverReadChan        chan *Packet
	serverWriteChan       chan *Packet

	Timeout         time.Duration
	ExtractPeerFunc func(msg *device.MessageInitiation) (fi *ServerConfigPeer, err error)
	CacheJar        WGITCacheJar

	// clientProxyIndex -> Peer
	clientMap map[uint32]*Peer

	// serverProxyIndex -> Peer
	serverMap map[uint32]*Peer

	mapLock    sync.RWMutex
	expireChan <-chan time.Time
	packetPool sync.Pool

	// UpdateAllServerDestinationChan is used to set all server address for mwgp-client (in case of DNS update).
	// this channel is not intended to be used by mwgp-server.
	UpdateAllServerDestinationChan chan *net.UDPAddr

	// MaxPacketSize is the maximum size of a WireGuard packet.
	//
	// We use the default value of 65536, which is the maximum possible size of a UDP packet.
	//
	// However, in most cases, 1500 is sufficient because WireGuard will only send
	// large UDP packets when you configure a large MTU on the WireGuard interface.
	//
	// If you are running mwgp on a server with limited memory, you can adjust this to
	// reduce memory consumption.
	MaxPacketSize uint
}

func defaultReadFromUDPFunc(conn *net.UDPConn, packet *Packet) (err error) {
	packet.Length, packet.Source, err = conn.ReadFromUDP(packet.Data[:])
	if err != nil {
		return
	}
	return
}

func defaultWriteToUDPFunc(conn *net.UDPConn, packet *Packet) (err error) {
	_, err = conn.WriteToUDP(packet.Slice(), packet.Destination)
	if err != nil {
		return
	}
	return
}

func NewWireGuardIndexTranslationTable() (table *WireGuardIndexTranslationTable) {
	table = &WireGuardIndexTranslationTable{
		ClientReadFromUDPFunc:          defaultReadFromUDPFunc,
		ServerReadFromUDPFunc:          defaultReadFromUDPFunc,
		ClientWriteToUDPFunc:           defaultWriteToUDPFunc,
		ServerWriteToUDPFunc:           defaultWriteToUDPFunc,
		clientReadChan:                 make(chan *Packet, 64),
		clientWriteChan:                make(chan *Packet, 64),
		serverReadChan:                 make(chan *Packet, 64),
		serverWriteChan:                make(chan *Packet, 64),
		Timeout:                        60 * time.Second,
		clientMap:                      make(map[uint32]*Peer),
		serverMap:                      make(map[uint32]*Peer),
		UpdateAllServerDestinationChan: make(chan *net.UDPAddr),
		MaxPacketSize:                  defaultMaxPacketSize,
	}
	table.packetPool.New = func() interface{} {
		return &Packet{
			Data: make([]byte, table.MaxPacketSize),
		}
	}
	return
}

func (t *WireGuardIndexTranslationTable) Serve() (err error) {
	cerr := t.CacheJar.LoadLocked(t.serverMap, t.clientMap)
	if cerr != nil {
		log.Printf("[warn] forward table cache not loaded: %s\n", cerr.Error())
	}

	t.clientConn, err = net.ListenUDP("udp", t.ClientListen)
	if err != nil {
		err = fmt.Errorf("failed to listen on client addr %s: %w", t.ClientListen, err)
		return
	}
	t.serverConn, err = net.ListenUDP("udp", t.ServerListen)
	if err != nil {
		err = fmt.Errorf("failed to listen on server addr %s: %w", t.ServerListen, err)
		return
	}
	t.expireChan = time.Tick(t.Timeout)
	go t.writeLoop()
	go t.serverReadLoop()
	go t.clientReadLoop()
	t.mainLoop()
	return
}

func (t *WireGuardIndexTranslationTable) clientReadLoop() {
	for {
		packet := t.obtainPacket()
		err := t.ClientReadFromUDPFunc(t.clientConn, packet)
		if err != nil {
			log.Printf("[error] failed to read from client conn: %s\n", err.Error())
			t.recyclePacket(packet)
			continue
		}
		t.clientReadChan <- packet
	}
}

func (t *WireGuardIndexTranslationTable) serverReadLoop() {
	for {
		packet := t.obtainPacket()
		err := t.ServerReadFromUDPFunc(t.serverConn, packet)
		if err != nil {
			log.Printf("[error] failed to read from server conn: %s\n", err.Error())
			t.recyclePacket(packet)
			continue
		}
		t.serverReadChan <- packet
	}
}

func (t *WireGuardIndexTranslationTable) writeLoop() {
	for {
		select {
		case packet := <-t.clientWriteChan:
			err := t.ClientWriteToUDPFunc(t.clientConn, packet)
			if err != nil {
				log.Printf("[error] failed to write to client conn dest=%s: %s\n", packet.Destination.String(), err.Error())
			}
			t.recyclePacket(packet)
		case packet := <-t.serverWriteChan:
			err := t.ServerWriteToUDPFunc(t.serverConn, packet)
			if err != nil {
				log.Printf("[error] failed to write to server conn dest=%s: %s\n", packet.Destination.String(), err.Error())
			}
			t.recyclePacket(packet)
		}
	}
}

func (t *WireGuardIndexTranslationTable) mainLoop() {
	for {
		select {
		case packet := <-t.clientReadChan:
			if packet.MessageType() == device.MessageTransportType {
				t.handleClientPacket(packet)
			} else {
				go t.handleClientPacket(packet)
			}
		case packet := <-t.serverReadChan:
			if packet.MessageType() == device.MessageTransportType {
				t.handleServerPacket(packet)
			} else {
				go t.handleServerPacket(packet)
			}
		case current := <-t.expireChan:
			t.handlePeersExpireCheck(current)
		case newServerAddr := <-t.UpdateAllServerDestinationChan:
			t.handleAllServerDestinationUpdate(newServerAddr)
		}
	}
}

func (t *WireGuardIndexTranslationTable) handleClientPacket(packet *Packet) {
	packetForwarded := false
	defer func() {
		if !packetForwarded {
			t.recyclePacket(packet)
		}
	}()

	var err error
	var peer *Peer
	switch packet.MessageType() {
	case device.MessageInitiationType:
		var msg device.MessageInitiation
		reader := bytes.NewReader(packet.Slice())
		err = binary.Read(reader, binary.LittleEndian, &msg)
		if err != nil {
			break
		}
		peer, err = t.processClientMessageInitiation(packet.Source, &msg)
		if err != nil {
			break
		}

		// for mwgp-server only, mwgp-client won't match this since its client would be official WireGuard
		if packet.Flags&PacketFlagDeobfuscatedAfterReceived != 0 {
			peer.obfuscateEnabled = true
		}
	case device.MessageTransportType:
		peer, err = t.processMessageTransport(packet, false)
	default:
		err = fmt.Errorf("unexcepted message type %d", packet.MessageType())
	}
	if err != nil {
		log.Printf("[info] failed to handle type %d packet from client %s: %s\n", packet.MessageType(), packet.Source.String(), err.Error())
		return
	}
	if peer == nil {
		log.Panicf("[fatal] err == nil && peer == nil, there must be a bug in the code\n")
		return
	}
	switch packet.MessageType() {
	case device.MessageInitiationType:
		if peer.clientOriginIndex != peer.clientProxyIndex {
			err = packet.SetSenderIndex(peer.clientProxyIndex)
			packet.FixMACs(&peer.clientCookieGenerator)
		}
	case device.MessageTransportType:
		err = packet.SetReceiverIndex(peer.serverOriginIndex)
	}
	if err != nil {
		log.Printf("[error] failed to patch type %d packet from client %s: %s\n", packet.MessageType(), packet.Source.String(), err.Error())
		return
	}

	packet.Destination = peer.serverDestination
	t.serverWriteChan <- packet
	packetForwarded = true
}

func (t *WireGuardIndexTranslationTable) handleServerPacket(packet *Packet) {
	packetForwarded := false
	defer func() {
		if !packetForwarded {
			t.recyclePacket(packet)
		}
	}()

	var err error
	var peer *Peer
	switch packet.MessageType() {
	case device.MessageResponseType:
		var msg device.MessageResponse
		reader := bytes.NewReader(packet.Slice())
		err = binary.Read(reader, binary.LittleEndian, &msg)
		if err != nil {
			break
		}
		peer, err = t.processServerMessageResponse(packet.Source, &msg)
		if err != nil {
			break
		}
	case device.MessageCookieReplyType:
		var msg device.MessageCookieReply
		reader := bytes.NewReader(packet.Slice())
		err = binary.Read(reader, binary.LittleEndian, &msg)
		if err != nil {
			break
		}
		peer, err = t.processServerMessageCookieReply(packet.Source, &msg)
		if err != nil {
			break
		}
		// still pass-through to client to for the MessageInitiation resending
	case device.MessageTransportType:
		peer, err = t.processMessageTransport(packet, true)
	default:
		err = fmt.Errorf("unexcepted message type %d", packet.MessageType())
	}
	if err != nil {
		log.Printf("[info] failed to handle type %d packet from server %s: %s\n", packet.MessageType(), packet.Source.String(), err.Error())
		return
	}
	if peer == nil {
		log.Panicf("[fatal] err == nil && peer == nil, there must be a bug in the code\n")
		return
	}
	switch packet.MessageType() {
	case device.MessageResponseType:
		if peer.serverOriginIndex != peer.serverProxyIndex || peer.clientOriginIndex != peer.clientProxyIndex {
			err = packet.SetSenderIndex(peer.serverProxyIndex)
			if err != nil {
				break
			}
			err = packet.SetReceiverIndex(peer.clientOriginIndex)
			if err != nil {
				break
			}
			packet.FixMACs(&peer.serverCookieGenerator)
		}
	case device.MessageCookieReplyType:
		fallthrough
	case device.MessageTransportType:
		err = packet.SetReceiverIndex(peer.clientOriginIndex)
	}
	if err != nil {
		log.Printf("[error] failed to patch type %d packet from server %s: %s\n", packet.MessageType(), packet.Source.String(), err.Error())
		return
	}

	// for mwgp-server only
	if peer.obfuscateEnabled {
		packet.Flags |= PacketFlagObfuscateBeforeSend
	}

	packet.Destination = peer.clientDestination
	t.clientWriteChan <- packet
	packetForwarded = true
}

func (t *WireGuardIndexTranslationTable) processClientMessageInitiation(src *net.UDPAddr, msg *device.MessageInitiation) (peer *Peer, err error) {
	// the MessageInitiation is the only message we can decrypt.
	sp, err := t.ExtractPeerFunc(msg)
	if err != nil {
		return
	}
	if sp == nil {
		log.Panicf("[fatal] ExtractPeerFunc must return a non-nil sp when err == nil\n")
		return
	}

	peer = &Peer{}

	peer.clientPublicKey = *sp.ClientPublicKey
	peer.clientCookieGenerator.Init(sp.serverPublicKey.NoisePublicKey)
	peer.serverPublicKey = sp.serverPublicKey
	peer.serverCookieGenerator.Init(sp.ClientPublicKey.NoisePublicKey)

	peer.clientOriginIndex = msg.Sender
	peer.clientDestination = src

	peer.serverDestination = sp.forwardToAddress
	peer.clientSourceValidateLevel = sp.ClientSourceValidateLevel

	peer.lastActive.Store(time.Now())

	t.mapLock.Lock()
	peer.clientProxyIndex = t.generateProxyIndexLocked(t.clientMap, peer.clientOriginIndex)
	t.clientMap[peer.clientProxyIndex] = peer
	t.mapLock.Unlock()

	log.Printf("[info] received message initiation from client, peer create stage #1: %s(idx:%08x->%08x) <=> %s\n",
		peer.clientDestination.String(), peer.clientOriginIndex, peer.clientProxyIndex,
		peer.serverDestination.String())

	return
}

func (t *WireGuardIndexTranslationTable) processServerMessageResponse(src *net.UDPAddr, msg *device.MessageResponse) (peer *Peer, err error) {
	// we cannot decrypt the MessageResponse, but we need to handle the sender_index from server.
	if msg.Receiver == 0 {
		err = fmt.Errorf("received message hanndshake_response from server %s with impossible receiver_index=0", src.String())
		return
	}

	// make sure the client won't be removed from clientMap
	// before we added it into serverMap in a raced condition (otherwise the peer will leak).
	// so we cannot use RLock()+RUnLock()+Lock() here.
	t.mapLock.Lock()
	defer t.mapLock.Unlock()

	var ok bool
	if peer, ok = t.clientMap[msg.Receiver]; ok {
		peer.lastActive.Store(time.Now())
		peer.serverOriginIndex = msg.Sender
		peer.serverProxyIndex = t.generateProxyIndexLocked(t.serverMap, peer.serverOriginIndex)
		t.serverMap[peer.serverProxyIndex] = peer
		log.Printf("[info] received message response from server, peer create stage #2: %s(idx:%08x->%08x) <=> %s(idx:%08x->%08x)\n",
			peer.clientDestination.String(), peer.clientOriginIndex, peer.clientProxyIndex,
			peer.serverDestination.String(), peer.serverOriginIndex, peer.serverProxyIndex)

		go t.persistForwardTableCache()

		return
	}

	err = fmt.Errorf("no matched peer found for clientMap[%08x], referred by MessageResponse.Receiver from server %s", msg.Receiver, src.String())
	return
}

func (t *WireGuardIndexTranslationTable) processServerMessageCookieReply(src *net.UDPAddr, msg *device.MessageCookieReply) (peer *Peer, err error) {
	if msg.Receiver == 0 {
		err = fmt.Errorf("received message cookie_reply from server %s with impossible receiver_index=0", src.String())
		return
	}

	var ok bool
	t.mapLock.RLock()
	peer, ok = t.clientMap[msg.Receiver]
	t.mapLock.RUnlock()

	if !ok {
		err = fmt.Errorf("no matched peer found for clientMap[%08x], referred by MessageCookieReply.Receiver from server %s", msg.Receiver, src.String())
		return
	}

	ok = peer.clientCookieGenerator.ConsumeReply(msg)
	if !ok {
		err = fmt.Errorf("failed to consume cookie reply from server %s", src.String())
		return
	}
	return
}

func (t *WireGuardIndexTranslationTable) processMessageTransport(packet *Packet, s2c bool) (peer *Peer, err error) {
	// we cannot decrypt MessageTransport,
	// but their receiver_index has the same offset and that is the only information we need
	receiverIndex, err := packet.ReceiverIndex()
	if err != nil {
		return
	}
	if receiverIndex == 0 {
		if s2c {
			err = fmt.Errorf("received message transport from server %s with impossible receiver_index=0", packet.Source.String())
		} else {
			err = fmt.Errorf("received message transport from client %s with impossible receiver_index=0", packet.Source.String())
		}
		return
	}

	var m map[uint32]*Peer
	if s2c {
		m = t.clientMap
	} else {
		m = t.serverMap
	}

	var ok bool
	t.mapLock.RLock()
	peer, ok = m[receiverIndex]
	t.mapLock.RUnlock()

	if !ok {
		if s2c {
			err = fmt.Errorf("no matched peer found for clientMap[%08x], referred by packet from server %s", receiverIndex, packet.Source.String())
		} else {
			err = fmt.Errorf("no matched peer found for serverMap[%08x], referred by packet from client %s", receiverIndex, packet.Source.String())
		}
		return
	}

	peer.lastActive.Store(time.Now())

	if s2c {
		// in case of udp out-of-order (seems not possible to happen)
		if peer.IsServerReplied() {
			ipChanged := !packet.Source.IP.Equal(peer.serverDestination.IP)
			portChanged := packet.Source.Port != peer.serverDestination.Port

			switch peer.serverSourceValidateLevel {
			case SourceValidateLevelIP:
				if ipChanged {
					err = fmt.Errorf("server IP mismatch (for client %s), expected %s, got %s",
						peer.clientDestination,
						peer.serverDestination.IP.String(),
						packet.Source.IP.String())
					return
				}
			case SourceValidateLevelDefault:
				fallthrough
			case SourceValidateLevelIPAndPort:
				if ipChanged || portChanged {
					err = fmt.Errorf("server IP/port mismatch (for server %s), expected %s:%d, got %s:%d",
						peer.clientDestination,
						peer.serverDestination.IP.String(), peer.serverDestination.Port,
						packet.Source.IP.String(), packet.Source.Port)
					return
				}
			}
			if ipChanged || portChanged {
				log.Printf("[info] allowed server reply from another source: %s => %s\n", peer.clientDestination.String(), packet.Source.String())
			}
		}
	} else {
		ipChanged := !packet.Source.IP.Equal(peer.clientDestination.IP)
		portChanged := packet.Source.Port != peer.clientDestination.Port

		switch peer.clientSourceValidateLevel {
		case SourceValidateLevelIP:
			if ipChanged {
				err = fmt.Errorf("client IP mismatch (for server %s), expected %s, got %s",
					peer.serverDestination,
					peer.clientDestination.IP.String(),
					packet.Source.IP.String())
				return
			}
		case SourceValidateLevelIPAndPort:
			if ipChanged || portChanged {
				err = fmt.Errorf("client IP/port mismatch (for server %s), expected %s:%d, got %s:%d",
					peer.serverDestination,
					peer.clientDestination.IP.String(), peer.clientDestination.Port,
					packet.Source.IP.String(), packet.Source.Port)
				return
			}
		}
		if ipChanged || portChanged {
			log.Printf("[info] allowed client romaing: %s => %s\n", peer.clientDestination.String(), packet.Source.String())
			peer.clientDestination = packet.Source
		}
	}

	return
}

func (t *WireGuardIndexTranslationTable) generateProxyIndexLocked(m map[uint32]*Peer, origin uint32) (proxy uint32) {
	if !DebugAlwaysGenerateProxyIndex {
		proxy = origin
	}

	// proxy index also cannot be 0, since the zero-value indicates the peer is not yet initialized
	for _, ok := m[proxy]; ok || proxy == 0; {
		proxy = rand.Uint32()
	}
	return
}

func (t *WireGuardIndexTranslationTable) handlePeersExpireCheck(current time.Time) {
	defer func() {
		go t.persistForwardTableCache()
	}()

	t.mapLock.Lock()
	defer t.mapLock.Unlock()

	for _, peer := range t.clientMap {
		if peer.lastActive.Load().(time.Time).Before(current.Add(-t.Timeout)) {
			delete(t.clientMap, peer.clientProxyIndex)
			delete(t.serverMap, peer.serverProxyIndex)
			log.Printf("[info] expire peer %s (idx:%08x->%08x) <=> %s (idx:%08x->%08x)\n",
				peer.clientDestination.String(), peer.clientOriginIndex, peer.clientProxyIndex,
				peer.serverDestination.String(), peer.serverOriginIndex, peer.serverProxyIndex)
		}
	}
}

func (t *WireGuardIndexTranslationTable) handleAllServerDestinationUpdate(addr *net.UDPAddr) {
	defer func() {
		go t.persistForwardTableCache()
	}()

	t.mapLock.Lock()
	defer t.mapLock.Unlock()

	for _, peer := range t.clientMap {
		peer.serverDestination = addr
	}
}

func (t *WireGuardIndexTranslationTable) persistForwardTableCache() {
	t.mapLock.RLock()
	defer t.mapLock.RUnlock()

	err := t.CacheJar.SaveLocked(t.serverMap)
	if err != nil {
		log.Printf("[error] failed to save forward table cache: %s\n", err)
	}
}

func (t *WireGuardIndexTranslationTable) obtainPacket() *Packet {
	return t.packetPool.Get().(*Packet)
}

func (t *WireGuardIndexTranslationTable) recyclePacket(packet *Packet) {
	packet.Reset()
	t.packetPool.Put(packet)
}
