package mwgp

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/device"
	"log"
	"net"
	"strings"
	"time"
)

type ServerConfigPeer struct {
	ForwardTo        string `json:"forward_to"`
	forwardToAddress *net.UDPAddr

	// ClientSourceValidateLevel is same config with the one in ServerConfigServer
	// but intended to be used as a per-peer override.
	ClientSourceValidateLevel int `json:"csvl,omitempty"`

	// ServerSourceValidateLevel is same config with the one in ServerConfigServer
	// but intended to be used as a per-peer override.
	ServerSourceValidateLevel int `json:"ssvl,omitempty"`

	ClientPublicKey *NoisePublicKey `json:"pubkey,omitempty"`

	// required by cookie generator
	serverPublicKey NoisePublicKey
}

func (p ServerConfigPeer) isFallback() bool {
	return p.ClientPublicKey == nil
}

const (
	SourceValidateLevelDefault = iota

	// SourceValidateLevelNone (1):
	//   do not validate the source address.
	//   this allows client roaming but also comes with the risk of a kind of DoS attack.
	//   this is the default behavior for ClientSourceValidateLevel.
	SourceValidateLevelNone

	// SourceValidateLevelIP (2):
	//   validate the source address only by IP.
	//   disable client roaming across different hosts,
	//   maybe compatible with some kinds of NAT.
	SourceValidateLevelIP

	// SourceValidateLevelIPAndPort (3):
	//   validate the source address by IP and port.
	//   disabled the client roaming to defeat DoS attack,
	//   but client need to wait timeout and resend the MessageInitiation
	//   if they really got their IP address changed.
	//   this is the default behavior for ServerSourceValidateLevel.
	SourceValidateLevelIPAndPort
)

type ServerConfigServer struct {
	PrivateKey     *NoisePrivateKey `json:"privkey"`
	PrivateKeyFile string           `json:"privkey_file,omitempty"`

	Address string              `json:"address"`
	Peers   []*ServerConfigPeer `json:"peers"`

	// ClientSourceValidateLevel specified the way to handle a MessageTransport
	// packet that comes from a source address not matches to prior packets.
	ClientSourceValidateLevel int `json:"csvl,omitempty"`

	// ServerSourceValidateLevel specified the way to handle a MessageTransport
	// packet that comes from a source address not matches to prior packets.
	ServerSourceValidateLevel int `json:"ssvl,omitempty"`
}

func (s *ServerConfigServer) Initialize() (err error) {
	if len(s.Peers) == 0 {
		err = fmt.Errorf("no peers")
		return
	}

	if s.PrivateKey == nil {
		if s.PrivateKeyFile == "" {
			err = fmt.Errorf("no server private key provided")
			return
		}
		s.PrivateKey = &NoisePrivateKey{}
		err = s.PrivateKey.ReadFromFile(s.PrivateKeyFile)
		if err != nil {
			err = fmt.Errorf("cannot read private key from file %s: %w", s.PrivateKeyFile, err)
			return
		}
	} else {
		if s.PrivateKeyFile != "" {
			err = fmt.Errorf("cannot specify both privkey and privkey_file")
			return
		}
	}

	var foundFallback bool
	for pi, p := range s.Peers {
		if p.ClientPublicKey == nil {
			if foundFallback {
				err = fmt.Errorf("multiple fallback peers found")
				return
			}
			foundFallback = true
		}

		if len(p.ForwardTo) == 0 {
			err = fmt.Errorf("peer[%d] has no forward_to address", pi)
			return
		}

		forwardToTokens := strings.Split(p.ForwardTo, ":")
		if len(forwardToTokens) != 2 {
			err = fmt.Errorf("peer[%d] has invalid forward_to address %s", pi, p.ForwardTo)
			return
		}
		address := strings.TrimSpace(forwardToTokens[0])
		port := strings.TrimSpace(forwardToTokens[1])
		if len(address) == 0 {
			address = s.Address
		}
		forwardToAddress := strings.Join([]string{address, port}, ":")
		p.forwardToAddress, err = net.ResolveUDPAddr("udp", forwardToAddress)
		if err != nil {
			err = fmt.Errorf("peer[%d] has invalid forward_to address %s: %w", pi, p.ForwardTo, err)
			return
		}

		if p.ClientSourceValidateLevel == SourceValidateLevelDefault {
			p.ClientSourceValidateLevel = s.ClientSourceValidateLevel
		}
		if p.ServerSourceValidateLevel == SourceValidateLevelDefault {
			p.ServerSourceValidateLevel = s.ServerSourceValidateLevel
		}

		p.serverPublicKey = s.PrivateKey.PublicKey()
	}
	return
}

type ServerConfig struct {
	Listen       string                `json:"listen"`
	Timeout      int                   `json:"timeout"`
	Servers      []*ServerConfigServer `json:"servers"`
	ObfuscateKey string                `json:"obfs"`
	WGITCacheConfig
}

type Server struct {
	wgitTable *WireGuardIndexTranslationTable
	servers   []*ServerConfigServer
}

func NewServerWithConfig(config *ServerConfig) (outServer *Server, err error) {
	if len(config.Servers) == 0 {
		err = errors.New("no server defined")
		return
	}

	for si, s := range config.Servers {
		err = s.Initialize()
		if err != nil {
			err = fmt.Errorf("server[%d]: %w", si, err)
			return
		}
	}

	server := Server{}
	server.servers = config.Servers
	server.wgitTable = NewWireGuardIndexTranslationTable()
	server.wgitTable.ClientListen, err = net.ResolveUDPAddr("udp", config.Listen)
	if err != nil {
		err = fmt.Errorf("invalid listen address %s: %w", config.Listen, err)
		return
	}
	server.wgitTable.Timeout = time.Duration(config.Timeout) * time.Second
	server.wgitTable.ExtractPeerFunc = server.extractPeer
	server.wgitTable.CacheJar.WGITCacheConfig = config.WGITCacheConfig

	var obfuscator WireGuardObfuscator
	obfuscator.Initialize(config.ObfuscateKey)
	server.wgitTable.ClientWriteToUDPFunc = obfuscator.WriteToUDPWithObfuscate
	server.wgitTable.ClientReadFromUDPFunc = obfuscator.ReadFromUDPWithDeobfuscate

	outServer = &server
	return
}

func (s *Server) extractPeer(msg *device.MessageInitiation) (sp *ServerConfigPeer, err error) {
	tryDecryptPeerPKWith := func(privateKey NoisePrivateKey) (peerPK NoisePublicKey, err error) {
		ourPublicKey := privateKey.PublicKey()

		// most implementation here is copied from device.Device.ConsumeMessageInitiation().
		var (
			hash     [blake2s.Size]byte
			chainKey [blake2s.Size]byte
		)

		devicex.mixHash(&hash, &device.InitialHash, ourPublicKey.NoisePublicKey[:])
		devicex.mixHash(&hash, &hash, msg.Ephemeral[:])
		devicex.mixKey(&chainKey, &device.InitialChainKey, msg.Ephemeral[:])

		// decrypt static key
		var key [chacha20poly1305.KeySize]byte
		ss := privateKey.SharedSecret(msg.Ephemeral)
		if devicex.isZero(ss[:]) {
			return
		}
		device.KDF2(&chainKey, &key, chainKey[:], ss[:])
		aead, _ := chacha20poly1305.New(key[:])
		_, err = aead.Open(peerPK.NoisePublicKey[:0], device.ZeroNonce[:], msg.Static[:], hash[:])
		if err != nil {
			return
		}

		// TODO: now we have peerPK, but we can do further validation to protect against replay & flood
		return
	}

	if len(s.servers) == 0 {
		err = fmt.Errorf("no server configured")
		return
	}

	var matchedServer *ServerConfigServer
	var peerPK NoisePublicKey
	for _, server := range s.servers {
		peerPK, err = tryDecryptPeerPKWith(*server.PrivateKey)
		if err == nil {
			matchedServer = server
			break
		}
	}
	if err != nil {
		err = fmt.Errorf("no server private key decrypted the message: %w", err)
		return
	}

	var matchedServerPeer *ServerConfigPeer
	var fallbackServerPeer *ServerConfigPeer
	for _, peer := range matchedServer.Peers {
		if peer.isFallback() {
			fallbackServerPeer = peer
		} else {
			if peer.ClientPublicKey.Equals(peerPK.NoisePublicKey) {
				matchedServerPeer = peer
			}
		}
	}
	if matchedServerPeer == nil {
		matchedServerPeer = fallbackServerPeer
	}
	if matchedServerPeer == nil {
		err = fmt.Errorf("no matched server peer and no fallback server peer for server %s", matchedServer.PrivateKey.Base64())
		return
	}

	copiedPeer := *matchedServerPeer
	copiedPeer.ClientPublicKey = &peerPK
	sp = &copiedPeer
	return
}

func (s *Server) Start() (err error) {
	log.Printf("[info] listen on %s ...\n", s.wgitTable.ClientListen)
	err = s.wgitTable.Serve()
	return
}
