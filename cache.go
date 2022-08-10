package mwgp

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

type WGITCacheConfig struct {
	CacheFilePath string `json:"cache_file_path,omitempty"`
	SkipLoadCache bool   `json:"-"`
}

type WGITCachePeer struct {
	ClientOriginIndex         uint32         `json:"coidx"`
	ClientProxyIndex          uint32         `json:"cpidx"`
	ClientPublicKey           NoisePublicKey `json:"cpk"`
	ClientDestination         string         `json:"cdst"`
	ClientSourceValidateLevel int            `json:"csvl"`
	ServerOriginIndex         uint32         `json:"soidx"`
	ServerProxyIndex          uint32         `json:"spidx"`
	ServerPublicKey           NoisePublicKey `json:"spk"`
	ServerDestination         string         `json:"sdst"`
	ServerSourceValidateLevel int            `json:"ssvl"`
	ObfuscateEnabled          bool           `json:"obfe"`
}

func (cp *WGITCachePeer) FromWGITPeer(peer *Peer) (err error) {
	cp.ClientOriginIndex = peer.clientOriginIndex
	cp.ClientProxyIndex = peer.clientProxyIndex
	cp.ClientPublicKey = peer.clientPublicKey
	cp.ClientDestination = peer.clientDestination.String()
	cp.ClientSourceValidateLevel = peer.clientSourceValidateLevel

	cp.ServerOriginIndex = peer.serverOriginIndex
	cp.ServerProxyIndex = peer.serverProxyIndex
	cp.ServerPublicKey = peer.serverPublicKey
	if peer.serverDestination != nil {
		cp.ServerDestination = peer.serverDestination.String()
	}
	cp.ServerSourceValidateLevel = peer.serverSourceValidateLevel

	cp.ObfuscateEnabled = peer.obfuscateEnabled

	return
}

func (cp *WGITCachePeer) WGITPeer() (peer *Peer, err error) {
	peer = &Peer{}

	peer.clientOriginIndex = cp.ClientOriginIndex
	peer.clientProxyIndex = cp.ClientProxyIndex
	peer.clientPublicKey = cp.ClientPublicKey
	if cp.ClientDestination == "" {
		err = fmt.Errorf("client destination cannot be empty")
		return
	}
	peer.clientDestination, err = net.ResolveUDPAddr("udp", cp.ClientDestination)
	if err != nil {
		return
	}
	peer.clientSourceValidateLevel = cp.ClientSourceValidateLevel

	peer.serverOriginIndex = cp.ServerOriginIndex
	peer.serverProxyIndex = cp.ServerProxyIndex
	peer.serverPublicKey = cp.ServerPublicKey
	if cp.ServerDestination == "" {
		err = fmt.Errorf("server destination cannot be empty")
		return
	}
	peer.serverDestination, err = net.ResolveUDPAddr("udp", cp.ServerDestination)
	if err != nil {
		return
	}
	peer.serverSourceValidateLevel = cp.ServerSourceValidateLevel

	peer.clientCookieGenerator.Init(peer.clientPublicKey.NoisePublicKey)
	peer.serverCookieGenerator.Init(peer.serverPublicKey.NoisePublicKey)

	peer.lastActive.Store(time.Now())

	peer.obfuscateEnabled = cp.ObfuscateEnabled

	return
}

type WGITCacheTable struct {
	ClientMap []WGITCachePeer `json:"client_map"`
}

type WGITCacheJar struct {
	WGITCacheConfig
}

func (c *WGITCacheJar) SaveLocked(clientMap map[uint32]*Peer) (err error) {
	if c.CacheFilePath == "" {
		return
	}

	ct := WGITCacheTable{}

	for _, peer := range clientMap {
		cp := WGITCachePeer{}
		ferr := cp.FromWGITPeer(peer)
		if ferr != nil {
			log.Printf("[error] failed to convert peer to cache peer: %s\n", ferr.Error())
			continue
		}
		ct.ClientMap = append(ct.ClientMap, cp)
	}

	bs, err := json.MarshalIndent(&ct, "", "  ")
	if err != nil {
		return
	}

	tmpfile := c.CacheFilePath + ".tmp"
	err = os.WriteFile(tmpfile, bs, 0644)
	if err != nil {
		err = fmt.Errorf("failed to write cache tmpfile %s: %w", tmpfile, err)
		return
	}

	err = os.Rename(tmpfile, c.CacheFilePath)
	if err != nil {
		err = fmt.Errorf("failed to create cache file %s: %w", c.CacheFilePath, err)
		return
	}

	return
}

func (c *WGITCacheJar) LoadLocked(serverMap map[uint32]*Peer, clientMap map[uint32]*Peer) (err error) {
	if c.CacheFilePath == "" {
		return
	}
	if c.SkipLoadCache {
		return
	}

	ct := WGITCacheTable{}

	bs, err := os.ReadFile(c.CacheFilePath)
	if err != nil {
        err = nil
		return
	}

	err = json.Unmarshal(bs, &ct)
	if err != nil {
		return
	}

	for _, cp := range ct.ClientMap {
		peer, ferr := cp.WGITPeer()
		if ferr != nil {
			log.Printf("[error] failed to convert cache peer to peer: %s\n", ferr.Error())
			continue
		}
		clientMap[peer.clientProxyIndex] = peer
		if peer.serverProxyIndex != 0 {
			serverMap[peer.serverProxyIndex] = peer
		}
	}

	return
}
