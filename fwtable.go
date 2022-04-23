package mwgp

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type forwardTableKey struct {
	srcIP   string
	srcPort int
}

type forwardTableValue struct {
	expire  atomic.Value // time.Time
	timeout time.Duration
	exited  atomic.Value // bool
	srcAddr *net.UDPAddr
	dstAddr *net.UDPAddr
	srcConn *net.UDPConn // not owned
	dstConn *net.UDPConn // owned
}

func (v *forwardTableValue) reverseForwardLoop() {
	var recvBuffer [kMTU]byte
	for {
		readLen, err := v.dstConn.Read(recvBuffer[:])
		if err != nil {
			log.Printf("[error] failed to read when forward from %s to %s: %s\n", v.dstAddr, v.srcAddr, err.Error())
			break
		}
		v.updateExpire()
		writeLen, err := v.srcConn.WriteToUDP(recvBuffer[:readLen], v.srcAddr)
		if err != nil {
			log.Printf("[error] failed to write when forward from %s to %s: %s\n", v.dstAddr, v.srcAddr, err.Error())
			break
		}
		if readLen != writeLen {
			log.Printf("[warn] read %d byte but wrote %d byte when forward from %s to %s\n", readLen, writeLen, v.dstAddr, v.srcAddr)
		}
		v.updateExpire()
	}
	v.exited.Store(true)
}

func (v *forwardTableValue) updateExpire() {
	v.expire.Store(time.Now().Add(v.timeout))
}

func (v *forwardTableValue) isExpired() bool {
	return time.Now().After(v.expire.Load().(time.Time)) || v.exited.Load().(bool)
}

func (v *forwardTableValue) Close() (err error) {
	if v.dstConn != nil {
		err = v.dstConn.Close()
	}
	return
}

type forwardTable struct {
	table     map[forwardTableKey]*forwardTableValue
	lock      sync.RWMutex
	timeout   time.Duration
	lastPurge time.Time
}

func newForwardTable(timeout time.Duration) *forwardTable {
	return &forwardTable{
		table:     make(map[forwardTableKey]*forwardTableValue),
		timeout:   timeout,
		lastPurge: time.Now(),
	}
}

func (t *forwardTable) createAndBeginReverseForward(srcAddr, dstAddr *net.UDPAddr, srcConn, dstConn *net.UDPConn) *forwardTableValue {
	key := forwardTableKey{
		srcIP:   srcAddr.IP.String(),
		srcPort: srcAddr.Port,
	}
	value := forwardTableValue{
		timeout: t.timeout,
		srcAddr: srcAddr,
		dstAddr: dstAddr,
		srcConn: srcConn,
		dstConn: dstConn,
	}
	value.updateExpire()
	value.exited.Store(false)
	t.lock.Lock()
	if originValue, ok := t.table[key]; ok {
		if originValue != nil {
			_ = originValue.Close()
		}
	}
	t.table[key] = &value
	t.lock.Unlock()
	go value.reverseForwardLoop()
	log.Printf("[info] forward created: %s <-> %s\n", srcAddr, dstAddr)
	return &value
}

func (t *forwardTable) purgeExpired() {
	if t.lastPurge.Add(t.timeout).After(time.Now()) {
		return
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	var keysToRemove []forwardTableKey
	for k, v := range t.table {
		if v == nil || v.isExpired() {
			keysToRemove = append(keysToRemove, k)
		}
	}
	for _, k := range keysToRemove {
		v := t.table[k]
		if v != nil {
			_ = v.Close()
		}
		delete(t.table, k)
	}
}

func (t *forwardTable) forwardPacket(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, srcConn *net.UDPConn, packet []byte) (err error) {
	t.purgeExpired()
	key := forwardTableKey{
		srcIP:   srcAddr.IP.String(),
		srcPort: srcAddr.Port,
	}
	t.lock.RLock()
	value := t.table[key]
	t.lock.RUnlock()
	if value != nil {
		isRecreateRequired := false
		if value.isExpired() {
			log.Printf("[warn] forward entry expired for client %s from %s to %s, recreate udp conn\n", srcAddr, value.dstAddr, dstAddr)
			isRecreateRequired = true
		}
		if !udpAddrEquals(value.dstAddr, dstAddr) {
			log.Printf("[warn] dst addr changed for client %s from %s to %s, recreate udp conn\n", srcAddr, value.dstAddr, dstAddr)
			isRecreateRequired = true
		}
		if isRecreateRequired {
			t.lock.Lock()
			_ = value.Close()
			delete(t.table, key)
			t.lock.Unlock()
		}
	}
	if value == nil {
		var dstConn *net.UDPConn
		dstConn, err = net.DialUDP("udp", nil, dstAddr)
		if err != nil {
			log.Printf("[error] failed to dial udp conn to %s\n", dstAddr)
			return
		}
		value = t.createAndBeginReverseForward(srcAddr, dstAddr, srcConn, dstConn)
	}
	value.updateExpire()
	_, err = value.dstConn.Write(packet)
	return
}

func udpAddrEquals(addr1 net.Addr, addr2 *net.UDPAddr) bool {
	if addr1, ok := addr1.(*net.UDPAddr); ok {
		return addr1.IP.Equal(addr2.IP) && addr1.Port == addr2.Port
	}
	return false
}
