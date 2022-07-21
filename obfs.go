package mwgp

import (
	"crypto/sha256"
	"github.com/cespare/xxhash/v2"
	"golang.zx2c4.com/wireguard/device"
	"math/rand"
	"net"
	"time"
)

// Goal:
// Fast obfuscation WireGuard Packet without overhead to MTU
//
// Design:
//
// A. Obfuscate
// A.1. For messages with type of MessageInitialize, MessageResponse, MessageCookieReply,
//      and MessageTransport with length < 256,
//      we generate a 16-byte random nonce, and attach it to the end of message.
// A.2. For messages with type of MessageTransport with length >= 256,
//      we use the final 16-byte of the message as the nonce,
//      and set packet[1] to 0x01.
// A.3. Generate the XOR patterns with MODIFIED_XXHASH64(NONCE+N*USERKEYHASH),
//      where (N-1) is the index of 8-bytes in the packet data.
// A.4. Obfuscate the packet data with XOR patterns.
//
// B. Deobfuscate
// B.1. Check the first 4-bytes of packet data, if it is already a valid WireGuard packet, skip the following steps.
// B.2. Use the tail 16-bytes of packet data as the nonce.
// B.3. Generate the XOR patterns with the same method in the A.3.
// B.4. Deobfuscate the packet data with XOR patterns.
// B.5. Check the packet[1], if it is 0x01, set it to 0, otherwise minus 16-bytes from its length.
//
// C. Modified XXHASH64
// C.1. Modified XXHASH64 is a patched XXHASH64 function which never returns all zero for first 4-bytes of output.

type WireGuardObfuscator struct {
	enabled     bool
	userKeyHash [sha256.Size]byte
}

func (o *WireGuardObfuscator) Initialize(userKey string) {
	if len(userKey) == 0 {
		o.enabled = false
		return
	}
	o.enabled = true
	rand.Seed(time.Now().Unix())
	h := sha256.New()
	h.Write([]byte(userKey))
	h.Sum(o.userKeyHash[:0])
}

func (o *WireGuardObfuscator) Obfuscate(packet *Packet) {
	if !o.enabled {
		return
	}
	if packet.Flags&PacketFlagObfuscateBeforeSend == 0 {
		return
	}
	messageType := packet.MessageType()
	var useExtendedNonce bool
	switch messageType {
	case device.MessageInitiationType:
		fallthrough
	case device.MessageResponseType:
		fallthrough
	case device.MessageCookieReplyType:
		useExtendedNonce = true
	case device.MessageTransportType:
		useExtendedNonce = packet.Length < 256
	}
	var nonce [16]byte
	if useExtendedNonce {
		_, _ = rand.Read(nonce[:])
		copy(packet.Data[packet.Length:], nonce[:])
		packet.Length += 16
	} else {
		copy(nonce[:], packet.Data[packet.Length-16:])
		packet.Data[1] = 0x01
	}
	o.processWithNonce(packet, nonce[:])
}

func (o *WireGuardObfuscator) Deobfuscate(packet *Packet) {
	if !o.enabled {
		return
	}
	if packet.Length < device.MinMessageSize {
		// wtf
		return
	}
	if packet.Data[0] >= 1 && packet.Data[0] <= 4 && packet.Data[1] == 0 && packet.Data[2] == 0 && packet.Data[3] == 0 {
		// non-obfuscated WireGuard packet
		return
	}

	var nonce [16]byte
	copy(nonce[:], packet.Data[packet.Length-16:])

	o.processWithNonce(packet, nonce[:])

	if packet.Data[1] == 0x01 {
		packet.Data[1] = 0
	} else {
		packet.Length -= 16
	}

	packet.Flags |= PacketFlagDeobfuscatedAfterReceived
}

func (o *WireGuardObfuscator) processWithNonce(packet *Packet, nonce []byte) {
	var digest ModifiedXXHashDigest
	digest.Reset()
	_, _ = digest.Write(nonce)
	for i := 0; i < packet.Length-16; i += 8 {
		_, _ = digest.Write(o.userKeyHash[:])
		var xorKey [8]byte
		digest.Sum(xorKey[:0])
		for j := i; j < i+8 && j < packet.Length-16; j++ {
			packet.Data[j] ^= xorKey[j-i]
		}
	}
}

func (o *WireGuardObfuscator) WriteToUDPWithObfuscate(conn *net.UDPConn, packet *Packet) (err error) {
	o.Obfuscate(packet)
	err = defaultWriteToUDPFunc(conn, packet)
	if err != nil {
		return
	}
	return
}

func (o *WireGuardObfuscator) ReadFromUDPWithDeobfuscate(conn *net.UDPConn, packet *Packet) (err error) {
	err = defaultReadFromUDPFunc(conn, packet)
	if err != nil {
		return
	}
	o.Deobfuscate(packet)
	return
}

type ModifiedXXHashDigest struct {
	xxhash.Digest
}

func (d *ModifiedXXHashDigest) Sum(b []byte) []byte {
	s := d.Sum64()
	return append(
		b,
		byte(s>>56),
		byte(s>>48),
		byte(s>>40),
		byte(s>>32),
		byte(s>>24),
		byte(s>>16),
		byte(s>>8),
		byte(s),
	)
}

func (d *ModifiedXXHashDigest) Sum64() uint64 {
	result := d.Digest.Sum64()
	if result&0xFFFF_FFFF_0000_0000 == 0 {
		result |= 0xD769_F4C2_0000_0000
	}
	return result
}
