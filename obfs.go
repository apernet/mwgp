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
// A.1. For messages with type of MessageInitiation, MessageResponse, and MessageCookieReply,
//      as they have fixed message length, we add a random suffix to the message.
//      For messages with type of MessageTransport with length < 256,
//      we generate a 16-byte random bytes, attach it to the end of message,
//      and set packet[1] to 0x01.
// A.2. Use the end 16-bytes of message as nonce to obfuscate the message.
// A.3. Generate the XOR patterns with MODIFIED_XXHASH64(NONCE+N*USERKEYHASH),
//      where (N-1) is the index of 8-bytes in the packet data.
// A.4. Obfuscate the packet data with XOR patterns.
//      For MessageInitiation, MessageResponse, and MessageCookieReply, we only obfuscate their origin length.
//      For MessageTransport, we only obfuscate the first 16-bytes.
//
// B. Deobfuscate
// B.1. Check the first 4-bytes of packet data, if it is already a valid WireGuard packet, skip the following steps.
// B.2. Use the tail 16-bytes of packet data as the nonce.
// B.3. Generate the XOR patterns with the same method in the A.3.
// B.4. Deobfuscate the first 8-bytes of the packet to find out its message type.
// B.5. For messages with type of MessageInitiation, MessageResponse, and MessageCookieReply,
//      set the packet length to its fixed message length, drop the rest data.
// B.6. For messages with type of MessageTransport, Check the packet[1],
//      if it is 0x01, set it to 0, and minus 16-bytes from its length.
// B.7. Deobfuscate the rest data.
//
// C. Modified XXHASH64
// C.1. Modified XXHASH64 is a patched XXHASH64 function which must returns a pattern that changes original WireGuard protocol.
//      So the packets of original WireGuard protocol can be distinguished from obfuscated packets.

const (
	kObfuscateRandomSuffixMaxLength  = 384
	kObfuscateSuffixAsNonceMinLength = 256
	kObfuscateNonceLength            = 16
)

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
	var obfsPartLength int
	switch messageType {
	case device.MessageInitiationType:
		packet.Length = device.MessageInitiationSize + kObfuscateNonceLength + rand.Int()%kObfuscateRandomSuffixMaxLength
		_, _ = rand.Read(packet.Data[device.MessageInitiationSize:packet.Length])
		obfsPartLength = device.MessageInitiationSize
	case device.MessageResponseType:
		packet.Length = device.MessageResponseSize + kObfuscateNonceLength + rand.Int()%kObfuscateRandomSuffixMaxLength
		_, _ = rand.Read(packet.Data[device.MessageResponseSize:packet.Length])
		obfsPartLength = device.MessageResponseSize
	case device.MessageCookieReplyType:
		packet.Length = device.MessageCookieReplySize + kObfuscateNonceLength + rand.Int()%kObfuscateRandomSuffixMaxLength
		_, _ = rand.Read(packet.Data[device.MessageCookieReplySize:packet.Length])
		obfsPartLength = device.MessageCookieReplySize
	case device.MessageTransportType:
		obfsPartLength = device.MessageTransportHeaderSize
		if packet.Length < kObfuscateSuffixAsNonceMinLength {
			packet.Data[1] = 0x01
			packet.Length += kObfuscateNonceLength
			_, _ = rand.Read(packet.Data[packet.Length-kObfuscateNonceLength : packet.Length])
		}
	default:
		return
	}

	var nonce [kObfuscateNonceLength]byte
	copy(nonce[:], packet.Data[packet.Length-kObfuscateNonceLength:])

	var digest ModifiedXXHashDigest
	digest.Reset()
	_, _ = digest.Write(nonce[:])
	for i := 0; i < obfsPartLength; i += 8 {
		_, _ = digest.Write(o.userKeyHash[:])
		var xorKey [8]byte
		digest.Sum(xorKey[:0])
		for j := i; j < i+8 && j < obfsPartLength; j++ {
			packet.Data[j] ^= xorKey[j-i]
		}
	}
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

	var nonce [kObfuscateNonceLength]byte
	copy(nonce[:], packet.Data[packet.Length-kObfuscateNonceLength:])

	var digest ModifiedXXHashDigest
	digest.Reset()
	_, _ = digest.Write(nonce[:])

	// decode first 8 bytes for message type
	_, _ = digest.Write(o.userKeyHash[:])
	var xorKey [8]byte
	digest.Sum(xorKey[:0])
	for i := 0; i < 8; i++ {
		packet.Data[i] ^= xorKey[i]
	}

	messageType := packet.MessageType()
	var obfsPartLength int
	switch messageType {
	case device.MessageInitiationType:
		obfsPartLength = device.MessageInitiationSize
		packet.Length = device.MessageInitiationSize
	case device.MessageResponseType:
		obfsPartLength = device.MessageResponseSize
		packet.Length = device.MessageResponseSize
	case device.MessageCookieReplyType:
		obfsPartLength = device.MessageCookieReplySize
		packet.Length = device.MessageCookieReplySize
	case device.MessageTransportType:
		obfsPartLength = device.MessageTransportHeaderSize
		if packet.Data[1] == 0x01 {
			packet.Data[1] = 0
			packet.Length -= kObfuscateNonceLength
		}
	default:
		// wtf?
		return
	}

	// decode the rest
	for i := 8; i < obfsPartLength; i += 8 {
		_, _ = digest.Write(o.userKeyHash[:])
		digest.Sum(xorKey[:0])
		for j := i; j < i+8 && j < obfsPartLength; j++ {
			packet.Data[j] ^= xorKey[j-i]
		}
	}

	packet.Flags |= PacketFlagDeobfuscatedAfterReceived
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
	high32 := uint32(result >> 32)
	if high32&0xF8FE_FFFF == 0 {
		result |= 0xD769_F4C2_0000_0000
	}
	return result
}
