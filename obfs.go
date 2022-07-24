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
// A.1a.For messages with type of MessageInitiation, MessageResponse, and MessageCookieReply,
//      as they have fixed message length, we add a random suffix to the message.
// A.1b.In additional, if the MessageInitiation.MAC2 and MessageResponse.MAC2 is all zero,
//      fill it with random bytes and set packet[1] to 0x01.
// A.1c.For messages with type of MessageTransport with length < 256,
//      we generate a 16-byte random bytes, attach it to the end of message,
//      and set packet[1] to 0x01.
// A.2. Use the end 16-bytes of message as nonce to obfuscate the message.
// A.3. Generate the XOR patterns with XXHASH64(NONCE+N*USERKEYHASH),
//      where (N-1) is the index of 8-bytes in the packet data,
//      but as for N=1, we use MODIFIED_XXHASH64() instead of XXHASH64()
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
// B.8. For message with type of MessageInitiation, MessageResponse, check the packet[1],
//      if it is 0x01, set it to 0, and memset(MAC2, 0, MAC2_LEN)
//
// C. Modified XXHASH64
// C.1. Modified XXHASH64 is a patched XXHASH64 function which must returns a pattern that changes original WireGuard protocol.
//      So the packets of original WireGuard protocol can be distinguished from obfuscated packets.

const (
	kObfuscateRandomSuffixMaxLength  = 384
	kObfuscateSuffixAsNonceMinLength = 256
	kObfuscateNonceLength            = 16
	kObfuscateXORKeyLength           = 8

	kMessageInitiationTypeMAC2Offset = 132
	kMessageResponseTypeMAC2Offset   = 76
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

	isAllZero := func(b []byte) (result bool) {
		result = true
		for _, v := range b {
			if v != 0 {
				result = false
				break
			}
		}
		return
	}

	messageType := packet.MessageType()
	var obfsPartLength int
	switch messageType {
	case device.MessageInitiationType:
		packet.Length = device.MessageInitiationSize + kObfuscateNonceLength + rand.Int()%kObfuscateRandomSuffixMaxLength
		obfsPartLength = device.MessageInitiationSize
		if isAllZero(packet.Data[kMessageInitiationTypeMAC2Offset:device.MessageInitiationSize]) {
			packet.Data[1] = 0x01
			obfsPartLength = kMessageInitiationTypeMAC2Offset
		}
		_, _ = rand.Read(packet.Data[obfsPartLength:packet.Length])
	case device.MessageResponseType:
		packet.Length = device.MessageResponseSize + kObfuscateNonceLength + rand.Int()%kObfuscateRandomSuffixMaxLength
		obfsPartLength = device.MessageResponseSize
		if isAllZero(packet.Data[kMessageResponseTypeMAC2Offset:device.MessageResponseSize]) {
			packet.Data[1] = 0x01
			obfsPartLength = kMessageResponseTypeMAC2Offset
		}
		_, _ = rand.Read(packet.Data[obfsPartLength:packet.Length])
	case device.MessageCookieReplyType:
		packet.Length = device.MessageCookieReplySize + kObfuscateNonceLength + rand.Int()%kObfuscateRandomSuffixMaxLength
		obfsPartLength = device.MessageCookieReplySize
		_, _ = rand.Read(packet.Data[obfsPartLength:packet.Length])
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

	var digest xxhash.Digest
	digest.Reset()
	_, _ = digest.Write(nonce[:])
	for i := 0; i < obfsPartLength; i += kObfuscateXORKeyLength {
		_, _ = digest.Write(o.userKeyHash[:])
		var xorKey [kObfuscateXORKeyLength]byte
		digest.Sum(xorKey[:0])
		if i == 0 {
			o.modifyHashMaskForWireGuardHeaderConflict(xorKey[:])
		}
		for j := i; j < i+kObfuscateXORKeyLength && j < obfsPartLength; j++ {
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

	var digest xxhash.Digest
	digest.Reset()
	_, _ = digest.Write(nonce[:])

	// decode first 8 bytes for message type
	_, _ = digest.Write(o.userKeyHash[:])
	var xorKey [kObfuscateXORKeyLength]byte
	digest.Sum(xorKey[:0])
	o.modifyHashMaskForWireGuardHeaderConflict(xorKey[:])
	for i := 0; i < kObfuscateXORKeyLength; i++ {
		packet.Data[i] ^= xorKey[i]
	}

	memset := func(b []byte, c byte) {
		for i := range b {
			b[i] = c
		}
	}

	messageType := packet.MessageType()
	var obfsPartLength int
	switch messageType {
	case device.MessageInitiationType:
		packet.Length = device.MessageInitiationSize
		obfsPartLength = device.MessageInitiationSize
		if packet.Data[1] == 0x01 {
			packet.Data[1] = 0
			obfsPartLength = kMessageInitiationTypeMAC2Offset
			memset(packet.Data[kMessageInitiationTypeMAC2Offset:device.MessageInitiationSize], 0)
		}
	case device.MessageResponseType:
		packet.Length = device.MessageResponseSize
		obfsPartLength = device.MessageResponseSize
		if packet.Data[1] == 0x01 {
			packet.Data[1] = 0
			obfsPartLength = kMessageResponseTypeMAC2Offset
			memset(packet.Data[kMessageResponseTypeMAC2Offset:device.MessageResponseSize], 0)
		}
	case device.MessageCookieReplyType:
		packet.Length = device.MessageCookieReplySize
		obfsPartLength = device.MessageCookieReplySize
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
	for i := kObfuscateXORKeyLength; i < obfsPartLength; i += kObfuscateXORKeyLength {
		_, _ = digest.Write(o.userKeyHash[:])
		digest.Sum(xorKey[:0])
		for j := i; j < i+kObfuscateXORKeyLength && j < obfsPartLength; j++ {
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

func (o *WireGuardObfuscator) modifyHashMaskForWireGuardHeaderConflict(b []byte) {
	if b[0]&0b11111000 == 0 && b[1]&0b11111110 == 0 {
		b[0] |= 0b11010111
		b[1] |= 0b01101001
	}
}
