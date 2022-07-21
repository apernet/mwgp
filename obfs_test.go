package mwgp

import (
	"crypto/rand"
	"golang.zx2c4.com/wireguard/device"
	"testing"
)

func TestWireGuardObfuscator_Obfuscate(t *testing.T) {
	testObfuscate(t, device.MessageInitiationType, device.MessageInitiationSize)
	testObfuscate(t, device.MessageResponseType, device.MessageResponseSize)
	testObfuscate(t, device.MessageCookieReplyType, device.MessageCookieReplySize)
	testObfuscate(t, device.MessageTransportType, device.MessageTransportSize)
	testObfuscate(t, device.MessageTransportType, 101)
	testObfuscate(t, device.MessageTransportType, 701)
	testObfuscate(t, device.MessageTransportType, 1500)
}

func testObfuscate(t *testing.T, messageType byte, messageLength int) {
	var obfuscator WireGuardObfuscator

	obfuscator.Initialize("test")
	var p Packet
	p.Data[0] = messageType
	p.Data[1] = 0
	p.Data[2] = 0
	p.Data[3] = 0
	p.Length = messageLength
	_, _ = rand.Read(p.Data[4:p.Length])

	t.Logf("origin packet: length=%d data=%v\n", p.Length, p.Data[:p.Length])

	originPacket := p

	p.Flags |= PacketFlagObfuscateBeforeSend
	obfuscator.Obfuscate(&p)

	t.Logf("obfuscated packet: length=%d data=%v\n", p.Length, p.Data[:p.Length])

	obfuscator.Deobfuscate(&p)

	if p.Flags&PacketFlagDeobfuscatedAfterReceived == 0 {
		t.Errorf("packet not deobfuscated")
	}

	packetEqual := func(lhs, rhs *Packet) bool {
		if lhs.Length != rhs.Length {
			return false
		}
		for i := 0; i < lhs.Length; i++ {
			if lhs.Data[i] != rhs.Data[i] {
				return false
			}
		}
		return true
	}

	if !packetEqual(&originPacket, &p) {
		t.Errorf("obfuscate/deobfuscate failed\n")
	}

	t.Logf("deobfuscated packet: length=%d data=%v\n", p.Length, p.Data[:p.Length])
}

func BenchmarkWireGuardObfuscator_Obfuscate(b *testing.B) {
	var obfuscator WireGuardObfuscator

	obfuscator.Initialize("test")
	var p Packet
	p.Data[0] = 4
	p.Data[1] = 0
	p.Data[2] = 0
	p.Data[3] = 0
	p.Length = 1500
	_, _ = rand.Read(p.Data[4:p.Length])
	p.Flags |= PacketFlagObfuscateBeforeSend

	originPacket := p

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		p = originPacket
		b.StartTimer()
		obfuscator.Obfuscate(&p)
	}
}

func BenchmarkWireGuardObfuscator_Deobfuscate(b *testing.B) {
	var obfuscator WireGuardObfuscator

	obfuscator.Initialize("test")
	var p Packet
	p.Data[0] = 4
	p.Data[1] = 0
	p.Data[2] = 0
	p.Data[3] = 0
	p.Length = 1500
	_, _ = rand.Read(p.Data[4:p.Length])
	p.Flags |= PacketFlagObfuscateBeforeSend
	obfuscator.Obfuscate(&p)

	originPacket := p

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		p = originPacket
		b.StartTimer()
		obfuscator.Deobfuscate(&p)
	}
}
