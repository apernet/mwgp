package mwgp

import (
	"encoding/binary"
	"fmt"
	"golang.zx2c4.com/wireguard/device"
	"net"
)

const (
	defaultMaxPacketSize = 65536
)

const (
	PacketFlagDeobfuscatedAfterReceived = 1 << iota
	PacketFlagObfuscateBeforeSend
)

type Packet struct {
	Data        []byte
	Length      int
	Source      *net.UDPAddr
	Destination *net.UDPAddr
	Flags       uint64
}

func (p *Packet) Reset() {
	//p.Data = [kMTU]byte{}
	p.Length = 0
	p.Source = nil
	p.Destination = nil
	p.Flags = 0
}

func (p *Packet) Slice() []byte {
	return p.Data[:p.Length]
}

func (p *Packet) MessageType() int {
	if p.Length < 1 {
		return -1
	}
	return int((p.Data)[0])
}

func (p *Packet) ReceiverIndex() (index uint32, err error) {
	messageType := p.MessageType()
	switch messageType {
	case device.MessageInitiationType:
		index, err = p.getLEUint32Offset(8)
	case device.MessageResponseType:
		index, err = p.getLEUint32Offset(8)
	case device.MessageCookieReplyType:
		index, err = p.getLEUint32Offset(4)
	case device.MessageTransportType:
		index, err = p.getLEUint32Offset(4)
	default:
		err = fmt.Errorf("cannot get receiver_index for message type %d", messageType)
	}
	return
}

func (p *Packet) SetSenderIndex(index uint32) (err error) {
	messageType := p.MessageType()
	switch messageType {
	case device.MessageInitiationType:
		err = p.putLEUint32Offset(4, index)
	case device.MessageResponseType:
		err = p.putLEUint32Offset(4, index)
	default:
		err = fmt.Errorf("cannot set sender_index for message type %d", messageType)
	}
	return
}

func (p *Packet) SetReceiverIndex(index uint32) (err error) {
	messageType := p.MessageType()
	switch messageType {
	case device.MessageInitiationType:
		err = p.putLEUint32Offset(8, index)
	case device.MessageResponseType:
		err = p.putLEUint32Offset(8, index)
	case device.MessageCookieReplyType:
		err = p.putLEUint32Offset(4, index)
	case device.MessageTransportType:
		err = p.putLEUint32Offset(4, index)
	default:
		err = fmt.Errorf("cannot set receiver_index for message type %d", messageType)
	}
	return
}

func (p *Packet) getLEUint32Offset(bytesOffset int) (value uint32, err error) {
	if p.Length < bytesOffset+4 {
		err = fmt.Errorf("packet is too short to get uint32 at offset %d", bytesOffset)
		return
	}
	value = binary.LittleEndian.Uint32(p.Data[bytesOffset:])
	return
}

func (p *Packet) putLEUint32Offset(bytesOffset int, value uint32) (err error) {
	if p.Length < bytesOffset+4 {
		err = fmt.Errorf("packet is too short to put uint32 at offset %d", bytesOffset)
		return
	}
	binary.LittleEndian.PutUint32(p.Data[bytesOffset:], value)
	return
}

func (p *Packet) FixMACs(cg *device.CookieGenerator) {
	cg.AddMacs(p.Slice())
}
