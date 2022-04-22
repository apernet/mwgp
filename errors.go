package mwgp

import "fmt"

type ErrInvalidPeerID struct {
	ID int
}

func (e ErrInvalidPeerID) Error() string {
	return fmt.Sprintf("invalid peer id: %d", e.ID)
}

type ErrResolveAddr struct {
	Type  string
	Addr  string
	Cause error
}

func (e ErrResolveAddr) Error() string {
	return fmt.Sprintf("failed to resolve %s address %s: %s", e.Type, e.Addr, e.Cause.Error())
}

type ErrPacketTooShort struct {
	Length int
}

func (e ErrPacketTooShort) Error() string {
	return fmt.Sprintf("packet too short: len=%d", e.Length)
}
