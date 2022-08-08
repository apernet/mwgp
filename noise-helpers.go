package mwgp

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
	"os"
	"strconv"
)

// non-exported functions copied from wireguard-go

type devicexType struct{}

var devicex devicexType

func (devicexType) mixKey(dst, c *[blake2s.Size]byte, data []byte) {
	device.KDF1(dst, c[:], data)
}

func (devicexType) mixHash(dst, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func (devicexType) isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

type NoisePublicKey struct {
	device.NoisePublicKey
}

func (pk *NoisePublicKey) MarshalJSON() (result []byte, err error) {
	if pk.NoisePublicKey.IsZero() {
		result = []byte("null")
		return
	}
	base64Str := pk.Base64()
	jsonStr := strconv.Quote(base64Str)
	result = []byte(jsonStr)
	return
}

func (pk *NoisePublicKey) UnmarshalJSON(bytes []byte) (err error) {
	base64Str, err := strconv.Unquote(string(bytes))
	if err != nil {
		return
	}
	if base64Str == "" {
		err = fmt.Errorf("encoded public key is empty")
		return
	}
	err = pk.FromBase64(base64Str)
	if err != nil {
		return
	}
	return
}

func (pk *NoisePublicKey) FromBase64(s string) (err error) {
	bs, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return
	}
	if len(bs) != device.NoisePublicKeySize {
		return fmt.Errorf("public key has wrong length: %d", len(bs))
	}
	copy(pk.NoisePublicKey[:], bs)
	return
}

func (pk *NoisePublicKey) Base64() (s string) {
	s = base64.StdEncoding.EncodeToString(pk.NoisePublicKey[:])
	return
}

type NoisePrivateKey struct {
	device.NoisePrivateKey
}

func (sk *NoisePrivateKey) MarshalJSON() (result []byte, err error) {
	base64Str := sk.Base64()
	jsonStr := strconv.Quote(base64Str)
	result = []byte(jsonStr)
	return
}

func (sk *NoisePrivateKey) UnmarshalJSON(bytes []byte) (err error) {
	hexStr, err := strconv.Unquote(string(bytes))
	if err != nil {
		return
	}
	if hexStr == "" {
		err = fmt.Errorf("encoded private key is empty")
		return
	}
	err = sk.FromBase64(hexStr)
	if err != nil {
		return
	}
	return
}

func (sk *NoisePrivateKey) FromBase64(s string) (err error) {
	bs, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return
	}
	if len(bs) != device.NoisePrivateKeySize {
		return fmt.Errorf("public key has wrong length: %d", len(bs))
	}
	copy(sk.NoisePrivateKey[:], bs)
	return
}

func (sk *NoisePrivateKey) Base64() (s string) {
	s = base64.StdEncoding.EncodeToString(sk.NoisePrivateKey[:])
	return
}

func (sk *NoisePrivateKey) ReadFromFile(path string) (err error) {
	exampleKey := "YCV5jh4xfuA4vq+TXYs/BdRT3c+EEgKVy0f1pcvEBlk="

	if path == "" {
		err = fmt.Errorf("no key file path provided")
		return
	}

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	bs := make([]byte, len(exampleKey))
	_, err = f.Read(bs)
	if err != nil {
		return
	}

	err = sk.FromBase64(string(bs))
	if err != nil {
		return
	}

	return
}

func (sk *NoisePrivateKey) PublicKey() (pk NoisePublicKey) {
	apk := (*[device.NoisePublicKeySize]byte)(&pk.NoisePublicKey)
	ask := (*[device.NoisePrivateKeySize]byte)(&sk.NoisePrivateKey)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

func (sk *NoisePrivateKey) SharedSecret(pk device.NoisePublicKey) (ss [blake2s.Size]byte) {
	apk := (*[device.NoisePublicKeySize]byte)(&pk)
	ask := (*[device.NoisePrivateKeySize]byte)(&sk.NoisePrivateKey)
	curve25519.ScalarMult(&ss, ask, apk)
	return
}
