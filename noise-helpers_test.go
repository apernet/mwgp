package mwgp

import "testing"

func TestNoiseKeys(t *testing.T) {
	var err error
	var sk NoisePrivateKey
	err = sk.FromBase64("aBLEHM1Kd8yCNQb8GSCWhbcnyJEiK00Uvw3QkGzAz0A=")
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.PublicKey()
	t.Logf("sk: %s\n", sk.Base64())
	t.Logf("pk: %s\n", pk.Base64())
	var exceptedPubKey NoisePublicKey
	err = exceptedPubKey.FromBase64("M7ELnm0etoIwGjofdKjM+1UjRH+bdf4daQzfA2Zb5ng=")
	if err != nil {
		t.Fatal(err)
	}
	if pk != exceptedPubKey {
		t.Fatal("public key mismatch")
	}
}
