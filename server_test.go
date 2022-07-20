package mwgp_test

import (
	_ "embed"
	"github.com/haruue-net/mwgp"
	json "github.com/yosuke-furukawa/json5/encoding/json5"
	"testing"
)

func TestServerConfigMarshal(t *testing.T) {
	var err error
	var sk mwgp.NoisePrivateKey
	err = sk.FromBase64("UAIk/C+zXnbmvYpoDmtdE4SXuxFe8bdE1Oa3FGA2VVE=")
	if err != nil {
		t.Fatal(err)
	}
	var pk1, pk2, pk3 mwgp.NoisePublicKey
	err = pk1.FromBase64("BQEK/C+zXnbmvYpoDmtdE4SXuxFe8bdE1Oa3FGA2VVE=")
	if err != nil {
		t.Fatal(err)
	}
	err = pk2.FromBase64("aLnqWMZbSG5jVOtubYyEjwFzPU9qhmHZKWI7vHWIF2k=")
	if err != nil {
		t.Fatal(err)
	}
	err = pk3.FromBase64("QEvSeYfcRQTL2gKdxIzviEv/voZu8V8k4XLxplJrZGI=")
	if err != nil {
		t.Fatal(err)
	}
	c := mwgp.ServerConfig{
		Listen:  ":2333",
		Timeout: 300,
		Servers: []*mwgp.ServerConfigServer{
			{
				PrivateKey: sk,
				Address:    "192.0.2.1",
				Peers: []*mwgp.ServerConfigPeer{
					{
						ForwardTo:                 ":1232",
						ClientSourceValidateLevel: 2,
						ServerSourceValidateLevel: 0,
						ClientPublicKey:           &pk1,
					},
					{
						ForwardTo:                 ":1233",
						ClientSourceValidateLevel: 2,
						ServerSourceValidateLevel: 0,
						ClientPublicKey:           &pk2,
					},
					{
						ForwardTo:                 "192.0.2.2:1233",
						ClientSourceValidateLevel: 0,
						ServerSourceValidateLevel: 0,
						ClientPublicKey:           &pk3,
					},
					{
						ForwardTo:                 ":1234",
						ClientSourceValidateLevel: 0,
						ServerSourceValidateLevel: 1,
						ClientPublicKey:           nil,
					},
				},
				ClientSourceValidateLevel: 0,
				ServerSourceValidateLevel: 2,
			},
		},
	}
	bs, err := json.MarshalIndent(&c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(bs))
}

//go:embed example.server.json
var exampleServerConfig []byte

func TestServerConfigUnmarshal(t *testing.T) {
	var err error
	var c mwgp.ServerConfig
	err = json.Unmarshal(exampleServerConfig, &c)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range c.Servers {
		err = s.Initialize()
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%#v\n", c)
	for _, s := range c.Servers {
		for _, p := range s.Peers {
			t.Logf("%#v\n", *p)
		}
	}
}
