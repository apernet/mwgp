Multi-WireGuard Proxy
===============

## Overview

Running multiple WireGuard interfaces with `AllowedIPs=0.0.0.0/0, ::0` over one
UDP port, powered by [WireGuard Index Translation](./PRINCIPLES.md).

This project is internally used in haruue-net to reduce the ports requirement
of some mystery traffic forwarding services.

DF (Don't Fragment) in the IP header is always removed since I don't like it.


## Installation

```bash
go install github.com/haruue-net/mwgp/cmd/mwgp@latest
```


## Usage

```
mwgp [server|client] config.json
```

### Server configuration

```json5
{
  "listen": ":1000",  // Listen address
  "timeout": 60,      // Timeout before a forward entry expired
  "servers": [
    {
      "privkey": "EFt3ELmZeM/M47qFkgF4RbSOijtdHS43BNIxvxstREI=", // The private key of server, required to decrypt the handshake_initiation message for the public_key of client.
      "address": "192.0.2.1", // the IP address of the server, concat with the peer.forward_to for a completed udp address.
      "peers": [
        { 
          "pubkey": "mCXTsTRyjQKV74eWR2Ka1LIdIptCG9K0FXlrG2NC4EQ=", // The public key of client which connect to the "forward_to" WireGuard interface.
          "forward_to": ":1000" // The endpoint of the target WireGuard interface, the server.address would be used if the IP address part omitted.
        },
        { "pubkey": "qKqIuUkQztLxY7Ounki8HXHcjy+S5AwAjTQvR77wf1E=", "forward_to": ":1001" },
        { "pubkey": "WKn3Dtne0ZYj/BXa6uzqMVU+xrLIQRsPA/F/SkgFsVY=", "forward_to": "192.0.2.2:1002" },
        { 
          // If the "pubkey" is not specified, this peer will become a "fallback" peer for unmatched public key, this is useful for edge connections.
          "forward_to": ":1003"
        }
      ]
    },
    {
      "privkey": "6GwcQf52eLIBckRygN+LaW3SfVpv4/Lc4kUyVkYfIkg=",
      "address": "192.0.2.3",
      "peers": [
        { "pubkey": "eHXJlZTNeFf6J8z0qbFKth7RmtweAaWpFOKW4ACGSlc=", "forward_to": ":1000" },
        { "forward_to": ":1001" }
      ]
    }
  ]
}
```


### Client configuration

An mwgp client is no longer required for mwgp v2, as you can directly connect
to the mwgp endpoint with official WireGuard implementation.

The client is kept for features like specifying the DNS server for server
address resolution, and WireGuard traffic obfuscation.

```json5
{
  "server": "192.0.2.1:1000", // The endpoint of mwgp server
  "listen": "127.10.11.1:1000", // Listen address
  "timeout": 60, // Timeout before a forward entry expired
  "server_pubkey": "S6hPS4iuvUKmnH3fp1TssT95XsHY3E3L4hqMZ68TknA=", // The WireGuard public key of WireGuard server, to compute the MAC in the handshake messages. 
  "client_pubkey": "mCXTsTRyjQKV74eWR2Ka1LIdIptCG9K0FXlrG2NC4EQ=", // The WireGuard public key of WireGuard client, to compute the MAC in the handshake messages. 
  "dns": "8.8.8.8:53" // the DNS server used to resolve the server address
}
```


