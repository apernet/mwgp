Multiple WireGuard Proxy
===============

mwgp is a WireGuard proxy designed to reuse one UDP port for multiple WireGuard
interfaces.

It is useful if you want to run multiple WireGuard interfaces with
`AllowedIPs=0.0.0.0/0, ::/0` on a server that only has limited UDP ports
available.

This project is internally used in haruue-net to reduce the ports requirement
of some mystery traffic forwarding services.

This project also comes with an experimental traffic obfuscation (see below).


## How it works

See [PRINCIPLES.md](./PRINCIPLES.md).

TLDR: mwgp utilizes the server private key to decrypt and extract the client
public key from the handshake initiation, distinguishes every WireGuard peer by
sender and receiver index in the WireGuard protocol, and forwards them by
matching rules with the client public key from handshake initiation. mwgp also
comes with a feature named "WGIT", which solves the conflict of sender and
receiver index.


## Install

```bash
go install github.com/haruue-net/mwgp/cmd/mwgp@latest
```

For Arch Linux users, we also maintain a 
[PKGBUILD in the AUR](https://aur.archlinux.org/packages/mwgp).


## Usage

```
mwgp [server|client] config.json
```

### Server config

```json5
{
  "listen": ":1000",  // Listen address
  "timeout": 60,      // Timeout before a forward entry expired, in seconds
  "servers": [
    {
      "privkey": "EFt3ELmZeM/M47qFkgF4RbSOijtdHS43BNIxvxstREI=", // The private key of server, required to decrypt the handshake_initiation message for the public_key of client.
      "address": "192.0.2.1", // the IP address of the server, would be concated with the peer.forward_to for a completed udp address.
      "peers": [
        { 
          "pubkey": "mCXTsTRyjQKV74eWR2Ka1LIdIptCG9K0FXlrG2NC4EQ=", // The public key of client who want to connect to the WireGuard interface listening on the "forward_to" address.
          "forward_to": ":1000" // The endpoint of the target WireGuard interface, the server.address will be used if the IP address part get omitted.
        },
        { 
          "pubkey": "WKn3Dtne0ZYj/BXa6uzqMVU+xrLIQRsPA/F/SkgFsVY=",
          "forward_to": "192.0.2.2:1002" // You can also specified a completed address if you want to forward to another host other than the server.address.
        },
        { 
          // If the "pubkey" is not specified, this peer will become a "fallback" peer for all unmatched public key, this is useful for edge connections.
          "forward_to": ":1003"
        }
      ]
    },
    {
      // You can forward for more than one server with different private keys.
      "privkey": "6GwcQf52eLIBckRygN+LaW3SfVpv4/Lc4kUyVkYfIkg=",
      "address": "192.0.2.3",
      "peers": [
        { 
          // As a privkey-pubkey pair defines a peer, a pubkey appear in other server can be appear again.
          "pubkey": "mCXTsTRyjQKV74eWR2Ka1LIdIptCG9K0FXlrG2NC4EQ=",
          "forward_to": ":1000" 
        }
      ]
    }
  ],
  "obfs": "kisekimo, mahoumo, muryoudewaarimasen" // Obfuscation password (optional)
}
```


### Client config

The mwgp-client provides features like specifying customized DNS server for
server address resolution, and WireGuard traffic obfuscation.

If you do not need these feature, you actually do not need to run mwgp-client,
as you can directly connect to the mwgp-server endpoint with official WireGuard
implementation.

```json5
{
  "server": "192.0.2.1:1000", // The endpoint of mwgp server
  "listen": "127.10.11.1:1000", // Listen address
  "timeout": 60,      // Timeout before a forward entry expired, in seconds
  "server_pubkey": "S6hPS4iuvUKmnH3fp1TssT95XsHY3E3L4hqMZ68TknA=", // The WireGuard public key of WireGuard server, used in MAC computation in the handshake messages. 
  "client_pubkey": "mCXTsTRyjQKV74eWR2Ka1LIdIptCG9K0FXlrG2NC4EQ=", // The WireGuard public key of WireGuard client, used in MAC computation in the handshake messages. 
  "dns": "8.8.8.8:53", // the DNS server used to resolve the server address (optional)
  "obfs": "kisekimo, mahoumo, muryoudewaarimasen" // Obfuscation password (optional)
}
```


### Forward Table Cache

mwgp stores its forward table on disk to persist the forward status across
restarts, otherwise, every time when mwgp restarts would cause a disconnect for
1~2 minutes.

The disk cache file is under the user cache directory by default and can be
specified with `--cache-file` options and `MWGP_CACHE_FILE` environment
variable.

Please note some configs, such as forward target and obfuscation, are also
cached as the forward table status. so if you modify those configs, it might
not take effect until the WireGuard client sends the next handshake initiation.
WireGuard sends handshake initiation once around 2 minutes, you can also
restart the WireGuard client manually to make it resend the handshake
initiation immediately.


### Traffic obfuscation (experimental)

> **Note**
> 
> Traffic obfuscation is still an experimental feature, if you want to try it,
> please make sure you are using the **exact same version** of mwgp-client
> and mwgp-server.

mwgp provides traffic obfuscation for WireGuard which helps you bypass
packet-inspection-based QoS.

Highlights of mwgp obfuscation:

+ Zero MTU overhead.
+ Appending random bytes (as well as whole message obfuscation) for
  `MessageInitiation`, `MessageResponse` and `MessageCookieReply`
  to randomize their length.
+ As for `MessageTransport`, mwgp only obfuscates the first 16 bytes header for
  maximized performance, as the remaining payload is already encrypted by
  chacha20-poly1305.
+ An mwgp-server with obfuscation enabled still accepts non-obfuscated clients,
  this is useful for some devices that cannot simply run mwgp-client (for
  example, connect from the official WireGuard Android/iOS app).

