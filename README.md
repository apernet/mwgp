Multiple WireGuard Proxy
===============

mwgp is a WireGuard proxy designed to reuse one UDP port for multiple WireGuard
interfaces, and still can be connected with the original WireGuard
implementation.

It is useful if you want to run multiple WireGuard interfaces with
`AllowedIPs=0.0.0.0/0, ::/0` on a server that only has limited UDP ports
available.

This project is internally used in haruue-net to reduce the ports requirement
of some mystery traffic forwarding services.

This project also comes with an experimental traffic obfuscation (see below).


## How it works

See [PRINCIPLES.md](./PRINCIPLES.md).

TLDR: mwgp utilizes the server-side private key to decrypt and extract the
client-side public key from the handshake initiation messages, distinguishes
every WireGuard peer by sender and receiver index in the WireGuard protocol,
and forwards them by matching rules with the client-side public key. mwgp also
solves the sender and receiver index conflict with a mechanism named "WGIT".


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
  "timeout": 60,      // Timeout before a forwarding entry expired, in seconds
  "servers": [
    {
      "privkey": "EFt3ELmZeM/M47qFkgF4RbSOijtdHS43BNIxvxstREI=", // The private key of the WireGuard server, which is required to decrypt the handshake_initiation message for the public_key of the client
      "address": "192.0.2.1", // The IP address of the WireGuard server, which would be combined with the peer."forward_to" for a completed UDP address
      "peers": [
        {
          "pubkey": "mCXTsTRyjQKV74eWR2Ka1LIdIptCG9K0FXlrG2NC4EQ=", // The public key of the client who would be connected to the WireGuard interface listening on the "forward_to" address
          "forward_to": ":1000" // The endpoint of the server WireGuard, will be combined with the server."address" if the IP address part gets omitted
        },
        {
          "pubkey": "WKn3Dtne0ZYj/BXa6uzqMVU+xrLIQRsPA/F/SkgFsVY=",
          "forward_to": "192.0.2.2:1002" // A complete UDP address will also be accepted, for forwarding to another host other than the server."address"
        },
        {
          // If the "pubkey" is not specified, it will define a "fallback" peer which matches any unmatched public keys, this is useful for edge nodes
          "forward_to": ":1003"
        }
      ]
    },
    {
      // Servers with different private keys can be defined in one mwgp-server and share the listen port
      "privkey_file": "/etc/wireguard/private/privkey", // As an alternative to the "privkey", you can also load it from a file, just like PrivateKeyFile= in the systemd.network(5)
      "address": "192.0.2.3",
      "peers": [
        {
          // A client can be defined again with the same public key for another server
          "pubkey": "mCXTsTRyjQKV74eWR2Ka1LIdIptCG9K0FXlrG2NC4EQ=",
          "forward_to": ":1000"
        },
        {
          "pubkey": "OPdP2G4hfQasp/+/AZ6LiHJXIY62UKQQY4iNHJVJwH4=",
          "forward_to": ":1001"
        }
      ]
    }
  ],
  "obfs": "kisekimo, mahoumo, muryoudewaarimasen" // Obfuscation password (optional)
}
```


### Client config

> **Note**
>
> You can connect to the mwgp-server endpoint directly with the official
> WireGuard implementation.

The mwgp-client provides features like specifying customized DNS server for
server address resolving, and WireGuard traffic obfuscation.

If you do not need these features, you actually do not need to run mwgp-client,
as you can directly connect to the mwgp-server endpoint with official WireGuard
implementation.

```json5
{
  "server": "192.0.2.1:1000", // The endpoint of mwgp-server
  "listen": "127.10.11.1:1000", // Listen address
  "timeout": 60,      // Timeout before a forwarding entry expired, in seconds
  "server_pubkey": "S6hPS4iuvUKmnH3fp1TssT95XsHY3E3L4hqMZ68TknA=", // The public key of the WireGuard server, required by MAC computation for the handshake messages
  "client_pubkey": "mCXTsTRyjQKV74eWR2Ka1LIdIptCG9K0FXlrG2NC4EQ=", // The public key of the WireGuard client, required by MAC computation for the handshake messages
  "dns": "8.8.8.8:53", // The DNS server for server address resolving (optional)
  "obfs": "kisekimo, mahoumo, muryoudewaarimasen" // Obfuscation password (optional)
}
```


### Forwarding Table Cache

mwgp stores its forwarding table on the disk to persist the forwarding status
across restarts, otherwise, every time when mwgp restarts would cause all
WireGuard peers it forwards disconnect for 1~2 minutes.

The disk cache file is under the user cache directory by default and can be
specified with `--cache-file` options and `MWGP_CACHE_FILE` environment
variable.

Please note some configs, such as forwarding target and obfuscation, are also
cached as the forwarding status. So if you modify those configs, it might not
take effect until the WireGuard client sends the next handshake initiation.
WireGuard sends handshake initiation once around 2 minutes, you can also
restart the WireGuard client manually to make it resend the handshake
initiation immediately.


### Traffic obfuscation (experimental)

> **Note**
>
> Traffic obfuscation is still an experimental feature, if you want to try it,
> please make sure you are using the **exact same version** of mwgp-client
> and mwgp-server.

mwgp comes with a built-in traffic obfuscation which helps you bypass
packet-inspection-based QoS. It can be enabled by setting an obfuscation
password in the server and client configs.

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

