Multiple WireGuard Proxy
===============

mwgp is a proxy software for WireGuard traffic that supports port multiplexing and experimental traffic obfuscation (see below). It is compatible with the official WireGuard client.

A common use case is to run multiple WireGuard instances on a single UDP port, each configured with `AllowedIPs=0.0.0.0/0, ::/0`.


## How it works

See [PRINCIPLES.md](./PRINCIPLES.md).

Summary: mwgp-server decrypts WireGuard handshake messages using the configured server-side private key. It is able to identify the sender of the handshake message by its public key. Then it records the corresponding sender index, which is always unencrypted, and forwards all subsequent data messages to the desired destination, according to this sender index. There is no need to decrypt data messages.
The sender index is generated locally, so there is a small chance of index conflict. mwgp resolves the conflict by a mechanism called WireGuard Index Translation.


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
  "timeout": 60,      // Timeout before a forwarding entry expires, in seconds
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
      "privkey_file": "/etc/wireguard/private/privkey", // As an alternative to the "privkey", you can also load it from a file, just like PrivateKeyFile= in the systemd.netdev(5)
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
> You can connect to a mwgp-server endpoint directly with the official
> WireGuard implementation.

The mwgp-client provides additional features: customized DNS server for
resolving the server address, and traffic obfuscation.

If you do not need these features, mwgp-client is not required since mwgp-server is compatible with official WireGuard clients.

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

### Forwarding Table Cache File

mwgp stores the forwarding table in a disk file to keep the forwarding rules persistent. Otherwise, a restart of mwgp would cause all peers to disconnect for 1~2 minutes, until new handshake messages are exchanged.

The cache file is under the user cache directory by default, and can be specified with the `--cache-file` option or the `MWGP_CACHE_FILE` environment variable.

Some configurations, such as forwarding destination and obfuscation settings, are also stored in the same file. As a result, the modification of these settings will not take effect until new handshake messages are exchanged.

Typically, a WireGuard initiator sends a handshake message every 2 minutes. You can always restart the client manually to send a handshake initiation message immediately.


### Traffic Obfuscation (experimental)

> **Note**
>
> Traffic obfuscation is still an experimental feature, if you want to try it,
> please make sure you are using **exact the same version** of mwgp-client
> and mwgp-server.

mwgp comes with a built-in traffic obfuscator which helps you bypass some DPI. Enable this feature by setting an obfuscation password on both ends.

Highlights of mwgp obfuscation:

+ Zero MTU overhead.
+ `MessageInitiation`, `MessageResponse` and `MessageCookieReply` messages are padded to a random length and then obfuscated.
+ First 16 bytes of `MessageTransport` are obfuscated. The remaining payload is already encrypted by chacha20-poly1305.
+ mwgp-server is still compatible with vanilla WireGuard clients even with the obfuscation setting enabled.
  This is very useful when some clients do not run mwgp-client.

