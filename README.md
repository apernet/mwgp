Multi-WireGuard Proxy
===============

**This project is intended for internal use, a breaking changes would happen
anytime without any notice, please fork it if you need a stable release.**


## Overview

Run multiple (up to 256) WireGuard interfaces with `AllowedIPs=0.0.0.0/0, ::0`
over one UDP port with `reserved_zero[3]` in WireGuard protocol.

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

```json
{
  "listen": ":1000",
  "timeout": 60,
  "peers": [
    { "id": 1, "forward_to": "127.0.0.1:2001" },
    { "id": 2, "forward_to": "127.0.0.1:2002" },
    { "id": 3, "forward_to": "127.0.0.1:2003" },
    { "id": 4, "forward_to": "127.0.0.1:2004" }
  ]
}
```

+ `id` should be an integer that matches `0 <= id <= 255`.


### Client configuration

```json
{
  "server": "192.88.99.0:2001",
  "timeout": 60,
  "id": 1,
  "listen": "127.10.11.8:1000"
}
```

+ `id` and port in `server` should match corresponding fields in server
  configuration.

