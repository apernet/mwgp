Principles & Limitations
===============

## WireGuard Protocol: Sender and Receiver

[WireGuard protocol][1] itself is a connection-less protocol, rather than using
the endpoint to distinguish different peers, both two sides of communication
assign an id for the WireGuard "connection", and tell each other in the
handshake (as `Sender`, just like "whom I am"). Then the `Sender` of another
side will be attached to every data packet sent to it (as `Receiver`). Consider
the WireGuard server and client are two people talking on the walkie-talkie.

+ Client: Hey there, I am Alice (Sender).
+ Server: Hello, Alice (Receiver), I am Bob (Sender).
+ Client: Alice (Receiver), there is a message for you...
+ Server: Bob (Receiver), there is a message for you...

It is interesting that both sides of communication actually use their own name
to find out who another side is, this is useful in a multi-peers WireGuard
interface.

+ Client1 -> Server: Hey there, I am Alice (Sender)
+ Server -> Client1: Hello, Alice (Receiver), I am Bob (Sender).
+ Client2 -> Server: Hey, I am Alice (Sender)
+ Server -> Client2: Hi Alice (Receiver), I am Chad (Sender).

And then when the Server received a message that calls him "Chad", he can soon
find out the message is sent from Client2 rather than Client1.

[1]: https://www.wireguard.com/protocol/


## Handshake and Proxy

Since Sender and Receiver are not encrypted in the protocol, a proxy can
distinguish every single WireGuard peer without decrypting any data packet. If
the proxy has the server-side private key which can be used to decrypt the
client-side public key from handshake initiation messages, it will be able to
select the forwarding rules for every single WireGuard peer.

+ Client1 -> Proxy: Hey there, I am Alice.
+ \*Proxy
  + Accepted a handshake initiation message from "Alice".
  + Decrypt the handshake initiation message with the server-side private key and extract the client-side public key inside it.
  + Save forwarding every packet with "Alice" as Receiver to the sender of this handshake initiation message into the forwarding table.
  + Match the in-config rules with the client-side public key, and find out the forwarding destination.
  + Forward this handshake initiation message to the destination server.
+ Proxy -> Server: Hey there, I am Alice.
+ Server -> Proxy: Hello, Alice, I am Bob.
+ \*Proxy
  + Accepted a handshake response message from "Bob", and the Receiver of this message is "Alice".
  + Save forwarding every packet with "Bob" as Receiver to the sender of this handshake response message into the forwarding table.
  + Find the Receiver "Alice" (the sender of the prior handshake initiation message) from the forwarding table and forward this handshake response message to her.

By maintaining such a forwarding table, the proxy will be able to correctly
forward every data packets to its Receiver. The WireGuard communication will be
able to establish.

However, such a proxy will fail if two or more clients choose the same Sender.

+ Client1 -> Proxy: Hey there, I am Alice.
+ \*Proxy
  + Save forwarding every packet with "Alice" as Receiver to the sender of this handshake initiation message into the forwarding table.
+ Client2 -> Proxy: Hey there, I am Alice.
+ \*Proxy
  + Save forwarding every packet with "Alice" as Receiver to ... WTF?

In the WireGuard protocol, both Sender and Receiver are randomly chosen uint32
numbers. The possibility of this conflict is actually a [birthday problem][2].

[2]: https://en.wikipedia.org/wiki/Birthday_problem


## WireGuard Index Translation

Thankfully, the Sender and Receiver in the WireGuard protocol are not verified
by the encrypted part.

So the proxy can set the Sender to another name (still need to re-compute the
MAC of handshake packets, which requires the PublicKey of both sides), and
modify the Receiver of other subsequent data packets.
We call this mechanism as WireGuard Index Translation (WGIT) for its similarity
to the stateful NAT.

+ Client1 -> Proxy: Hey there, I am Alice.
+ \*Proxy
  + Rename the "Alice" to "Alice1".
  + Save forwarding every packet with "Alice1" as Receiver to the sender of this handshake initiation message as well as set the Receiver back to "Alice" into the forwarding table.
+ Proxy -> Server: Hey there, I am Alice1.
+ Server -> Proxy: Hi Alice1, I am Bob.
+ Proxy -> Client1: Hi Alice, I am Bob.
+ Client2 -> Proxy: Hey there, I am Alice.
+ \*Proxy
  + Rename the "Alice" to "Alice2".
  + Save forwarding every packet with "Alice2" as Receiver to the sender of this handshake initiation message as well as set the Receiver back to "Alice" into the forwarding table.
+ Proxy -> Server: Hey there, I am Alice2.
+ Server -> Proxy: Hello Alice2, I am Chad.
+ Proxy -> Client2: Hello Alice, I am Chad.

The same index translation mechanism is also required for the server-side, as
this kind of conflict is actually not side related.


## Limitations

The mwgp-server needs the client-side public key in the handshake initiation
message to match the forward destination. Hence if the forwarding table is
purged accidentally (e.g. the mwgp-server is restarted), all following
WireGuard data packets will then be immediately dropped until the client sends
another handshake initiation message. In the testing, this would interrupt the
whole WireGuard connection for 10 seconds to around 2 minutes (this issue has
been solved by caching the forwarding table into the disk).

The server-side private key can only decrypt the handshake initiation message.
Without the session key, it cannot decrypt or validate the following packet.
Therefore if the mwgp-server received a data packet sent from a new source
address, but with a Receiver that is already in the forwarding table.
The mwgp-server will not be able to determine whether or not to trust it
(as well as update the forwarding table to forward the further data packet of
 the peer to the new source address).
If it does, an attacker will be able to send malicious data packets with a
current using Receiver but from another source address to modify our forwarding
table and cause packet loss.
And if it doesn't, the WireGuard roaming will stop working.

