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

It is interesting that both side of communication actually use the name of
themselves to find out who is the another side, this is useful in a multi-peers
WireGuard interface.

+ Client1 -> Server: Hey there, I am Alice (Sender)
+ Server -> Client1: Hello, Alice (Receiver), I am Bob (Sender).
+ Client2 -> Server: Hey, I am Alice (Sender)
+ Server -> Client2: Hi Alice (Receiver), I am Chad (Sender).

And then when the Server received a message calls himself as "Chad", he can
soon find out the message is sent from Client2 rather than Client1.

[1]: https://www.wireguard.com/protocol/


## Handshake and Proxy

Since Sender and Receiver is not encrypted in the protocol, a proxy can
distinguish every wireguard peering without decrypt any data packet. If the
proxy could decrypt the handshake initiation, it will be able to select the the
forward rules for every WireGuard peering by client public key.

+ Client1 -> Proxy: Hey there, I am Alice.
+ \*Proxy 
  + Accepted a handshake initiation from "Alice"
  + Decrypted the handshake data with server private key and extract the public key inside it.
  + Remembered forward every packet with "Alice" as Receiver to the sender of this handshake initiation.
  + Match rules with the public key, find out forward destination.
  + Forward the handshake initiation to the destination.
+ Proxy -> Server: Hey there, I am Alice.
+ Server -> Proxy: Hello, Alice, I am Bob.
+ \*Proxy
  + Accepted a handshake response from "Bob", the response is sent to "Alice".
  + Remembered forward every packet with "Bob" as Receiver to the sender of this handshake response.
  + Forward the handshake response to the sender of handshake initiation (the "Alice").

As the proxy remembered how to forward with the Receiver of every data packet,
the both side of communication would be able to talk with each other. 
However, the proxy will fail if two clients choose a same name (as the Sender).

+ Client1 -> Proxy: Hey there, I am Alice.
+ \*Proxy 
  + Remembered forward every packet with "Alice" as Receiver to the sender of this handshake initiation.
+ Client2 -> Proxy: Hey there, I am Alice.
+ \*Proxy
  + Remembered forward every packet with "Alice" as Receiver to ... WTF?

In the WireGuard protocol, both Sender and Receiver are random choosed uint32 numbers. 
The possibility of this conflict is actually a [birthday problem][2].

[2]: https://en.wikipedia.org/wiki/Birthday_problem


## WireGuard Index Translation

Thankfully the Sender and Receiver in the WireGuard protocol is not verified by
the encrypted part.

So the proxy may set the Sender (only need to re-compute the MAC of handshake
packets, which requires the PublicKey of both side), and modify the Receiver of
other subsequent data packets.
We call this WireGuard Index Translation (WGIT) for it similarity to the stateful NAT.

+ Client1 -> Proxy: Hey there, I am Alice.
+ \*Proxy 
  + Rename "Alice" to "Alice1"
  + Remembered forward every packet with "Alice1" as Receiver to the sender of this handshake initiation, and modify the Receiver to "Alice" before forward.
+ Proxy -> Server: Hey there, I am Alice1.
+ Server -> Proxy: Hi Alice1, I am Bob.
+ Proxy -> Client1: Hi Alice, I am Bob.
+ Client2 -> Proxy: Hey there, I am Alice.
+ \*Proxy
  + Remembered forward every packet with "Alice2" as Receiver to the sender of this handshake initiation, and modify the Receiver to "Alice" before forward.
+ Proxy -> Server: Hey there, I am Alice2.
+ Server -> Proxy: Hello Alice2, I am Chad.
+ Proxy -> Client2: Hello Alice, I am Chad.

And we also need a same index translation layer for the server side, since
index conflict may occur for both side.


## Limitations

mwgp needs public key in the handshake initiation to match the forward destination.
So if a mwgp server restarted (purged the whole forward table), all WireGuard
packet data will be dropped immediately until the client send another handshake initiation.
In the testing, this would interrupt the whole WireGuard connection for 10 seconds to 2 minutes
(this issue has been solved by forward table disk cache).

mwgp can only decrypt the handshake initiation, without the session key, we
cannot decrypt or validate any further data packet. This means when mwgp got a
data packet sent from an unknown source address, but with a known Receiver in
the forward table, mwgp will not be able to determine whether or not to trust it
(as well as modify the forward table to send further packet back to the sender).
If we trust it, an attacker may replay a packet from a different source address
to cause packet loss. And if we don't trust it, the roaming will stop working.

