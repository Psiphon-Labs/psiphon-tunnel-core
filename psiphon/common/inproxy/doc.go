/*
 * Copyright (c) 2023, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*
Package inproxy enables 3rd party, ephemeral proxies to help Psiphon clients
connect to the Psiphon network.

The in-proxy architecture is inspired by and similar to Tor's snowflake
pluggable transport, https://snowflake.torproject.org/.

With in-proxy, Psiphon clients are matched with proxies by brokers run by the
Psiphon network.

In addition to proxies in unblocked regions, proxies in blocked regions are
supported, to facilitate the use cases such as a local region hop from a
mobile ISP, where international traffic may be expensive and throttled, to a
home ISP, which may be less restricted.

The proxy/server hop uses the full range of Psiphon tunnel protocols,
providing blocking circumvention on the 2nd hop.

Proxies don't create Psiphon tunnels, they just relay either TCP or UDP flows
from the client to the server, where those flows are Psiphon tunnel
protocols. Proxies don't need to be upgraded in order to relay newer Psiphon
tunnel protocols or protocol variants.

Proxies cannot see the client traffic within the relayed Psiphon tunnel.
Brokers verify that client destinations are valid Psiphon servers only, so
proxies cannot be misused for non-Psiphon relaying.

To limit the set of Psiphon servers that proxies can observe and enumerate,
client destinations are limited to the set of servers specifically designated
with in-proxy capabilities. This is enforced by the broker.

Proxies are compartmentalized in two ways; (1) personal proxies will use a
personal compartment ID to limit access to clients run by users with whom the
proxy operator has shared, out-of-band, a personal compartment ID, or access
token; (2) common proxies will be assigned a common compartment ID by the
Psiphon network to limit access to clients that have obtained the common
compartment ID, or access token, from Psiphon through channels such as
targeted tactics or embedded in OSLs.

Proxies are expected to be run for longer periods, on desktop computers. The
in-proxy design does not currently support browser extension or website
widget proxies.

The client/proxy hop uses WebRTC, with the broker playing the role of a WebRTC
signaling server in addition to matching clients and proxies. Clients and
proxies gather ICE candidates, including any host candidates, IPv4 or IPv6,
as well as STUN server reflexive candidates. In addition, any available port
mapping protocols -- UPnP-IGD, NAT-PMP, PCP -- are used to gather port
mapping candidates, which are injected into ICE SDPs as host candidates. TURN
candidates are not used.

NAT topology discovery is performed and metrics sent to broker to optimize
utility and matching of proxies to clients. Mobile networks may be assumed to
be CGNAT in case NAT discovery fails or is skipped. And, for mobile networks,
there is an option to skip discovery and STUN for a faster dial.

The client-proxy is a WebRTC data channel; on the wire, it is DTLS, preceded
by an ICE STUN packet. By default, WebRTC DTLS is configured to look like
common browsers. In addition, the DTLS ClientHello can be randomized. Proxy
endpoints are ephemeral, but if they were to be scanned or probed, the
response should look like common WebRTC stacks that receive packets from
invalid peers.

Clients and proxies connect to brokers via a domain fronting transport; the
transport is abstracted and other channels may be provided. Within that
transport, a Noise protocol framework session is established between
clients/proxies and a broker, to ensure privacy, authentication, and replay
defense between the end points; not even a domain fronting CDN can observe
the transactions within a session. The session has an additional obfuscation
layer that renders the messages as fully random, which may be suitable for
encapsulating in plaintext transports;  adds random padding; and detects
replay of any message.

For clients and proxies, all broker and WebRTC dial parameters, including
domain fronting, STUN server selection, NAT discovery behavior, timeouts, and
so on are remotely configurable via Psiphon tactics. Callbacks facilitate
replay of successful dial parameters for individual stages of a dial,
including a successful broker connection, or a working STUN server.

For each proxied client tunnel, brokers use secure sessions to send the
destination Psiphon server a message indicating the proxy ID that's relaying
the client's traffic, the original client IP, and additional metrics to be
logged with the server_tunnel log for the tunnel. Neither a client nor a
proxy is trusted to report the original client IP or the proxy ID.

Instead of having the broker connect out to Psiphon servers, and trying to
synchronize reliable arrival of these messages, the broker uses the client to
relay secure session packets -- the message, preceded by a session handshake
if required -- inline, in the client/broker and client/server tunnel
connections. These session packets piggyback on top of client/broker and
client/server round trips that happen anyway, including the Psiphon API
handshake.

Psiphon servers with in-proxy capabilities should be configured, on in-proxy
listeners, to require receipt of this broker message before finalizing
traffic rules, issuing tactics, issuing OSL progress, or allowing traffic
tunneling. The original client IP reported by the broker should be used for
all client GeoIP policy decisions and logging.

The proxy ID corresponds to the proxy's secure session public key; the proxy
proves possession of the corresponding private key in the session handshake.
Proxy IDs are not revealed to clients; only to brokers and Psiphon servers. A
proxy may maintain a long-term key pair and corresponding proxy ID, and that
may be used by Psiphon to assign reputation to well-performing proxies or to
issue rewards for proxies.

Each secure session public key is an Ed25519 public key. This public key is
used for signatures, including the session reset token in the session
protocol. This signing key may also be used, externally, in a
challenge/response registration process where a proxy operator can
demonstrate ownership of a proxy public key and its corresponding proxy ID.
For use in ECDH in the Noise protocol, the Ed25519 public key is converted to
the corresponding, unique Curve25519 public key.

Logged proxy ID values will be the Curve25519 representation of the public
key. Since Curve25519 public keys don't uniquely map back to Ed25519 public
keys, any external proxy registration system should store the Ed25519 public
key and derive the corresponding Curve25519 when mapping server tunnel proxy
IDs back to the Ed25519 proxy public key.

The proxy is designed to be bundled with the tunnel-core client, run
optionally, and integrated with its tactics, data store, and logging. The
broker is designed to be bundled with the Psiphon server, psiphond, and, like
tactics requests, run under MeekServer; and use the tactics, psinet database,
GeoIP services, and logging services provided by psiphond.
*/
package inproxy
