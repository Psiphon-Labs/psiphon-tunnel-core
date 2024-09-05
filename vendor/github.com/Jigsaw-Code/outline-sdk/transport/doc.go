// Copyright 2024 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package transport has the core types to work with transport layer connections.

# Connections

Connections enable communication between two endpoints over an abstract transport. There are two types of connections:

  - Stream connections, like TCP and the SOCK_STREAM Posix socket type. They are represented by [StreamConn] objects.
  - Datagram connections, like UDP and the SOCK_DGRAM Posix socket type. They are represented by [net.Conn] objects.

We use "Packet" instead of "Datagram" in the method and type names related to datagrams because that is the convention in the Go standard library.

Each write and read on datagram connections represent a single datagram, while reads and writes on stream connections operate on byte sequences
that may be independent of how those bytes are packaged.

Stream connections offer CloseRead and CloseWrite methods, which allows for a half-closed state (like TCP).
In general, you communicate end of data ("EOF") to the other side of the connection by calling CloseWrite (TCP will send a FIN).
CloseRead doesn't generate packets, but it allows for releasing resources (e.g. a read loop) and to signal errors to the peer
if more data does arrive (TCP will usually send a RST).

Connections can be wrapped to create nested connections over a new transport. For example, a StreamConn could be over TCP,
over TLS over TCP, over HTTP over TLS over TCP, over QUIC, among other options.

# Dialers

Dialers enable the creation of connections given a host:port address while encapsulating the underlying transport or proxy protocol.
The [StreamDialer] and [PacketDialer] types create stream ([StreamConn]) and datagram ([net.Conn]) connections, respectively, given an address.

Dialers can also be nested. For example, a TLS Stream Dialer can use a TCP dialer to create a StreamConn backed by a TCP connection,
then create a TLS StreamConn backed by the TCP StreamConn. A SOCKS5-over-TLS Dialer could use the TLS Dialer to create the TLS StreamConn
to the proxy before doing the SOCKS5 connection to the target address.
*/
package transport
