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
Package shadowsocks implements the Shadowsocks secure transport and proxy protocols.

Shadowsocks is a a combination of two protocols:
  - [Encrypted transport]: uses authenticated encryption for privacy and security. Traffic appears random to avoid detection,
    with no distinguishable pattern or markers.
  - [Proxy protocol]: a simplified [SOCKS5]-like protocol for routing TCP and UDP connections to various destinations.

# Setting up Shadowsocks Servers

When using Shadowsocks, you will need a server. There are many ways to run Shadowsocks servers. We recommend:

  - [Outline Manager app]: The easiest way to create and manage Shadowsocks servers in the cloud.
  - [outline-ss-server]: A command-line tool for advanced users offering greater configuration flexibility.

# IPv6 Limitations

The Shadowsocks proxy protocol lacks a mechanism for servers to signal successful connection to a destination.
For that reason, the [StreamDialer] immediately returns a connection
once the TCP connection to the proxy is established, but before the connection to the destination by the proxy happens.

This is fine for dialed addresses that use a host name, since the name resolution will happen in the proxy, and the proxy
will handle address selection for the client. That is usually the case for proxy apps. However in VPN apps using a "tun2socks" approach,
the client is doing the name resolution and address selection, dialing using IP addresses. Because the dialer returns a successful connection
regardless of the destination connectivity, this breaks the Happy Eyeballs address selection, effectively breaking IPv6 support.

It's recommended that you prioritize hostname-based dialing for optimal IPv6 compatibility, and disable IPv6 if name resolution and address selection
happens on the client side, as is the case of VPN apps.

# Security Considerations

Shadowsocks uses strong authenticated encryption (AEAD), standardized by the IETF. For privacy and security, this package does not support the legacy and unsafe [stream ciphers].

Shadowsocks does not provide forward-secrecy. That can be accomplished by generating a new,
completely random secret for every session, and delivering it to the client in a forward-secret way.
With Outline, that can be done via [Dynamic Keys]: when the Dynamic Key is requested, generate a new secret.
The response is sent over TLS, which implements forward-secrecy.

[SOCKS5]: https://datatracker.ietf.org/doc/html/rfc1928
[Outline Manager app]: https://getoutline.org/get-started/#step-1
[outline-ss-server]: https://github.com/Jigsaw-Code/outline-ss-server?tab=readme-ov-file#how-to-run-it
[Encrypted transport]: https://shadowsocks.org/doc/aead.html
[Proxy protocol]: https://shadowsocks.org/doc/what-is-shadowsocks.html
[stream ciphers]: https://shadowsocks.org/doc/stream.html
[Dynamic Keys]: https://www.reddit.com/r/outlinevpn/wiki/index/dynamic_access_keys/
*/
package shadowsocks
