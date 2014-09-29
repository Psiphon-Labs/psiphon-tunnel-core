Psiphon 3 Tunnel Core README
================================================================================

Overview
--------------------------------------------------------------------------------

A Psiphon client component implemented in Go. This component provide core tunnel functionality, handling all aspects of connecting to Psiphon servers and relaying traffic through those servers. Local proxies provide an interface for routing traffic through the tunnel.

This component does not include a UI and does not handle capturing or routing local traffic. These major aspects are handled by other parts of Psiphon client applications.

Status
--------------------------------------------------------------------------------

This project is currently at the proof-of-concept stage. Current production Psiphon client code is available at our [main repository](https://bitbucket.org/psiphon/psiphon-circumvention-system).

### TODO (proof-of-concept)

* shutdown results in log noise: "use of closed network connection"
* region preference
* use ContextError in more places
* psiphon.Conn for Windows
* build/test on Android and iOS
* integrate meek-client
* disconnect all local proxy clients when tunnel disconnected
* add connection and idle timeouts to proxied connections where appropriate
* log levels

### TODO (future)

* SSH keepalive
* SSH compression
* preemptive reconnect functionality
* implement page view stats
* implement local traffic stats (e.g., to display bytes sent/received
* control interface (w/ event messages)?
* VpnService compatibility
* upstream proxy support
* support upgrades
  * download entire client
  * download core component only
* support protocol preference
* try multiple protocols for each server (currently only tries one protocol per server)
* consider ability to multiplex across multiple tunnel sessions
* support a config pushed by the network
  * server can push preferred/optimized settings; client should prefer over defaults
  * e.g., etablish worker pool size; multiplex tunnel pool size
* overlap between httpProxy.go and socksProxy.go: refactor?

Licensing
--------------------------------------------------------------------------------

Please see the LICENSE file.


Contacts
--------------------------------------------------------------------------------

For more information on Psiphon Inc, please visit our web site at:

[www.psiphon.ca](http://www.psiphon.ca)
