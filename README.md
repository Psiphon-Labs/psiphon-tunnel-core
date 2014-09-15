Psiphon 3 Tunnel Core README
================================================================================

Overview
--------------------------------------------------------------------------------

A Psiphon client component implemented in Go. This component provide core tunnel functionality, handling all aspects of connecting to Psiphon servers and relaying traffic through those servers. Local proxies provide an interface for routing traffic through the tunnel.

This component does not include a UI and does not handle capturing or routing local traffic. These major aspects are handled by other parts of Psiphon client applications.

Status
--------------------------------------------------------------------------------

This project is currently at the proof-of-concept stage. Current production Psiphon client code is available at our [main repository](https://bitbucket.org/psiphon/psiphon-circumvention-system).

### TODO
* SSH variable length random padding in KEX phase
* more test cases
* integrate meek-client
* add config options
  * protocol preference; whether to try multiple protocols for each server
  * region preference
  * platform (for upgrade download)
* SSH keepalive (+ hook into disconnectedSignal)
* SSH compression?
*  local SOCKS
  * disconnect all local clients when tunnel disconnected
  * use InterruptableConn?
* run fetchRemoteServerList in parallel when already have entries
* add a HTTP proxy (chain to SOCKS)
* persist server entries
* add Psiphon web requests: handshake/connected/etc.
* implement page view stats
* implement local traffic stats (e.g., to display bytes sent/received
* build/test on Android and iOS
* control interface (w/ event messages)?
* VpnService compatibility
* upstream proxy support
* support upgrades
  * download entire client
  * download core component only
* consider ability to multiplex across multiple tunnel sessions
* support a "pushedNetworkConfig"
  * server can push preferred/optimized settings; client should use over defaults
  * e.g., etablish worker pool size; multiplex tunnel pool size


Licensing
--------------------------------------------------------------------------------

Please see the LICENSE file.


Contacts
--------------------------------------------------------------------------------

For more information on Psiphon Inc, please visit our web site at:

[www.psiphon.ca](http://www.psiphon.ca)
