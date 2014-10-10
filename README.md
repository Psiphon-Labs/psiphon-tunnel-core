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

* pendingConns lifecycle issue: MeekConn's dialer uses the establishTunnel pendingConns, which means there's
  a chance that the asynchronous pendingConns.Interrupt() by establishTunnel will close a meek HTTPS conn. Also,
  MeekConn is holding a reference to this pendingConns long after establishTunnel finishes.
  fix: MeekConn should keep its own PendingConns for underlying HTTPS connections; MeekConn should go into the
  establish pendingConns and when it closes, it should in turn close its own pendingConns.
  ...And the same for serverApi.
* ResponseHeaderTimeout is not sufficient to detect dead tunneled web requests
  fix: use DirectDialer with all timeouts set, use dedicated pendingConns (see above)
* prefilter entries by capability; don't log "server does not have sufficient capabilities"
* log noise: "use of closed network connection"
* log noise(?): 'Unsolicited response received on idle HTTP channel starting with "H"'
* use ContextError in more places
* build/test on Android and iOS
* disconnect all local proxy clients when tunnel disconnected
* add connection and idle timeouts to proxied connections where appropriate

### TODO (future)

* SOCKS5 support
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
