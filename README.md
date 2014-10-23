Psiphon 3 Tunnel Core README
================================================================================

Overview
--------------------------------------------------------------------------------

A Psiphon client component implemented in Go. This component provide core tunnel functionality, handling all aspects of connecting to Psiphon servers and relaying traffic through those servers. Local proxies provide an interface for routing traffic through the tunnel.

This component does not include a UI and does not handle capturing or routing local traffic. These major aspects are handled by other parts of Psiphon client applications.

Status
--------------------------------------------------------------------------------

This project is currently at the proof-of-concept stage. Current production Psiphon client code is available at our [Psiphon 3 repository](https://bitbucket.org/psiphon/psiphon-circumvention-system).

Setup
--------------------------------------------------------------------------------

* Go 1.3 (or higher) is required.
* In this repository, run `go build` to make the `psiphon-tunnel-core` binary.
* Note that the `psiphon` package is imported using the absolute path `github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon`; without further local configuration, `go` will use this version of the code and not the local copy in the repository.
* This project builds and runs on recent versions of Windows, Linux, and Mac OS X.
* Run `./psiphon-tunnel-core --config psiphon.config` where the config file looks like this:
    ```json
    {
        "PropagationChannelId" : "<placeholder>",
        "SponsorId" : "<placeholder>",
        "RemoteServerListUrl" : "<placeholder>",
        "RemoteServerListSignaturePublicKey" : "<placeholder>",
        "LogFilename" : "",
        "LocalHttpProxyPort" : 0,
        "LocalSocksProxyPort" : 0,
        "EgressRegion" : "",
        "TunnelProtocol" : "",
        "ConnectionWorkerPoolSize" : 10
    }
    ```
* Replace each `<placeholder>` with a value from your Psiphon network. The Psiphon server-side stack is open source and can be found in our  [Psiphon 3 repository](repository). If you would like to use the Psiphon Inc. network, contact [developer-support@psiphon.ca](developer-support@psiphon.ca).
* The project builds and runs on Android. At this time, Android support is in the developer branch of Go, so build Go from source and use the Android NDK to build android/arm target support. See the sample AndroidApp README [COMING SOON] for more information about building the Go binary, along with a sample Android app that uses it.

Roadmap
--------------------------------------------------------------------------------

### TODO (proof-of-concept)

* fail-over to new server on "ssh: rejected: administratively prohibited (open failed)" error?
* PendingConns: is interrupting connection establishment worth the extra code complexity?
* prefilter entries by capability; don't log "server does not have sufficient capabilities"
* log noise: "use of closed network connection"
* log noise(?): 'Unsolicited response received on idle HTTP channel starting with "H"'
* use ContextError in more places
* build/test on Android and iOS
* reconnection busy loop when no network available (ex. close laptop)

### TODO (future)

* meek enhancements
  * address this: https://trac.torproject.org/projects/tor/wiki/doc/meek#HowtolooklikebrowserHTTPS (new Go client is equivilent to current Windows client, but differs from current Android client which uses the same Android HTTPS stack used by regular apps)
* SSH compression
* preemptive reconnect functionality
  * unfronted meek almost makes this obsolete, since meek sessions survive underlying
     HTTP transport socket disconnects. The client could prefer unfronted meek protocol
     when handshake returns a preemptive_reconnect_lifetime_milliseconds.
* split tunnel support
* implement page view stats
* implement local traffic stats (e.g., to display bytes sent/received)
* control interface (w/ event messages)?
* VpnService compatibility
* upstream proxy support
* support upgrades
  * download entire client
  * download core component only
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
