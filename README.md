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

* Go 1.4 (or higher) is required.
* In this repository, run `go build` to make the `psiphon-tunnel-core` binary.
* Note that the `psiphon` package is imported using the absolute path `github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon`; without further local configuration, `go` will use this version of the code and not the local copy in the repository.
* This project builds and runs on recent versions of Windows, Linux, and Mac OS X.
* Run `./psiphon-tunnel-core --config psiphon.config` where the config file looks like this:

    ```
    {
        "PropagationChannelId" : "<placeholder>",
        "SponsorId" : "<placeholder>",
        "RemoteServerListUrl" : "<placeholder>",
        "RemoteServerListSignaturePublicKey" : "<placeholder>",
        "DataStoreDirectory" : "",
        "DataStoreTempDirectory" : "",
        "LogFilename" : "",
        "LocalHttpProxyPort" : 0,
        "LocalSocksProxyPort" : 0,
        "EgressRegion" : "",
        "TunnelProtocol" : "",
        "ConnectionWorkerPoolSize" : 10,
        "TunnelPoolSize" : 1,
        "PortForwardFailureThreshold" : 10,
        "UpstreamHttpProxyAddress" : ""
    }
    ```

* Replace each `<placeholder>` with a value from your Psiphon network. The Psiphon server-side stack is open source and can be found in our  [Psiphon 3 repository](https://bitbucket.org/psiphon/psiphon-circumvention-system). If you would like to use the Psiphon Inc. network, contact <developer-support@psiphon.ca>.
* The project builds and runs on Android. See the [AndroidLibrary README](AndroidLibrary/README.md) for more information about building the Go component, and the [AndroidApp README](AndroidApp/README.md) for a sample Android app that uses it.

Roadmap
--------------------------------------------------------------------------------

### TODO (short-term)

* sometimes fails to promptly detect loss of connection after device sleep
* requirements for integrating with Windows client
  * split tunnel support
  * resumable download of client upgrades
* Android app
  * open home pages
  * settings UI (e.g., region selection)
* log noise
  * "use of closed network connection"
  * 'Unsolicited response received on idle HTTP channel starting with "H"'

### TODO (future)

* meek enhancements
  * address this: https://trac.torproject.org/projects/tor/wiki/doc/meek#HowtolooklikebrowserHTTPS (new Go client is equivilent to current Windows client, but differs from current Android client which uses the same Android HTTPS stack used by regular apps)
* SSH compression
* preemptive reconnect functionality
  * unfronted meek almost makes this obsolete, since meek sessions survive underlying
     HTTP transport socket disconnects. The client could prefer unfronted meek protocol
     when handshake returns a preemptive_reconnect_lifetime_milliseconds.
  * could also be accomplished with TunnelPoolSize > 1 and staggering the establishment times
* implement local traffic stats (e.g., to display bytes sent/received)
* more formal control interface (w/ event messages)?
* support upgrading core only
* try multiple protocols for each server (currently only tries one protocol per server)
* support a config pushed by the network
  * server can push preferred/optimized settings; client should prefer over defaults
  * e.g., etablish worker pool size; tunnel pool size

Licensing
--------------------------------------------------------------------------------

Please see the LICENSE file.


Contacts
--------------------------------------------------------------------------------

For more information on Psiphon Inc, please visit our web site at:

[www.psiphon.ca](http://www.psiphon.ca)
