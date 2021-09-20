[![CI](https://github.com/Psiphon-Labs/psiphon-tunnel-core/actions/workflows/tests.yml/badge.svg)](https://github.com/Psiphon-Labs/psiphon-tunnel-core/actions/workflows/tests.yml) [![Coverage Status](https://coveralls.io/repos/github/Psiphon-Labs/psiphon-tunnel-core/badge.svg?branch=master)](https://coveralls.io/github/Psiphon-Labs/psiphon-tunnel-core?branch=master)


Psiphon Tunnel Core README
================================================================================

Overview
--------------------------------------------------------------------------------

Psiphon is an Internet censorship circumvention system.

The tunnel core project includes a tunneling client and server, which together implement key aspects of evading blocking and relaying client traffic through Psiphon and beyond censorship.

All Psiphon open source projects, including the complete open source code for Android, iOS, and Windows clients may be found at [www.github.com/Psiphon-Inc/psiphon](https://www.github.com/Psiphon-Inc/psiphon).

For more information about Psiphon Inc., please visit our web site at [www.psiphon.ca](https://www.psiphon.ca).

```
psiphon-tunnel-core
  └── ClientLibrary  General client libraries
  └── ConsoleClient  CLI client program
  └── MobileLibrary  Android/iOS client libraries
  └── Server         Server program
  └── psiphon        Client code package
    └── common\...   Common code packages
    └── server       Server code package
```


Technical Summary
--------------------------------------------------------------------------------

Psiphon tunnels Internet traffic through a network of proxy servers with the goal of circumventing Internet censorship.

Users run a client program which connects to a proxy server and routes client host Internet traffic through a tunnel established to the proxy. Traffic egresses from the proxy, which is located beyond the entity censoring the user's Internet.

### Traffic Routing

Psiphon has multiple routing modes:
- Port forward mode: the client runs localhost SOCKS and HTTPS proxies and the client host or individual apps are configured to use these local proxies; each connection to a local proxy is related through the tunnel to the server.
- Packet tunnel mode: the client relays IP packets between a host "tun" device and the server.

### Traffic Security

At the core of all tunnels is an SSH connection which protects the confidentiality and integrity of client traffic between the client host and the proxy server. Clients authenticate the SSH server using pre-shared public keys, ensuring clients connect only to authentic Psiphon servers.

### Server Entries

Server connection information, including SSH public keys, addresses, and obfuscation parameters are distributed to clients in the form of a list of "server entries". Each server entry fully describes one Psiphon server.

Clients binaries may be built with embedded server lists. Clients may also "discover" new server entries when they successfully connect to a server.

Psiphon also uses out-of-band server list delivery mechanisms, including fetching server lists from drops which are configured in the clients. All out-of-band mechanisms perform additional server list verification using public keys configured in the clients.

All delivery mechanisms use partitioning to prevent trivial enumeration of all server entries.

Some out-of-band server server lists, called ["obfuscated server lists"](psiphon/common/osl/README.md), are encrypted and only clients that have been granted sufficient required keys can access the included servers.

### Traffic Obfuscation

The core SSH protocol is wrapped in optional obfuscation layers which transform traffic in order to evade blocking of Psiphon servers. Mitigated attacks include endpoint blocking, keyword-based blocking, DPI-based blocking, and more.

Obfuscation techniques include:
- Making traffic on the wire look fully random.
- Making traffic on the wire look like popular implementations of popular protocols.
- Performing traffic shaping to obscure the size and timing properties of encapsulated traffic.
- Connecting to proxy servers indirectly, via intermediaries.

### Circumvention Optimizations

To minimize connection time, Psiphon makes multiple concurrent connection attempts to different servers using different obfuscation techniques. This process generally selects the fastest working obfuscation technique and server. This process is how Psiphon load balances clients across its network of servers without using a centralized load balancing mechanism.

A successful connection may be subject to further quality tests before selection. The Psiphon client remembers which servers and which obfuscation techniques and parameters are successful and prioritizes using the same on subsequent connections.

Psiphon uses a mechanism called ["tactics"](psiphon/common/tactics) to remotely deliver targeted, optimized configuration and obfuscation parameters to clients.


Running Psiphon
--------------------------------------------------------------------------------

### Get the programs

Official binaries are avaiable at:
- https://github.com/Psiphon-Labs/psiphon-tunnel-core-binaries
- https://github.com/Psiphon-Labs/psiphon-tunnel-core/releases, for libraries

For these instructions, use:
- [psiphond](https://github.com/Psiphon-Labs/psiphon-tunnel-core-binaries/blob/master/psiphond/psiphond)
- [ConsoleClient](https://github.com/Psiphon-Labs/psiphon-tunnel-core-binaries/blob/master/linux/psiphon-tunnel-core-x86_64)

### Generate configuration data

Run the "generate" mode of psiphond to generate configs, setting the IP address as appropriate; this is the address the client will use to connect to the server.

```
$ ./psiphond -ipaddress 127.0.0.1 -protocol OSSH:9999 -protocol generate

$ ls
psiphond
psiphond.config
psiphond-osl.config
psiphond-tactics.config
psiphond-traffic-rules.config
server-entry.dat
```

Create a client config file, copying the contents of `server-entry.dat` to the `TargetServerEntry` field.

```
$ cat server-entry.dat 
3132372e302e302e31202020207b22746167223a22222c2269[...]

$ cat client.config
{
    "LocalHttpProxyPort" : 8080,
    "LocalSocksProxyPort" : 1080,

    "PropagationChannelId" : "24BCA4EE20BEB92C",
    "SponsorId" : "721AE60D76700F5A",

    "TargetServerEntry" : "3132372e302e302e31202020207b22746167223a22222c2269[...]"
}
```

### Run psiphond

```
$ ./psiphond run
{"localAddress":"127.0.0.1:9999","msg":"listening","tunnelProtocol":"OSSH",[...]}
{"localAddress":"127.0.0.1:9999","msg":"running","tunnelProtocol":"OSSH",[...]}
[...]
```

### Run the console client

```
$ ./ConsoleClient -config ./client.config
{"data":{"port":1080},"noticeType":"ListeningSocksProxyPort",[...]}
{"data":{"port":8080},"noticeType":"ListeningHttpProxyPort",[...]}
[...]
{"data":{"count":1},"noticeType":"Tunnels",[...]}
```

### Tunnel traffic through Psiphon

Use the local SOCKS proxy (port 1080) or HTTP proxy (port 8080) to tunnel traffic.


Acknowledgements
--------------------------------------------------------------------------------

Psiphon Tunnel Core uses:

* [Go](https://golang.org)
* [agl/ed25519](https://github.com/agl/ed25519)
* [AndreasBriese/bbloom](https://github.com/AndreasBriese/bbloom)
* [aristanetworks/goarista/monotime](https://github.com/aristanetworks/goarista)
* [armon/go-proxyproto](https://github.com/armon/go-proxyproto)
* [armon/go-socks](https://github.com/armon/go-socks5)
* [bifurcation/mint](https://github.com/bifurcation/mint)
* [boltdb/bolt](https://github.com/boltdb/bolt)
* [cheekybits/genny/generic](https://github.com/cheekybits/genny/generic)
* [cloudflare/tls-tris](https://github.com/cloudflare/tls-tris)
* [codahale/sss](https://github.com/codahale/sss)
* [cognusion/go-cache-lru](https://github.com/cognusion/go-cache-lru)
* [creack/goselect](https://github.com/creack/goselect)
* [davecgh/go-spew/spew](https://github.com/davecgh/go-spew/spew)
* [deckarep/golang-set](https://github.com/deckarep/golang-set)
* [dgraph-io/badger](https://github.com/dgraph-io/badger)
* [dgryski/go-farm](https://github.com/dgryski/go-farm)
* [elazarl/goproxy](https://github.com/elazarl/goproxy)
* [florianl/go-nfqueue](https://github.com/florianl/go-nfqueue)
* [gobwas/glob](https://github.com/gobwas/glob)
* [golang/protobuf](https://github.com/golang/protobuf)
* [google/gopacket](https://github.com/google/gopacket)
* [grafov/m3u8](https://github.com/grafov/m3u8)
* [hashicorp/golang-lru](https://github.com/hashicorp/golang-lru)
* [juju/ratelimit](https://github.com/juju/ratelimit)
* [kardianos/osext](https://github.com/kardianos/osext)
* [groupcache/lru]("github.com/golang/groupcache/lru")
* [lucas-clemente/quic-go](https://github.com/lucas-clemente/quic-go)
* [marusama/semaphore](https://github.com/marusama/semaphore)
* [mdlayher/netlink)](https://github.com/mdlayher/netlink)
* [miekg/dns](https://github.com/miekg/dns)
* [mitchellh/panicwrap](https://github.com/mitchellh/panicwrap)
* [oschwald/maxminddb-golang](https://github.com/oschwald/maxminddb-golang)
* [patrickmn/go-cache](https://github.com/patrickmn/go-cache)
* [pkg/errors](https://github.com/pkg/errors)
* [pmezard/go-difflib](https://github.com/pmezard/go-difflib)
* [redjack/marionette](https://github.com/redjack/marionette)
* [refraction-networking/gotapdance](https://github.com/refraction-networking/gotapdance)
* [refraction-networking/utls](https://github.com/refraction-networking/utls)
* [ryanuber/go-glob](https://github.com/ryanuber/go-glob)
* [sergeyfrolov/bsbuffer](https://github.com/sergeyfrolov/bsbuffer)
* [sirupsen/logrus](https://github.com/sirupsen/logrus)
* [stretchr/testify](https://github.com/stretchr/testify)
* [syndtr/gocapability/capability](https://github.com/syndtr/gocapability/capability)
* [ThomsonReutersEikon/go-ntlm](https://github.com/ThomsonReutersEikon/go-ntlm)
* [wader/filtertransport](https://github.com/wader/filtertransport)
* [Yawning/chacha20](https://github.com/Yawning/chacha20)
* [Yawning/goptlib](https://github.com/Yawning/goptlib)
* [yawning/obfs4](https://gitlab.com/yawning/obfs4)
* [zach-klippenstein/goregen](https://github.com/zach-klippenstein/goregen)
* [zap](https://go.uber.org/zap)

