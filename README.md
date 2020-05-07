[![Build Status](https://travis-ci.org/Psiphon-Labs/psiphon-tunnel-core.png)](https://travis-ci.org/Psiphon-Labs/psiphon-tunnel-core) [![Coverage Status](https://coveralls.io/repos/github/Psiphon-Labs/psiphon-tunnel-core/badge.svg?branch=master)](https://coveralls.io/github/Psiphon-Labs/psiphon-tunnel-core?branch=master)

Psiphon Tunnel Core README
================================================================================

Overview
--------------------------------------------------------------------------------

Psiphon is an Internet censorship circumvention system.

The tunnel core project includes tunneling clients and a server, which together implement all aspects of evading blocking and relaying traffic through Psiphon.

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
3132372e302e302e31202020207b22746167223a22222c22697041646472657373223a223132372e302e302e31222c227[...]4696f6e56657273696f6e223a312c227369676e6174757265223a22227d

$ cat client.config
{
    "LocalHttpProxyPort" : 8080,
    "LocalSocksProxyPort" : 1080,

    "PropagationChannelId" : "24BCA4EE20BEB92C",
    "SponsorId" : "721AE60D76700F5A",

    "TargetServerEntry" : "3132372e302e302e31202020207b22746167223a22222c22697041646472657373223a223132372e302e302e31222c227[...]4696f6e56657273696f6e223a312c227369676e6174757265223a22227d"
}
```

### Run psiphond

```
$ ./psiphond run
{"buildDate":"","buildRepo":"","buildRev":"","build_rev":"","context":"server.RunServices#68","dependencies":{},"goVersion":"","host_id":"example-host-id","level":"info","msg":"startup","timestamp":"2019-08-09T11:14:10-04:00"}
{"build_rev":"","context":"server.(*TunnelServer).Run#194","host_id":"example-host-id","level":"info","localAddress":"127.0.0.1:9999","msg":"listening","timestamp":"2019-08-09T11:14:10-04:00","tunnelProtocol":"OSSH"}
{"build_rev":"","context":"server.(*TunnelServer).Run.func2#214","host_id":"example-host-id","level":"info","localAddress":"127.0.0.1:9999","msg":"running","timestamp":"2019-08-09T11:14:10-04:00","tunnelProtocol":"OSSH"}
[...]
```

### Run the console client

```
$ ./ConsoleClient -config ./client.config
{"data":{"port":1080},"noticeType":"ListeningSocksProxyPort","showUser":false,"timestamp":"2019-08-09T15:14:54.800Z"}
{"data":{"port":8080},"noticeType":"ListeningHttpProxyPort","showUser":false,"timestamp":"2019-08-09T15:14:54.801Z"}
[...]
{"data":{"count":1},"noticeType":"Tunnels","showUser":false,"timestamp":"2019-08-09T15:14:54.995Z"}
```

### Tunnel traffic through Psiphon

Use the local SOCKS proxy (port 1080) or HTTP proxy (port 8080) to tunnel traffic.


Acknowledgements
--------------------------------------------------------------------------------

Psiphon Tunnel Core uses:

* [Go](https://golang.org/)
* [boltdb/bolt](https://github.com/boltdb/bolt)
* [patrickmn/go-cache](https://github.com/patrickmn/go-cache)
* [miekg/dns](https://github.com/miekg/dns)
* [ThomsonReutersEikon/go-ntlm](https://github.com/ThomsonReutersEikon/go-ntlm)
* [Yawning/goptlib](https://github.com/Yawning/goptlib)
* [zach-klippenstein/goregen](https://github.com/zach-klippenstein/goregen)
* [creack/goselect](https://github.com/creack/goselect)
* [Sirupsen/logrus](https://github.com/Sirupsen/logrus)
* [grafov/m3u8](https://github.com/grafov/m3u8)
* [oschwald/maxminddb-golang](https://github.com/oschwald/maxminddb-golang)
* [goarista/monotime](https://github.com/aristanetworks/goarista)
* [spacemonkeygo/openssl](https://github.com/spacemonkeygo/openssl)
* [kardianos/osext](https://github.com/kardianos/osext)
* [mitchellh/panicwrap](https://github.com/mitchellh/panicwrap)
* [juju/ratelimit](https://github.com/juju/ratelimit)
* [codahale/sss](https://github.com/codahale/sss)
* [marusama/semaphore](https://github.com/marusama/semaphore)
* [refraction-networking/utls](https://github.com/refraction-networking/utls)
* [lucas-clemente/quic-go](https://github.com/lucas-clemente/quic-go)
* [cloudflare/tls-tris](https://github.com/cloudflare/tls-tris)
* [Yawning/chacha20](https://github.com/Yawning/chacha20)
* [wader/filtertransport](https://github.com/wader/filtertransport)
