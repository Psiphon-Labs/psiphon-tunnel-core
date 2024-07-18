module github.com/Psiphon-Labs/psiphon-tunnel-core

go 1.21

replace gitlab.com/yawning/obfs4.git => github.com/jmwample/obfs4 v0.0.0-20230725223418-2d2e5b4a16ba

replace github.com/pion/dtls/v2 => github.com/mingyech/dtls/v2 v2.0.0

require (
	github.com/Psiphon-Inc/rotate-safe-writer v0.0.0-20210303140923-464a7a37606e
	github.com/Psiphon-Labs/bolt v0.0.0-20200624191537-23cedaef7ad7
	github.com/Psiphon-Labs/consistent v0.0.0-20240322131436-20aaa4e05737
	github.com/Psiphon-Labs/goptlib v0.0.0-20200406165125-c0e32a7a3464
	github.com/Psiphon-Labs/psiphon-tls v0.0.0-20240716162946-891a0d5db073
	github.com/Psiphon-Labs/quic-go v0.0.0-20240424181006-45545f5e1536
	github.com/armon/go-proxyproto v0.0.0-20180202201750-5b7edb60ff5f
	github.com/bifurcation/mint v0.0.0-20180306135233-198357931e61
	github.com/cespare/xxhash v1.1.0
	github.com/cheekybits/genny v0.0.0-20170328200008-9127e812e1e9
	github.com/cognusion/go-cache-lru v0.0.0-20170419142635-f73e2280ecea
	github.com/deckarep/golang-set v0.0.0-20171013212420-1d4478f51bed
	github.com/dgraph-io/badger v1.5.4-0.20180815194500-3a87f6d9c273
	github.com/elazarl/goproxy v0.0.0-20200809112317-0581fc3aee2d
	github.com/elazarl/goproxy/ext v0.0.0-20200809112317-0581fc3aee2d
	github.com/florianl/go-nfqueue v1.1.1-0.20200829120558-a2f196e98ab0
	github.com/gobwas/glob v0.2.4-0.20180402141543-f00a7392b439
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e
	github.com/google/gopacket v1.1.19
	github.com/grafov/m3u8 v0.0.0-20171211212457-6ab8f28ed427
	github.com/hashicorp/golang-lru v1.0.2
	github.com/juju/ratelimit v1.0.2
	github.com/marusama/semaphore v0.0.0-20171214154724-565ffd8e868a
	github.com/miekg/dns v1.1.44-0.20210804161652-ab67aa642300
	github.com/mitchellh/panicwrap v0.0.0-20170106182340-fce601fe5557
	github.com/oschwald/maxminddb-golang v1.12.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pion/sctp v1.8.8
	github.com/refraction-networking/conjure v0.7.11-0.20240130155008-c8df96195ab2
	github.com/refraction-networking/gotapdance v1.7.10
	github.com/refraction-networking/utls v1.6.8-0.20240720032424-23de245734c7
	github.com/ryanuber/go-glob v0.0.0-20170128012129-256dc444b735
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.8.4
	github.com/syndtr/gocapability v0.0.0-20170704070218-db04d3cc01c8
	github.com/wader/filtertransport v0.0.0-20200316221534-bdd9e61eee78
	golang.org/x/crypto v0.22.0
	golang.org/x/net v0.24.0
	golang.org/x/sync v0.2.0
	golang.org/x/sys v0.19.0
	golang.org/x/term v0.19.0
)

require (
	filippo.io/bigmod v0.0.1 // indirect
	filippo.io/keygen v0.0.0-20230306160926-5201437acf8e // indirect
	github.com/AndreasBriese/bbloom v0.0.0-20170702084017-28f7e881ca57 // indirect
	github.com/BurntSushi/toml v1.3.2 // indirect
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/dgryski/go-farm v0.0.0-20180109070241-2de33835d102 // indirect
	github.com/flynn/noise v1.0.0 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/pprof v0.0.0-20211214055906-6f57359322fd // indirect
	github.com/josharian/native v1.0.0 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/libp2p/go-reuseport v0.4.0 // indirect
	github.com/mdlayher/netlink v1.4.2-0.20210930205308-a81a8c23d40a // indirect
	github.com/mdlayher/socket v0.0.0-20210624160740-9dbe287ded84 // indirect
	github.com/mroth/weightedrand v1.0.0 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pion/dtls/v2 v2.2.7 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/stun v0.6.1 // indirect
	github.com/pion/transport/v2 v2.2.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/refraction-networking/ed25519 v0.1.2 // indirect
	github.com/refraction-networking/obfs4 v0.1.2 // indirect
	github.com/sergeyfrolov/bsbuffer v0.0.0-20180903213811-94e85abb8507 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.5.0 // indirect
	go.uber.org/mock v0.4.0 // indirect
	golang.org/x/exp v0.0.0-20221205204356-47842c84f3db // indirect
	golang.org/x/mod v0.11.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.9.1 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	honnef.co/go/tools v0.2.1 // indirect
)
