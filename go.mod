module github.com/Psiphon-Labs/psiphon-tunnel-core

go 1.20

// When this is the main module, use a patched version of
// refraction/gotapdance with
// https://github.com/Psiphon-Labs/psiphon-tunnel-core/commit/2a4121d9
replace github.com/refraction-networking/gotapdance => ./replace/gotapdance

// When this is the main module, gitlab.com/yawning/obfs4, used by
// refraction-networking/gotapdance, is pinned at 816cff15 the last revision
// published without a GPL license. This version lacks obfuscation
// improvements added in revision 1a6129b6, but these changes apply only on
// the server side.
replace gitlab.com/yawning/obfs4.git => ./replace/obfs4.git

require (
	github.com/Psiphon-Inc/rotate-safe-writer v0.0.0-20210303140923-464a7a37606e
	github.com/Psiphon-Labs/bolt v0.0.0-20200624191537-23cedaef7ad7
	github.com/Psiphon-Labs/goptlib v0.0.0-20200406165125-c0e32a7a3464
	github.com/Psiphon-Labs/quic-go v0.0.0-20230215230806-9b1ddbf778cc
	github.com/Psiphon-Labs/tls-tris v0.0.0-20210713133851-676a693d51ad
	github.com/armon/go-proxyproto v0.0.0-20180202201750-5b7edb60ff5f
	github.com/bifurcation/mint v0.0.0-20180306135233-198357931e61
	github.com/buraksezer/consistent v0.10.0
	github.com/cespare/xxhash v1.1.0
	github.com/cheekybits/genny v0.0.0-20170328200008-9127e812e1e9
	github.com/cognusion/go-cache-lru v0.0.0-20170419142635-f73e2280ecea
	github.com/deckarep/golang-set v0.0.0-20171013212420-1d4478f51bed
	github.com/dgraph-io/badger v1.5.4-0.20180815194500-3a87f6d9c273
	github.com/elazarl/goproxy v0.0.0-20200809112317-0581fc3aee2d
	github.com/elazarl/goproxy/ext v0.0.0-20200809112317-0581fc3aee2d
	github.com/florianl/go-nfqueue v1.1.1-0.20200829120558-a2f196e98ab0
	github.com/flynn/noise v1.0.1-0.20220214164934-d803f5c4b0f4
	github.com/fxamacker/cbor/v2 v2.4.0
	github.com/gammazero/deque v0.2.1
	github.com/gobwas/glob v0.2.4-0.20180402141543-f00a7392b439
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da
	github.com/google/gopacket v1.1.19-0.20200831200443-df1bbd09a561
	github.com/grafov/m3u8 v0.0.0-20171211212457-6ab8f28ed427
	github.com/hashicorp/golang-lru v0.0.0-20180201235237-0fb14efe8c47
	github.com/juju/ratelimit v1.0.2
	github.com/marusama/semaphore v0.0.0-20171214154724-565ffd8e868a
	github.com/miekg/dns v1.1.44-0.20210804161652-ab67aa642300
	github.com/mitchellh/panicwrap v0.0.0-20170106182340-fce601fe5557
	github.com/oschwald/maxminddb-golang v1.2.1-0.20170901134056-26fe5ace1c70
	github.com/panmari/cuckoofilter v1.0.3
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pion/datachannel v1.5.5
	github.com/pion/ice/v2 v2.3.2
	github.com/pion/sdp/v3 v3.0.6
	github.com/pion/stun v0.4.0
	github.com/pion/webrtc/v3 v3.2.1
	github.com/refraction-networking/gotapdance v1.2.0
	github.com/refraction-networking/utls v1.1.3
	github.com/ryanuber/go-glob v0.0.0-20170128012129-256dc444b735
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.2
	github.com/syndtr/gocapability v0.0.0-20170704070218-db04d3cc01c8
	github.com/wader/filtertransport v0.0.0-20200316221534-bdd9e61eee78
	golang.org/x/crypto v0.6.0
	golang.org/x/net v0.8.0
	golang.org/x/sync v0.1.0
	golang.org/x/sys v0.7.0
	golang.org/x/term v0.6.0
	golang.zx2c4.com/wireguard v0.0.0-20230325221338-052af4a8072b
	tailscale.com v1.40.0
)

require (
	git.torproject.org/pluggable-transports/goptlib.git v1.2.0 // indirect
	github.com/AndreasBriese/bbloom v0.0.0-20170702084017-28f7e881ca57 // indirect
	github.com/Psiphon-Labs/qtls-go1-18 v0.0.0-20230515185031-ae6632ab97ac // indirect
	github.com/Psiphon-Labs/qtls-go1-19 v0.0.0-20230515185100-099bac32c181 // indirect
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412 // indirect
	github.com/alexbrainman/sspi v0.0.0-20210105120005-909beea2cc74 // indirect
	github.com/andybalholm/brotli v1.0.5-0.20220518190645-786ec621f618 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/siphash v1.2.3-0.20201109081723-a21c2e7914a8 // indirect
	github.com/dgryski/go-farm v0.0.0-20180109070241-2de33835d102 // indirect
	github.com/dgryski/go-metro v0.0.0-20200812162917-85c65e2d0165 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/golang/protobuf v1.5.3-0.20210916003710-5d5e8c018a13 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/josharian/native v1.1.1-0.20230202152459-5c7d0dd6ab86 // indirect
	github.com/jsimonetti/rtnetlink v1.1.2-0.20220408201609-d380b505068b // indirect
	github.com/kardianos/osext v0.0.0-20170510131534-ae77be60afb1 // indirect
	github.com/klauspost/compress v1.15.10-0.20220729101446-5a3a4a965cc6 // indirect
	github.com/mdlayher/netlink v1.7.1 // indirect
	github.com/mdlayher/socket v0.4.0 // indirect
	github.com/mroth/weightedrand v0.4.1 // indirect
	github.com/onsi/ginkgo/v2 v2.2.0 // indirect
	github.com/pion/dtls/v2 v2.2.6 // indirect
	github.com/pion/interceptor v0.1.16 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/mdns v0.0.7 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.10 // indirect
	github.com/pion/rtp v1.7.13 // indirect
	github.com/pion/sctp v1.8.7 // indirect
	github.com/pion/srtp/v2 v2.0.12 // indirect
	github.com/pion/transport/v2 v2.2.0 // indirect
	github.com/pion/turn/v2 v2.1.0 // indirect
	github.com/pion/udp/v2 v2.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/sergeyfrolov/bsbuffer v0.0.0-20180903213811-94e85abb8507 // indirect
	github.com/tailscale/goupnp v1.0.1-0.20210804011211-c64d0f06ea05 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	gitlab.com/yawning/obfs4.git v0.0.0-20190120164510-816cff15f425 // indirect
	go4.org/mem v0.0.0-20210711025021-927187094b94 // indirect
	golang.org/x/exp v0.0.0-20221205204356-47842c84f3db // indirect
	golang.org/x/text v0.8.0 // indirect
	golang.org/x/tools v0.7.0 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.3 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
