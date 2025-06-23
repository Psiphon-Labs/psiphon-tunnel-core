module github.com/Psiphon-Labs/psiphon-tunnel-core

go 1.24.0

toolchain go1.24.4

// The following replace is required only when the build tag
// PSIPHON_ENABLE_REFRACTION_NETWORKING is specified.

replace gitlab.com/yawning/obfs4.git => github.com/jmwample/obfs4 v0.0.0-20230725223418-2d2e5b4a16ba

// When this is the main module, github.com/pion/dtls/v2, used by
// psiphon/common/inproxy via pion/webrtc, is replaced with a fork
// which adds support for optional DTLS ClientHello randomization.
// This fork is currently based on https://github.com/pion/dtls v2.2.7.
//
// This fork also includes the mingyech/dtls Conjure customizations.
//
// In addition, ice/v2 and webrtc/v3 are replaced by forks, based on
// github.com/pion/ice/v2 v2.3.24 and github.com/pion/webrtc/v3 v3.2.40
// respectively, containing Psiphon customizations. See comments in
// psiphon/common/inproxy/newWebRTCConn for details.
//
// The following replaces are required only when the build tags
// PSIPHON_ENABLE_REFRACTION_NETWORKING (dtls/v2 only) or
// PSIPHON_ENABLE_INPROXY are specified.

replace github.com/pion/dtls/v2 => ./replace/dtls

replace github.com/pion/ice/v2 => ./replace/ice

replace github.com/pion/webrtc/v3 => ./replace/webrtc

require (
	filippo.io/edwards25519 v1.1.0
	github.com/Jigsaw-Code/outline-sdk v0.0.16
	github.com/Jigsaw-Code/outline-ss-server v1.8.0
	github.com/Psiphon-Inc/rotate-safe-writer v0.0.0-20210303140923-464a7a37606e
	github.com/Psiphon-Labs/bolt v0.0.0-20200624191537-23cedaef7ad7
	github.com/Psiphon-Labs/consistent v0.0.0-20240322131436-20aaa4e05737
	github.com/Psiphon-Labs/goptlib v0.0.0-20200406165125-c0e32a7a3464
	github.com/Psiphon-Labs/psiphon-tls v0.0.0-20250318183125-2a2fae2db378
	github.com/Psiphon-Labs/quic-go v0.0.0-20250527153145-79fe45fb83b1
	github.com/Psiphon-Labs/utls v0.0.0-20250623193530-396869e9cd87
	github.com/armon/go-proxyproto v0.0.0-20180202201750-5b7edb60ff5f
	github.com/bifurcation/mint v0.0.0-20180306135233-198357931e61
	github.com/bits-and-blooms/bloom/v3 v3.6.0
	github.com/cespare/xxhash v1.1.0
	github.com/cheekybits/genny v0.0.0-20170328200008-9127e812e1e9
	github.com/cognusion/go-cache-lru v0.0.0-20170419142635-f73e2280ecea
	github.com/deckarep/golang-set v0.0.0-20171013212420-1d4478f51bed
	github.com/dgraph-io/badger v1.5.4-0.20180815194500-3a87f6d9c273
	github.com/elazarl/goproxy v0.0.0-20200809112317-0581fc3aee2d
	github.com/elazarl/goproxy/ext v0.0.0-20200809112317-0581fc3aee2d
	github.com/florianl/go-nfqueue v1.1.1-0.20200829120558-a2f196e98ab0
	github.com/flynn/noise v1.0.1-0.20220214164934-d803f5c4b0f4
	github.com/fxamacker/cbor/v2 v2.5.0
	github.com/go-ole/go-ole v1.3.0
	github.com/gobwas/glob v0.2.4-0.20180402141543-f00a7392b439
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da
	github.com/google/gopacket v1.1.19
	github.com/grafov/m3u8 v0.0.0-20171211212457-6ab8f28ed427
	github.com/marusama/semaphore v0.0.0-20171214154724-565ffd8e868a
	github.com/miekg/dns v1.1.56
	github.com/mitchellh/panicwrap v0.0.0-20170106182340-fce601fe5557
	github.com/oschwald/maxminddb-golang v1.12.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pion/datachannel v1.5.5
	github.com/pion/dtls/v2 v2.2.7
	github.com/pion/ice/v2 v2.3.24
	github.com/pion/interceptor v0.1.25
	github.com/pion/logging v0.2.2
	github.com/pion/rtp v1.8.5
	github.com/pion/sctp v1.8.16
	github.com/pion/sdp/v3 v3.0.9
	github.com/pion/stun v0.6.1
	github.com/pion/transport/v2 v2.2.4
	github.com/pion/webrtc/v3 v3.2.40
	github.com/refraction-networking/conjure v0.7.11-0.20240130155008-c8df96195ab2
	github.com/refraction-networking/gotapdance v1.7.10
	github.com/ryanuber/go-glob v0.0.0-20170128012129-256dc444b735
	github.com/shirou/gopsutil/v4 v4.24.5
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.9.0
	github.com/syndtr/gocapability v0.0.0-20170704070218-db04d3cc01c8
	github.com/wader/filtertransport v0.0.0-20200316221534-bdd9e61eee78
	github.com/wlynxg/anet v0.0.5
	golang.org/x/crypto v0.35.0
	golang.org/x/net v0.36.0
	golang.org/x/sync v0.11.0
	golang.org/x/sys v0.30.0
	golang.org/x/term v0.29.0
	golang.org/x/time v0.5.0
	golang.zx2c4.com/wireguard v0.0.0-20230325221338-052af4a8072b
	golang.zx2c4.com/wireguard/windows v0.5.3
	tailscale.com v1.58.2
)

require (
	filippo.io/bigmod v0.0.1 // indirect
	filippo.io/keygen v0.0.0-20230306160926-5201437acf8e // indirect
	github.com/AndreasBriese/bbloom v0.0.0-20190825152654-46b345b51c96 // indirect
	github.com/alexbrainman/sspi v0.0.0-20231016080023-1a75b4708caa // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/bits-and-blooms/bitset v1.10.0 // indirect
	github.com/cloudflare/circl v1.5.0 // indirect
	github.com/coreos/go-iptables v0.7.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dblohm7/wingoes v0.0.0-20230929194252-e994401fc077 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/dgryski/go-farm v0.0.0-20200201041132-a6ae2369ad13 // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/nftables v0.1.1-0.20230115205135-9aa6fdf5a28c // indirect
	github.com/google/pprof v0.0.0-20211214055906-6f57359322fd // indirect
	github.com/google/uuid v1.3.1 // indirect
	github.com/josharian/native v1.1.1-0.20230202152459-5c7d0dd6ab86 // indirect
	github.com/jsimonetti/rtnetlink v1.3.5 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/libp2p/go-reuseport v0.4.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	github.com/mroth/weightedrand v1.0.0 // indirect
	github.com/onsi/ginkgo/v2 v2.12.0 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pion/mdns v0.0.12 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.12 // indirect
	github.com/pion/srtp/v2 v2.0.18 // indirect
	github.com/pion/turn/v2 v2.1.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/refraction-networking/ed25519 v0.1.2 // indirect
	github.com/refraction-networking/obfs4 v0.1.2 // indirect
	github.com/refraction-networking/utls v1.3.3 // indirect
	github.com/sergeyfrolov/bsbuffer v0.0.0-20180903213811-94e85abb8507 // indirect
	github.com/shadowsocks/go-shadowsocks2 v0.1.5 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/tailscale/goupnp v1.0.1-0.20210804011211-c64d0f06ea05 // indirect
	github.com/tailscale/netlink v1.1.1-0.20211101221916-cabfb018fe85 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/vishvananda/netlink v1.2.1-beta.2 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.5.0 // indirect
	go.uber.org/mock v0.4.0 // indirect
	go4.org/mem v0.0.0-20220726221520-4f986261bf13 // indirect
	go4.org/netipx v0.0.0-20230824141953-6213f710f925 // indirect
	golang.org/x/exp v0.0.0-20240110193028-0dcbfd608b1e // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
