
# Prefix Transport

**TLDR** - This transport allows up to prepend conjure connections with bytes that look like the
initialization of other protocols. This can help to circumvent blocking in some areas and better
understand censorship regimes, but is generally a short term solution.

The `Prefix_Min` transport is a strictly improved version of the existing `Min` transport and we
suggest migration.

## Description

This package implements the prefix transport for the conjure refraction-networking system. The
prefix transport operates in much the same way as the min transport, sending a tag in the fist
packet signalling to the station that the flow has knowledge of a secret shared with the station by
a previous registration.

### Integrating the Prefix Transport

Though the client dialer allows the use of TrasnportType  for compatibility reasons, the prefix
transport requires use of the newer Client Transport interface (`TransportConfig` in the dialer)
which is implemented by the `prefix.ClientTransport` object.

Usage Example:

```go
// basic - default prefix is Random.
t := transports.NewWithParams("prefix", nil)

dialer = &tapdanceDialer{TransportConfig: t}
conn, err := dialer.Dial("tcp", "1.1.1.1:443")
// ...
```

```go
// Options included
var prefixID int32 = prefix.OpenSSH2
var randomizePhantomPort = true
var flushPolicy = prefix.FlushAfterTag

params = &pb.PrefixTransportParams{
  RandomizeDstPort: &randomizePhantomPort,
  PrefixId: &prefixID
  CustomFlushPolicy: &flushPolicy
}

t, err := transports.NewWithParams("prefix", params)
if err != nil {
  panic(err)
}

dialer = &tapdanceDialer{ TransportConfig: t}
conn, err := dialer.Dial("tcp", "1.1.1.1:443")
// ...
```

### Prefixes Supported by Default

All Prefixes include an obfuscated tag that indicates to the station that this is in fact a
registered client and shared the registration identifier as a secure value obfuscated to uniform
random.

- `Min` - minimum prefix prepends no bytes other than obfuscated tag, similar to
  the existing [Min
  transport](https://github.com/refraction-networking/conjure/tree/master/pkg/transports/wrapping/min)
- `GetLong` - Plain text HTTP 1.1 GET Header for a root path
- `PostLong` - Plain text HTTP 1.1 POST Header for a root path
- `HTTPResp` - Plain text HTTP 1.1 Response Header with a 200 (success) return code
- `TLSClientHello` - TLS ClientHello header up to random field
- `TLSServerHello` - TLS ServerHello header up to random field
- `TLSAlertWarning` - TLS header indicating a fatal alert
- `TLSAlertFatal` - TLS header indicating a fatal alert
- `DNSOverTCP` - DNS over TCP header
- `OpenSSH2` - OpenSSH banner header version 8.9.p1

### Ports

Prefixes have default ports associated with them, but also allow port randomization. In the prefix
Transport specifically the parameter to control that is `RandomizeDstPort`. If this is not set, then
the connection will set the port to the the fixed port associated with the chosen prefix (e.g. TLS
prefixes will use 443, HTTP will use 80, etc.). If Randomize is selected, the port is chosen from a
destination port randomly from the range [1024 - 65535].

### Prefix Write Buffer Flush

Given that the prefix support is intended to be relatively flexible wrt. the way that prefixes can
be expressed we have added a parameter to give the user basic control over the places where the
write buffer gets flushed. Each existing prefix haa a default flush policy that makes the most sense
for the individual prefix.

Currently there are only two positions where potential flushes will be inserted, after the prefix
and/or after the obfuscated tag.

```txt
[prefix_bytes] |    | [obfuscated_tag] |    | [client bytes .... -> ]
                 ^                        ^
            maybe flush              maybe flush
```

Currently the default policy for the existing (partial packet) prefixes is no added flushes.
However, for different prefixes in the future (e.g a complete TLS ClientHello packet) it would make
sense to flush after the prefix.

### :warning: Sharp Edges :warning:

In general this transport will not properly mimic the protocols that are sent as a prefix and should
not be expected to do so.

**Comparing the [Min transport](https://github.com/refraction-networking/conjure/tree/master/pkg/transports/wrapping/min) and the min prefix**

The min transport is designed to send a uniform random encoding of the client`s session identifier
before the initial packet in a connection. Howveer, on reconnect the same value is sent for the
session identifier. Meaning that connections made by re-using registrations will always start with
the same 32 bytes.

In contrast the Min prefix uses a 64 byte obfuscated tag that will be random on every connection,
even when re-using a registration. Beyond this the tag encoding scheme is built to be modular, and
capable of supporting new obfuscation techniques as necessary in the future. Currently obfuscation
is done by deriving a shared key using ECDHE an then encrypts the plaintext under that key using
AES CTR. The elligator representative for the clients public key is prepended to the returned byte
array. This means that the result length will likely be: `32 + len(plaintext)`.

```txt
// Min Transport
[32B elligator encoded session indicator]

// Min Prefix
[32B elligator encoded client ECDHE Pub] [32B session indicator]

```

## Adding a Prefix / Bidirectional Registration Prefix Overrides

TODO:  :construction:  In order to add a prefix ...

## :construction: Road-Map

Planned Features

- [X] **Randomization** - indicate segments of the prefix to be filled from a random source.

- [ ] **Server Side Prefix Override From File** - file format shared between station and Reg server
  describing available prefixes outside of defaults.

These features are not necessarily planned or landing imminently, they are simply things that would
be nice to have.

- [ ] **TagEncodings** - Allow the tag to (by prefix configuration) be encoded using an encoder
  expected by the station, Base64 for example.

- [ ] **StreamEncodings** - Allow the Stream of client bytes to (by configuration) encoded /
  encrypted using a scheme expected by the station, AES or Base64 for example.

- [ ] **Prefix Revocation** - If there is a prefix that is known to be blocked and we don't want
  clients to use it, but we still want them to roll a random prefix, how do we do this?
