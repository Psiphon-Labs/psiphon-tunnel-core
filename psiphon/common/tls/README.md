This is a fork of go 1.8 `crypto/tls`.

The files `obfuscated.go` and `obfuscated_test.go` implement obfuscated session tickets, a network obfuscation protocol based on TLS. The obfuscated session tickets protocol is implemented as an optional mode enabled through the `Config`. The implementation requires access to `crypto.tls` internals.

The `EmulateChrome` feature configures the TLS ClientHello to match the ClientHello message sent by a modern Chrome browser.

All customizations are tagged with `// [Psiphon]` comments.