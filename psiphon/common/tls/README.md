This is a fork of go 1.7.3 `crypto/tls`. Changes are almost entirely contained in two new files, `obfuscated.go` and `obfuscated_test.go`, which implement obfuscated session tickets, a network obfuscation protocol based on TLS.

The obfuscated session tickets protocol is implemented as an optional mode enabled through the `Config`. The implementation requires access to `crypto.tls` internals.

Apart from this optional mode, this is a stock `crypto/tls`.
