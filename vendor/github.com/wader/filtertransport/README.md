#### Filtering go http transport and proxy handler

Useful when you want to limit what clients can connect to. Default transport
and proxy handler filters local, private and link local networks.

See [client](cmd/filterclient/main.go) and [proxy](cmd/filterproxy/main.go) examples.

#### Known issues

- Probably messes up IPv6 happy eyeballs

#### License

filtertransport is licensed under the MIT license. See [LICENSE](LICENSE) for the full license text.
