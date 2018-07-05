shared:
	go build -buildmode=c-shared -o PsiphonTunnel.dylib PsiphonTunnel.go
.PHONY: shared

static:
	go build -buildmode=c-archive -o PsiphonTunnel.a PsiphonTunnel.go

.PHONY: static
