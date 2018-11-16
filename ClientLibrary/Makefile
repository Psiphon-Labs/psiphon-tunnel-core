shared:
	go build -buildmode=c-shared -o libpsiphontunnel.so PsiphonTunnel.go
.PHONY: shared

static:
	go build -buildmode=c-archive -o libpsiphontunnel.a PsiphonTunnel.go

clean:
	rm libpsiphontunnel.so libpsiphontunnel.h

.PHONY: static
