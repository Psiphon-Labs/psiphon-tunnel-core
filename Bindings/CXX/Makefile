shared:
	go build -buildmode=c-shared -o psi.dylib psi.go
.PHONY: shared

static:
	go build -buildmode=c-archive -o psi.a psi.go

.PHONY: static
