shared:
	go build -buildmode=c-shared -o psi.dylib main.go
.PHONY: shared

static:
	go build -buildmode=c-archive -o psi.a main.go

.PHONY: static
