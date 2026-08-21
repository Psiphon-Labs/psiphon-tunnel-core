# Ciphersuite Package

This package provides DTLS cipher suite implementations for GCM, CCM, and CBC modes.

## Benchmarking

The package includes comprehensive benchmarks for all cipher operations across multiple payload sizes.

**Note:** Benchmarks are excluded from regular test runs using build tags. You must specify `-tags=bench` to run them.

### Running all ciphersuite benchmarks

```bash
go test -tags=bench -bench=. -benchmem
```

### Running a specific benchmark

- GCM benchmarks only:

```bash
go test -tags=bench -bench=BenchmarkGCM -benchmem
```

- GCM `Encrypt` benchmark only:

```bash
go test -tags=bench -bench=BenchmarkGCMEncrypt -benchmem
```

- GCM `Decrypt` benchmark only:

```bash
go test -tags=bench -bench=BenchmarkGCMDecrypt -benchmem
```

- CCM benchmarks only:

```bash
go test -tags=bench -bench=BenchmarkCCM -benchmem
```

- CCM `Encrypt` benchmark only:

```bash
go test -tags=bench -bench=BenchmarkCCMEncrypt -benchmem
```

- CCM `Decrypt` benchmark only:

```bash
go test -tags=bench -bench=BenchmarkCCMDecrypt -benchmem
```

- CBC benchmarks only:

```bash
go test -tags=bench -bench=BenchmarkCBC -benchmem
```

- CBC `Encrypt` benchmark only:

```bash
go test -tags=bench -bench=BenchmarkCBCEncrypt -benchmem
```

- CBC `Decrypt` benchmark only:

```bash
go test -tags=bench -bench=BenchmarkCBCDecrypt -benchmem
```

- ChaCha20Poly1305 benchmarks only:

```bash
go test -tags=bench -bench=BenchmarkChaCha20Poly1305 -benchmem
```

- ChaCha20Poly1305 `Encrypt` benchmark only:

```bash
go test -tags=bench -bench=BenchmarkChaCha20Poly1305Encrypt -benchmem
```

- ChaCha20Poly1305 `Decrypt` benchmark only:

```bash
go test -tags=bench -bench=BenchmarkChaCha20Poly1305Decrypt -benchmem
```

- All ciphers, with 1KB payloads only

```bash
go test -tags=bench -bench=/1KB -benchmem
```

- All ciphers, with 16B payloads only

```bash
go test -tags=bench -bench=/16B -benchmem
```

### Benchmark Options

Increase benchmark time for more accurate results:

```bash
go test -tags=bench -bench=BenchmarkGCM -benchmem -benchtime=5s
```

Run benchmarks multiple times:

```bash
go test -tags=bench -bench=BenchmarkGCM -benchmem -count=5
```

### Understanding Results

Example output:

```
BenchmarkGCMEncrypt/016B-8  5895367  202.6 ns/op  78.99 MB/s   160 B/op  5 allocs/op
```

- `5895367`: Number of iterations
- `202.6 ns/op`: Time per operation
- `78.99 MB/s`: Throughput
- `160 B/op`: Bytes allocated per operation
- `5 allocs/op`: Number of allocations per operation


## Profiling

Generate CPU profile:

```bash
go test -tags=bench -bench=BenchmarkGCMEncrypt -benchmem -cpuprofile=cpu.prof
go tool pprof -top cpu.prof
```

Generate memory profile:

```bash
go test -tags=bench -bench=BenchmarkGCMEncrypt -benchmem -memprofile=mem.prof
go tool pprof -top -alloc_objects mem.prof
```