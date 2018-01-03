semaphore
=========
[![Build Status](https://travis-ci.org/marusama/semaphore.svg?branch=master)](https://travis-ci.org/marusama/semaphore)
[![Go Report Card](https://goreportcard.com/badge/github.com/marusama/semaphore)](https://goreportcard.com/report/github.com/marusama/semaphore)
[![Coverage Status](https://coveralls.io/repos/github/marusama/semaphore/badge.svg?branch=master)](https://coveralls.io/github/marusama/semaphore?branch=master)
[![GoDoc](https://godoc.org/github.com/kamilsk/semaphore?status.svg)](https://godoc.org/github.com/marusama/semaphore)
[![License](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](LICENSE)

Fast resizable golang semaphore based on CAS

* allows weighted acquire/release;
* supports cancellation via context;
* allows change semaphore limit after creation;
* faster than channels based semaphores.

### Usage
Initiate
```go
import "github.com/marusama/semaphore"
...
sem := semaphore.New(5) // new semaphore with limit=5
```
Acquire
```go
sem.Acquire(ctx, n)     // acquire n with context
sem.TryAcquire(n)       // try acquire n without blocking 
...
ctx := context.WithTimeout(context.Background(), time.Second)
sem.Acquire(ctx, n)     // acquire n with timeout
``` 
Release
```go
sem.Release(n)          // release n
```
Change semaphore limit
```go
sem.SetLimit(new_limit) // set new semaphore limit
```


### Some benchmarks
Run on MacBook Pro (early 2015) with 2,7GHz Core i5 cpu and 16GB DDR3 ram:
```text
// this semaphore:
BenchmarkSemaphore_Acquire_Release_under_limit_simple-4                   	50000000	        31.1 ns/op	       0 B/op	       0 allocs/op
BenchmarkSemaphore_Acquire_Release_under_limit-4                          	 1000000	      1383 ns/op	       0 B/op	       0 allocs/op
BenchmarkSemaphore_Acquire_Release_over_limit-4                           	  100000	     13468 ns/op	      24 B/op	       0 allocs/op


// some other implementations:

// golang.org/x/sync/semaphore:
BenchmarkXSyncSemaphore_Acquire_Release_under_limit_simple-4              	30000000	        51.8 ns/op	       0 B/op	       0 allocs/op
BenchmarkXSyncSemaphore_Acquire_Release_under_limit-4                     	  500000	      2655 ns/op	       0 B/op	       0 allocs/op
BenchmarkXSyncSemaphore_Acquire_Release_over_limit-4                      	   20000	    100004 ns/op	   15991 B/op	     299 allocs/op

// github.com/abiosoft/semaphore:
BenchmarkAbiosoftSemaphore_Acquire_Release_under_limit_simple-4           	 5000000	       269 ns/op	       0 B/op	       0 allocs/op
BenchmarkAbiosoftSemaphore_Acquire_Release_under_limit-4                  	  300000	      5602 ns/op	       0 B/op	       0 allocs/op
BenchmarkAbiosoftSemaphore_Acquire_Release_over_limit-4                   	   30000	     54090 ns/op	       0 B/op	       0 allocs/op

// github.com/dropbox/godropbox
BenchmarkDropboxBoundedSemaphore_Acquire_Release_under_limit_simple-4     	20000000	        99.6 ns/op	       0 B/op	       0 allocs/op
BenchmarkDropboxBoundedSemaphore_Acquire_Release_under_limit-4            	 1000000	      1343 ns/op	       0 B/op	       0 allocs/op
BenchmarkDropboxBoundedSemaphore_Acquire_Release_over_limit-4             	  100000	     35735 ns/op	       0 B/op	       0 allocs/op
BenchmarkDropboxUnboundedSemaphore_Acquire_Release_under_limit_simple-4   	30000000	        56.0 ns/op	       0 B/op	       0 allocs/op
BenchmarkDropboxUnboundedSemaphore_Acquire_Release_under_limit-4          	  500000	      2871 ns/op	       0 B/op	       0 allocs/op
BenchmarkDropboxUnboundedSemaphore_Acquire_Release_over_limit-4           	   30000	     41089 ns/op	       0 B/op	       0 allocs/op

// github.com/kamilsk/semaphore
BenchmarkKamilskSemaphore_Acquire_Release_under_limit_simple-4            	10000000	       170 ns/op	      16 B/op	       1 allocs/op
BenchmarkKamilskSemaphore_Acquire_Release_under_limit-4                   	  500000	      3023 ns/op	     160 B/op	      10 allocs/op
BenchmarkKamilskSemaphore_Acquire_Release_over_limit-4                    	   20000	     67687 ns/op	    1600 B/op	     100 allocs/op

// github.com/pivotal-golang/semaphore
BenchmarkPivotalGolangSemaphore_Acquire_Release_under_limit_simple-4      	 1000000	      1006 ns/op	     136 B/op	       2 allocs/op
BenchmarkPivotalGolangSemaphore_Acquire_Release_under_limit-4             	  100000	     11837 ns/op	    1280 B/op	      20 allocs/op
BenchmarkPivotalGolangSemaphore_Acquire_Release_over_limit-4              	   10000	    128890 ns/op	   12800 B/op	     200 allocs/op

```
You can rerun these benchmarks, just checkout `benchmarks` branch and run `go test -bench=. -benchmem ./bench/...`
