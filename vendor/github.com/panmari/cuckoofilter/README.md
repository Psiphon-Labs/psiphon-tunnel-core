# Cuckoo Filter

[![GitHub go.mod Go version of a Go module](https://img.shields.io/github/go-mod/go-version/panmari/cuckoofilter.svg)](https://github.com/panmari/cuckoofilter)
[![GoDoc](https://godoc.org/github.com/panmari/cuckoofilter?status.svg)](https://godoc.org/github.com/panmari/cuckoofilter)
[![GoReportCard](https://goreportcard.com/badge/github.com/panmari/cuckoofilter)](https://goreportcard.com/report/github.com/panmari/cuckoofilter)

Well-tuned, production-ready cuckoo filter that performs best in class for low false positive rates (at around 0.01%). For details, see [full evaluation](https://panmari.github.io/2020/10/09/probabilistic-filter-golang.html).

## Background

Cuckoo filter is a Bloom filter replacement for approximated set-membership queries. While Bloom filters are well-known space-efficient data structures to serve queries like "if item x is in a set?", they do not support deletion. Their variances to enable deletion (like counting Bloom filters) usually require much more space.

Cuckoo filters provide the flexibility to add and remove items dynamically. A cuckoo filter is based on cuckoo hashing (and therefore named as cuckoo filter). It is essentially a cuckoo hash table storing each key's fingerprint. Cuckoo hash tables can be highly compact, thus a cuckoo filter could use less space than conventional Bloom filters, for applications that require low false positive rates (< 3%).

["Cuckoo Filter: Better Than Bloom" by Bin Fan, Dave Andersen and Michael Kaminsky](https://www.cs.cmu.edu/~dga/papers/cuckoo-conext2014.pdf)

## Implementation details

The paper cited above leaves several parameters to choose. In this implementation

1. Every element has 2 possible bucket indices
2. Buckets have a static size of 4 fingerprints
3. Fingerprints have a static size of 16 bits

1 and 2 are suggested to be the optimum by the authors. The choice of 3 comes down to the desired false positive rate. Given a target false positive rate of `r` and a bucket size `b`, they suggest choosing the fingerprint size `f` using

    f >= log2(2b/r) bits

With the 16 bit fingerprint size in this repository, you can expect `r ~= 0.0001`.
[Other implementations](https://github.com/seiflotfy/cuckoofilter) use 8 bit, which correspond to a false positive rate of `r ~= 0.03`.

## Example usage

```golang
import (
	"fmt"

	cuckoo "github.com/panmari/cuckoofilter"
)

func Example() {
	cf := cuckoo.NewFilter(1000)

	cf.Insert([]byte("pizza"))
	cf.Insert([]byte("tacos"))
	cf.Insert([]byte("tacos")) // Re-insertion is possible.

	fmt.Println(cf.Lookup([]byte("pizza")))
	fmt.Println(cf.Lookup([]byte("missing")))

	cf.Reset()
	fmt.Println(cf.Lookup([]byte("pizza")))
	// Output:
	// true
	// false
	// false
}
```

For more examples, see [the example tests](https://github.com/panmari/cuckoofilter/blob/master/example_test.go).
Operations on a filter are not thread safe by default. 
See [this example](example_threadsafe_test.go) for using the filter concurrently.
