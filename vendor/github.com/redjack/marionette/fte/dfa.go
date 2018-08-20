package fte

// #cgo CXXFLAGS: -std=c++11
// #cgo LDFLAGS: -ldl ${SRCDIR}/../third_party/libs/libgmp.a
// #include <stdlib.h>
// #include <stdint.h>
// void* _dfa_new(char *tbl, const uint32_t max_len);
// void _dfa_delete(void *ptr);
// int _dfa_rank(void *ptr, const char *s, const size_t ssz, char **out, size_t *sz);
// int _dfa_unrank(void *ptr, const char *in, const size_t insz, char **out, size_t *sz);
// char* _dfa_getNumWordsInLanguage(void *ptr, const uint32_t min_word_length, const uint32_t max_word_length, char **out, size_t *sz);
import "C"

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"unsafe"

	"github.com/redjack/marionette/regex2dfa"
)

var (
	ErrLanguageIsEmptySet = errors.New("fte: language is empty set")
)

type DFA struct {
	mu       sync.RWMutex
	ptr      unsafe.Pointer
	capacity int

	regex string
	n     int
}

func NewDFA(regex string, n int) (*DFA, error) {
	tbl, err := regex2dfa.Regex2DFA(regex)
	if err != nil {
		return nil, err
	}

	ctbl := C.CString(tbl)
	defer C.free(unsafe.Pointer(ctbl))

	ptr := C._dfa_new(ctbl, C.uint32_t(n))
	dfa := &DFA{ptr: ptr, regex: regex, n: n}

	// Calculate capacity.
	if err := dfa.calculateCapacity(); err != nil {
		dfa.Close()
		return nil, err
	}

	return dfa, nil
}

func (dfa *DFA) Close() error {
	if dfa.ptr != nil {
		C._dfa_delete(dfa.ptr)
		dfa.ptr = nil
	}
	return nil
}

// Regex returns the regex passed into the DFA.
func (dfa *DFA) Regex() string { return dfa.regex }

// N returns the n passed into the DFA.
func (dfa *DFA) N() int { return dfa.n }

// Capacity returns the capacity of the encoder.
func (dfa *DFA) Capacity() int {
	return dfa.capacity
}

func (dfa *DFA) calculateCapacity() error {
	wordsInSlice, err := dfa.NumWordsInLanguage(dfa.n, dfa.n)
	if err != nil {
		return err
	} else if wordsInSlice.Cmp(big.NewInt(0)) == 0 {
		return ErrLanguageIsEmptySet
	}

	dfa.capacity = (Log2(wordsInSlice) - 1) / 8 // div by 8 to convert to bytes
	return nil
}

// Rank maps s into an integer ranking.
func (dfa *DFA) Rank(s string) (*big.Int, error) {
	dfa.mu.Lock()
	defer dfa.mu.Unlock()

	cs := C.CString(s)
	defer C.free(unsafe.Pointer(cs))

	var cout *C.char
	var sz C.size_t
	errno := C._dfa_rank(dfa.ptr, cs, C.size_t(len(s)), &cout, &sz)
	out := C.GoStringN(cout, C.int(sz))
	C.free(unsafe.Pointer(cout))

	if errno != 0 {
		return nil, fmt.Errorf("fte.DFA.Rank: %s", out)
	}

	var rank big.Int
	if _, ok := rank.SetString(out, 10); !ok {
		return nil, fmt.Errorf("fte.Rank: cannot parse returned big.Int: %q", out)
	}
	return &rank, nil
}

// Unrank reverses the map from an integer to a string.
func (dfa *DFA) Unrank(rank *big.Int) (string, error) {
	dfa.mu.Lock()
	defer dfa.mu.Unlock()

	rankStr := rank.String()
	cin := C.CString(rankStr)
	defer C.free(unsafe.Pointer(cin))

	var cout *C.char
	var sz C.size_t
	if ret := C._dfa_unrank(dfa.ptr, cin, C.size_t(len(rankStr)), &cout, &sz); ret != 0 {
		return "", fmt.Errorf("fte.Unrank: error")
	}

	out := C.GoStringN(cout, C.int(sz))
	C.free(unsafe.Pointer(cout))
	return out, nil
}

func (dfa *DFA) NumWordsInSlice(n int) (*big.Int, error) {
	return dfa.NumWordsInLanguage(n, n)
}

func (dfa *DFA) NumWordsInLanguage(min, max int) (*big.Int, error) {
	var cout *C.char
	var sz C.size_t
	C._dfa_getNumWordsInLanguage(dfa.ptr, C.uint32_t(min), C.uint32_t(max), &cout, &sz)

	out := C.GoStringN(cout, C.int(sz))
	C.free(unsafe.Pointer(cout))

	var rank big.Int
	if _, ok := rank.SetString(out, 10); !ok {
		return nil, fmt.Errorf("fte.NumWordsInLanguage: cannot parse returned big.Int: %q", out)
	}
	return &rank, nil
}

// Log2 returns floor(log2(v)).
func Log2(v *big.Int) int {
	for i := 1; ; i++ {
		var exp big.Int
		exp.Exp(big.NewInt(2), big.NewInt(int64(i)), nil)
		if cmp := exp.Cmp(v); cmp == 0 {
			return i
		} else if cmp == 1 {
			return i - 1
		}
	}
}
