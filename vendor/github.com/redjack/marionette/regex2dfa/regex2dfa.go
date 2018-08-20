package regex2dfa

// #cgo CXXFLAGS: -std=c++11 -DMARIONETTE -I${SRCDIR}/../third_party/re2/ -I${SRCDIR}/../third_party/openfst/src/include/
// #cgo LDFLAGS: -ldl ${SRCDIR}/../third_party/libs/libfst.a ${SRCDIR}/../third_party/libs/libfstscript.a ${SRCDIR}/../third_party/libs/libre2.a
// #include <stdlib.h>
// #include <stdint.h>
// int _regex2dfa(const char* input_regex, uint32_t input_regex_len, char **out, size_t *sz);
import "C"

import (
	"errors"
	"sync"
	"unsafe"
)

// ErrInternal is returned any error occurs.
var ErrInternal = errors.New("regex2dfa: internal error")

// Shared mutex for all Regex2DFA calls.
var mu sync.Mutex

// Regex2DFA converts regex into a DFA table.
func Regex2DFA(regex string) (string, error) {
	mu.Lock()
	defer mu.Unlock()

	regex = "^" + regex + "$"

	cregex := C.CString(regex)
	defer C.free(unsafe.Pointer(cregex))

	var cout *C.char
	var sz C.size_t
	if errno := C._regex2dfa(cregex, C.uint32_t(len(regex)), &cout, &sz); errno != 0 {
		return "", ErrInternal
	}
	out := C.GoStringN(cout, C.int(sz))
	C.free(unsafe.Pointer(cout))

	return out, nil
}

// MustRegex2DFA converts regex into a DFA table. Panic on error.
func MustRegex2DFA(regex string) string {
	s, err := Regex2DFA(regex)
	if err != nil {
		panic(err)
	}
	return s
}
