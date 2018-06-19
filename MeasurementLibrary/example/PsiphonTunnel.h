/* Created by "go tool cgo" - DO NOT EDIT. */

/* package command-line-arguments */

/* Start of preamble from import "C" comments.  */




/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef __SIZE_TYPE__ GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

typedef struct { const char *p; GoInt n; } GoString;
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif


// Start starts the controller and returns once either of the following has occured: an active tunnel has been
// established, the timeout has elapsed before an active tunnel could be established or an error has occured.
//
// Start returns a StartResult object serialized as a JSON string in the form of a null-terminated buffer of C chars.
// Start will return,
// On success:
//   {
//     "result_code": 0,
//     "bootstrap_time": <time_to_establish_tunnel>,
//     "http_proxy_port": <http_proxy_port_num>,
//     "socks_proxy_port": <socks_proxy_port_num>
//   }
//
// On timeout:
//  {
//    "result_code": 1,
//    "error": <error message>
//  }
//
// On other error:
//   {
//     "result_code": 2,
//     "error": <error message>
//   }
//
// networkID should be not be blank and should follow the format specified by
// https://godoc.org/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon#NetworkIDGetter.

extern char* Start(GoString p0, GoString p1, GoString p2, GoInt64 p3);

// Stop stops the controller if it is running and waits for it to clean up and exit.
//
// Stop should always be called after a successful call to Start to ensure the
// controller is not left running.

extern void Stop();

#ifdef __cplusplus
}
#endif
