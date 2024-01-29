// Code borrowd from https://github.com/quic-go/qtls-go1-20

package tls

import (
	"crypto/tls"
	"reflect"
	"unsafe"
)

func init() {
	if !structsEqual(&tls.ConnectionState{}, &connectionState{}) {
		panic("qtls.ConnectionState doesn't match")
	}
	if !structsEqual(&tls.ClientSessionState{}, &clientSessionState{}) {
		panic("qtls.ClientSessionState doesn't match")
	}
	if !structsEqual(&tls.SessionState{}, &sessionState{}) {
		panic("qtls.SessionState doesn't match")
	}
	if !structsEqual(&tls.CertificateRequestInfo{}, &certificateRequestInfo{}) {
		panic("qtls.CertificateRequestInfo doesn't match")
	}
	if !structsEqual(&tls.Config{}, &config{}) {
		panic("qtls.Config doesn't match")
	}
	if !structsEqual(&tls.ClientHelloInfo{}, &clientHelloInfo{}) {
		panic("qtls.ClientHelloInfo doesn't match")
	}
}

func toConnectionState(c connectionState) ConnectionState {
	return *(*ConnectionState)(unsafe.Pointer(&c))
}

func toClientSessionState(s *clientSessionState) *ClientSessionState {
	return (*ClientSessionState)(unsafe.Pointer(s))
}

func toSessionState(ss *sessionState) *SessionState {
	return (*SessionState)(unsafe.Pointer(ss))
}

func fromSessionState(ss *SessionState) *sessionState {
	return (*sessionState)(unsafe.Pointer(ss))
}

func fromClientSessionState(s *ClientSessionState) *clientSessionState {
	return (*clientSessionState)(unsafe.Pointer(s))
}

func toCertificateRequestInfo(i *certificateRequestInfo) *CertificateRequestInfo {
	return (*CertificateRequestInfo)(unsafe.Pointer(i))
}

func toConfig(c *config) *Config {
	return (*Config)(unsafe.Pointer(c))
}

func fromConfig(c *Config) *config {
	return (*config)(unsafe.Pointer(c))
}

func toClientHelloInfo(chi *clientHelloInfo) *ClientHelloInfo {
	return (*ClientHelloInfo)(unsafe.Pointer(chi))
}

func structsEqual(a, b interface{}) bool {
	return compare(reflect.TypeOf(a), reflect.TypeOf(b))
}

// compare compares two types and returns true if and only if
// they can be casted to each other safely.
// compare does not currently support Maps, Chan, UnsafePointer if reflect.DeepEqual fails.
// Support for these types can be added if needed.
// note that field names are still compared.
func compare(a, b reflect.Type) bool {

	if reflect.DeepEqual(a, b) {
		return true
	}

	if a.Kind() != b.Kind() {
		return false
	}

	if a.Kind() == reflect.Pointer || a.Kind() == reflect.Slice {
		return compare(a.Elem(), b.Elem())
	}

	if a.Kind() == reflect.Func {
		if a.NumIn() != b.NumIn() || a.NumOut() != b.NumOut() {
			return false
		}
		for i_in := 0; i_in < a.NumIn(); i_in++ {
			if !compare(a.In(i_in), b.In(i_in)) {
				return false
			}
		}
		for i_out := 0; i_out < a.NumOut(); i_out++ {
			if !compare(a.Out(i_out), b.Out(i_out)) {
				return false
			}
		}
		return true
	}

	if a.Kind() == reflect.Struct {

		if a.NumField() != b.NumField() {
			return false
		}

		for i := 0; i < a.NumField(); i++ {
			fa := a.Field(i)
			fb := b.Field(i)

			if !reflect.DeepEqual(fa.Index, fb.Index) || fa.Name != fb.Name ||
				fa.Anonymous != fb.Anonymous || fa.Offset != fb.Offset {
				return false
			}

			if !reflect.DeepEqual(fa.Type, fb.Type) {
				if !compare(fa.Type, fb.Type) {
					return false
				}
			}
		}

		return true
	}

	// TODO: add support for missing types
	return false
}

// InitSessionTicketKeys triggers the initialization of session ticket keys.
func InitSessionTicketKeys(conf *Config) {
	fromConfig(conf).ticketKeys(nil)
}
