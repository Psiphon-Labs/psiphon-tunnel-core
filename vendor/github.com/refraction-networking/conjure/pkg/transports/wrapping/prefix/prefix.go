package prefix

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	// Earliest client library version ID that supports destination port randomization
	randomizeDstPortMinVersion uint = 3

	// port range boundaries for prefix transport when randomizing
	portRangeMin = 1024
	portRangeMax = 65535
)

const minTagLength = 64

// const minTagLengthBase64 = 88

// prefix provides the elements required for independent prefixes to be usable as part of the
// transport used by the server specifically.
type prefix struct {
	// // Regular expression to match
	// *regexp.Regexp

	// // Function allowing decode / transformation of obfuscated ID bytes before attempting to
	// // de-obfuscate them. Example - base64 decode.
	// // [FUTURE WORK]
	// tagDecode func([]byte) ([]byte, int, error)

	// // Function allowing decode / transformation stream bytes before attempting to forward them.
	// // Example - base64 decode.
	// // [FUTURE WORK]
	// streamDecode func([]byte) ([]byte, int, error)

	// Static string to match to rule out protocols without using a regex.
	StaticMatch []byte

	// Offset in a byte array where we expect the identifier to start.
	Offset int

	// Minimum length to guarantee we have received the whole identifier
	// (i.e. return ErrTryAgain)
	MinLen int

	// Maximum length after which we can rule out prefix if we have not found a known identifier
	// (i.e. return ErrNotTransport)
	MaxLen int

	// Minimum client library version that supports this prefix
	MinVer uint

	// Default DST Port for this prefix. We are not bound by client_lib_version (yet) so we can set the
	// default destination port for each prefix individually
	DefaultDstPort uint16

	// Flush Indicates whether the client is expected to flush the write buffer after the prefix
	// before writing the tag. This would allow the whole first packet to be a prefix (with no tag).
	Flush int32
}

// PrefixID provide an integer Identifier for each individual prefixes allowing clients to indicate
// to the station the prefix they intend to connect with.
type PrefixID int

const (
	Rand PrefixID = -1 + iota
	Min
	GetLong
	PostLong
	HTTPResp
	TLSClientHello
	TLSServerHello
	TLSAlertWarning
	TLSAlertFatal
	DNSOverTCP
	OpenSSH2

	// GetShortBase64
)

var (
	// ErrUnknownPrefix indicates that the provided Prefix ID is unknown to the transport object.
	ErrUnknownPrefix = errors.New("unknown / unsupported prefix")

	// ErrBadParams indicates that the parameters provided to a call on the server side do not make
	// sense in the context that they are provided and the registration will be ignored.
	ErrBadParams = errors.New("bad parameters provided")

	// ErrIncorrectPrefix indicates that tryFindRegistration found a valid registration based on
	// the obfuscated tag, however the prefix that it matched was not the prefix indicated in the
	// registration.
	ErrIncorrectPrefix = errors.New("found connection for unexpected prefix")

	// ErrIncorrectTransport indicates that tryFindRegistration found a valid registration based on
	// the obfuscated tag, however the prefix that it matched was not the prefix indicated in the
	// registration.
	ErrIncorrectTransport = errors.New("found registration w/ incorrect transport type")
)

// Name returns the human-friendly name of the prefix.
func (id PrefixID) Name() string {
	switch id {
	case Min:
		return "Min"
	case GetLong:
		return "GetLong"
	case PostLong:
		return "PostLong"
	case HTTPResp:
		return "HTTPResp"
	case TLSClientHello:
		return "TLSClientHello"
	case TLSServerHello:
		return "TLSServerHello"
	case TLSAlertWarning:
		return "TLSAlertWarning"
	case TLSAlertFatal:
		return "TLSAlertFatal"
	case DNSOverTCP:
		return "DNSOverTCP"
	case OpenSSH2:
		return "OpenSSH2"

	// case GetShort:
	// 	return "GetShort"
	default:
		return "other"
	}
}

// defaultPrefixes provides the prefixes supported by default for use when
// initializing the prefix transport.
var defaultPrefixes = map[PrefixID]prefix{
	//Min - Empty prefix
	Min: {[]byte{}, 0, minTagLength, minTagLength, randomizeDstPortMinVersion, 443, NoAddedFlush},
	// HTTP GET
	GetLong: {[]byte("GET / HTTP/1.1\r\n"), 16, 16 + minTagLength, 16 + minTagLength, randomizeDstPortMinVersion, 80, NoAddedFlush},
	// HTTP POST
	PostLong: {[]byte("POST / HTTP/1.1\r\n"), 17, 17 + minTagLength, 17 + minTagLength, randomizeDstPortMinVersion, 80, NoAddedFlush},
	// HTTP Response
	HTTPResp: {[]byte("HTTP/1.1 200\r\n"), 14, 14 + minTagLength, 14 + minTagLength, randomizeDstPortMinVersion, 80, NoAddedFlush},
	// TLS Client Hello
	TLSClientHello: {[]byte("\x16\x03\x03\x40\x00\x01"), 6, 6 + minTagLength, 6 + minTagLength, randomizeDstPortMinVersion, 443, NoAddedFlush},
	// TLS Server Hello
	TLSServerHello: {[]byte("\x16\x03\x03\x40\x00\x02\r\n"), 8, 8 + minTagLength, 8 + minTagLength, randomizeDstPortMinVersion, 443, NoAddedFlush},
	// TLS Alert Warning
	TLSAlertWarning: {[]byte("\x15\x03\x01\x00\x02"), 5, 5 + minTagLength, 5 + minTagLength, randomizeDstPortMinVersion, 443, NoAddedFlush},
	// TLS Alert Fatal
	TLSAlertFatal: {[]byte("\x15\x03\x02\x00\x02"), 5, 5 + minTagLength, 5 + minTagLength, randomizeDstPortMinVersion, 443, NoAddedFlush},
	// DNS over TCP
	DNSOverTCP: {[]byte("\x05\xDC\x5F\xE0\x01\x20"), 6, 6 + minTagLength, 6 + minTagLength, randomizeDstPortMinVersion, 53, NoAddedFlush},
	// SSH-2.0-OpenSSH_8.9p1
	OpenSSH2: {[]byte("SSH-2.0-OpenSSH_8.9p1"), 21, 21 + minTagLength, 21 + minTagLength, randomizeDstPortMinVersion, 22, NoAddedFlush},

	// // HTTP GET base64 in url min tag length 88 because 64 bytes base64 encoded should be length 88
	// GetShort: {base64TagDecode, []byte("GET /"), 5, 5 + 88, 5 + 88, randomizeDstPortMinVersion},
}

// Transport provides a struct implementing the Transport, WrappingTransport,
// PortRandomizingTransport, and FixedPortTransport interfaces.
type Transport struct {
	SupportedPrefixes map[PrefixID]prefix
	TagObfuscator     transports.Obfuscator
	Privkey           [32]byte
}

// Name returns the human-friendly name of the transport, implementing the
// Transport interface..
func (Transport) Name() string { return "PrefixTransport" }

// LogPrefix returns the prefix used when including this transport in logs,
// implementing the Transport interface.
func (Transport) LogPrefix() string { return "PREF" }

// GetIdentifier takes in a registration and returns an identifier for it. This
// identifier should be unique for each registration on a given phantom;
// registrations on different phantoms can have the same identifier.
func (Transport) GetIdentifier(d transports.Registration) string {
	return string(core.ConjureHMAC(d.SharedSecret(), "PrefixTransportHMACString"))
}

// GetProto returns the next layer protocol that the transport uses. Implements
// the Transport interface.
func (Transport) GetProto() pb.IPProto {
	return pb.IPProto_Tcp
}

// ParseParams gives the specific transport an option to parse a generic object into parameters
// provided by the client during registration. This Transport was written after RandomizeDstPort was
// added, so it should not be usable by clients who don't support destination port randomization.
func (t Transport) ParseParams(libVersion uint, data *anypb.Any) (any, error) {
	if data == nil {
		return nil, nil
	}

	if libVersion < randomizeDstPortMinVersion {
		return nil, fmt.Errorf("client couldn't support this transport")
	}

	var m = &pb.PrefixTransportParams{}
	err := transports.UnmarshalAnypbTo(data, m)

	// Check if this is a prefix that we know how to parse, if not, drop the registration because
	// we will be unable to pick up.
	if _, ok := t.SupportedPrefixes[PrefixID(m.GetPrefixId())]; !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnknownPrefix, m.GetPrefixId())
	}

	return m, err
}

// ParamStrings returns an array of tag string that will be added to tunStats when a proxy session
// is closed.
func (t Transport) ParamStrings(p any) []string {
	params, ok := p.(*pb.PrefixTransportParams)
	if !ok {
		return nil
	}

	out := []string{PrefixID(params.GetPrefixId()).Name()}

	return out
}

// GetDstPort Given the library version, a seed, and a generic object
// containing parameters the transport should be able to return the
// destination port that a clients phantom connection will attempt to reach
func (t Transport) GetDstPort(libVersion uint, seed []byte, params any) (uint16, error) {

	if libVersion < randomizeDstPortMinVersion {
		return 0, fmt.Errorf("client couldn't support this transport")
	}
	parameters, ok := params.(*pb.PrefixTransportParams)
	if !ok {
		return 0, fmt.Errorf("%w: incorrect type", ErrBadParams)
	}

	if parameters == nil {
		return 0, fmt.Errorf("%w: nil params", ErrBadParams)
	}

	prefix := parameters.GetPrefixId()
	p, ok := t.SupportedPrefixes[PrefixID(prefix)]
	if !ok {
		return 0, ErrUnknownPrefix
	}

	if parameters.GetRandomizeDstPort() {
		return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
	}

	return p.DefaultDstPort, nil
}

// WrapConnection attempts to wrap the given connection in the transport. It
// takes the information gathered so far on the connection in data, attempts to
// identify itself, and if it positively identifies itself wraps the connection
// in the transport, returning a connection that's ready to be used by others.
//
// If the returned error is nil or non-nil and non-{ transports.ErrTryAgain,
// transports.ErrNotTransport }, the caller may no longer use data or conn.
func (t Transport) WrapConnection(data *bytes.Buffer, c net.Conn, originalDst net.IP, regManager transports.RegManager) (transports.Registration, net.Conn, error) {
	if data.Len() < minTagLength {
		return nil, nil, transports.ErrTryAgain
	}

	reg, err := t.tryFindReg(data, originalDst, regManager)
	if err != nil {
		return nil, nil, err
	}

	return reg, transports.PrependToConn(c, data), nil
}

func (t Transport) tryFindReg(data *bytes.Buffer, originalDst net.IP, regManager transports.RegManager) (transports.Registration, error) {
	if data.Len() == 0 {
		return nil, transports.ErrTryAgain
	}

	var eWrongPrefix error = nil
	err := transports.ErrNotTransport
	for id, prefix := range t.SupportedPrefixes {
		if len(prefix.StaticMatch) > 0 {
			matchLen := min(len(prefix.StaticMatch), data.Len())
			if !bytes.Equal(prefix.StaticMatch[:matchLen], data.Bytes()[:matchLen]) {
				continue
			}
		}

		if data.Len() < prefix.MinLen {
			// the data we have received matched at least one static prefix, but was not long
			// enough to extract the tag - go back and read more, continue checking if any
			// of the other prefixes match. If not we want to indicate to read more, not
			// give up because we may receive the rest of the match.
			err = transports.ErrTryAgain
			continue
		}

		if data.Len() < prefix.Offset+minTagLength && data.Len() < prefix.MaxLen {
			err = transports.ErrTryAgain
			continue
		} else if data.Len() < prefix.MaxLen {
			continue
		}

		var obfuscatedID []byte
		var forwardBy = minTagLength
		// var errN error
		// if prefix.fn != nil {
		// 	obfuscatedID, forwardBy, errN = prefix.tagDecode(data.Bytes()[prefix.Offset:])
		// 	if errN != nil || len(obfuscatedID) != minTagLength {
		// 		continue
		// 	}
		// } else {
		obfuscatedID = data.Bytes()[prefix.Offset : prefix.Offset+minTagLength]
		// }

		hmacID, err := t.TagObfuscator.TryReveal(obfuscatedID, t.Privkey)
		if err != nil || hmacID == nil {
			continue
		}

		reg, ok := regManager.GetRegistrations(originalDst)[string(hmacID)]
		if !ok {
			continue
		}

		if reg.TransportType() != pb.TransportType_Prefix {
			return nil, ErrIncorrectTransport
		} else if params, ok := reg.TransportParams().(*pb.PrefixTransportParams); ok {
			if params == nil || params.GetPrefixId() != int32(id) {
				// If the registration we found has no params specified (invalid and shouldn't have
				// been ingested) or if the prefix ID does not match the expected prefix, set the
				// err to return if we can't match any other prefixes.
				eWrongPrefix = fmt.Errorf("%w: e %d != %d", ErrIncorrectPrefix, params.GetPrefixId(), id)
				continue
			}
		}

		// We don't want to forward the prefix or Tag bytes, but if any message
		// remains we do want to forward it.
		data.Next(prefix.Offset + forwardBy)

		return reg, nil
	}

	if errors.Is(err, transports.ErrNotTransport) && errors.Is(eWrongPrefix, ErrIncorrectPrefix) {
		// If we found a match and it was the only one that matched (i.e. none of the other prefixes
		// could possibly match even if we read more bytes). Then something went wrong and the
		// client is attempting to connect with the wrong prefix.
		return nil, ErrIncorrectPrefix
	}

	return nil, err
}

// New Given a private key this builds the server side transport with an EMPTY set of supported
// prefixes. The optional filepath specifies a file from which to read extra prefixes. If provided
// only the first variadic string will be used to attempt to parse prefixes. There can be no
// colliding PrefixIDs - within the file first defined takes precedence.
func New(privkey [32]byte, filepath ...string) (*Transport, error) {
	var prefixes map[PrefixID]prefix = make(map[PrefixID]prefix)
	var err error
	if len(filepath) > 0 && filepath[0] != "" {
		prefixes, err = tryParsePrefixes(filepath[0])
		if err != nil {
			return nil, err
		}
	}
	return &Transport{
		Privkey:           privkey,
		SupportedPrefixes: prefixes,
		TagObfuscator:     transports.CTRObfuscator{},
	}, nil
}

// Default Given a private key this builds the server side transport with the DEFAULT set of supported
// prefixes. The optional filepath specifies a file from which to read extra prefixes.
// If provided only the first variadic string will be used to attempt to parse prefixes. There can
// be no colliding PrefixIDs - file defined prefixes take precedent over defaults, and within the
// file first defined takes precedence.
func Default(privkey [32]byte, filepath ...string) (*Transport, error) {
	t, err := New(privkey, filepath...)
	if err != nil {
		return nil, err
	}

	for k, v := range defaultPrefixes {
		if _, ok := t.SupportedPrefixes[k]; !ok {
			t.SupportedPrefixes[k] = v
		}
	}
	return t, nil
}

// DefaultSet builds a hollow version of the transport with the DEFAULT set of supported
// prefixes. This is useful in instances where we just need to check whether the prefix ID is known,
// not actually handle any major operations (tryFindReg / WrapConn)
func DefaultSet() *Transport {
	var prefixes map[PrefixID]prefix = make(map[PrefixID]prefix)
	for k, v := range defaultPrefixes {
		if _, ok := prefixes[k]; !ok {
			prefixes[k] = v
		}
	}
	return &Transport{
		SupportedPrefixes: prefixes,
	}
}

func tryParsePrefixes(filepath string) (map[PrefixID]prefix, error) {
	return nil, nil
}

func applyDefaultPrefixes() {
	// if at any point we need to do init on the prefixes (i.e compiling regular expressions) it
	// should happen here.
	for ID, p := range defaultPrefixes {
		DefaultPrefixes[ID] = &clientPrefix{p.StaticMatch, ID, p.DefaultDstPort, p.Flush}
	}
}

func init() {
	applyDefaultPrefixes()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// func base64TagDecode(encoded []byte) ([]byte, int, error) {
// 	if len(encoded) < minTagLengthBase64 {
// 		return nil, 0, fmt.Errorf("not enough to decode")
// 	}
// 	buf := make([]byte, minTagLengthBase64)
// 	n, err := base64.StdEncoding.Decode(buf, encoded[:minTagLengthBase64])
// 	if err != nil {
// 		return nil, 0, err
// 	}

// 	return buf[:n], minTagLengthBase64, nil
// }
