package decoy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"strings"
	"time"

	"github.com/refraction-networking/conjure/pkg/client/assets"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/station/log"
	pb "github.com/refraction-networking/conjure/proto"
	td "github.com/refraction-networking/gotapdance/tapdance"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// utils.go contains functions needed for the decoy-registrar specifically
// that do not have a ConjureReg, ConjureSession, DecoyRegistrar, etc receiver.
// Most functions are taken from gotapdance/tapdance/utils.go

// The key argument should be the AES key, either 16 or 32 bytes
// to select AES-128 or AES-256.
func aesGcmEncrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGcmCipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesGcmCipher.Seal(nil, iv, plaintext, nil), nil
}

// Tries to get crypto random int in range [min, max]
// In case of crypto failure -- return insecure pseudorandom
func getRandInt(min int, max int) int {
	// I can't believe Golang is making me do that
	// Flashback to awful C/C++ libraries
	diff := max - min
	if diff < 0 {
		// r.logger.Warningf("getRandInt(): max is less than min")
		min = max
		diff *= -1
	} else if diff == 0 {
		return min
	}
	var v int64
	err := binary.Read(rand.Reader, binary.LittleEndian, &v)
	if v < 0 {
		v *= -1
	}
	if err != nil {
		// r.logger.Warningf("Unable to securely get getRandInt(): " + err.Error())
		v = mrand.Int63()
	}
	return min + int(v%int64(diff+1))
}

// returns random duration between min and max in milliseconds
func getRandomDuration(min int, max int) time.Duration {
	return time.Millisecond * time.Duration(getRandInt(min, max))
}

// Converts provided duration to raw milliseconds.
// Returns a pointer to u32, because protobuf wants pointers.
// Max valid input duration (that fits into uint32): 49.71 days.
func durationToU32ptrMs(d time.Duration) *uint32 {
	i := uint32(d.Milliseconds())
	return &i
}

func rttInt(millis uint32) int {
	defaultValue := 300
	if millis == 0 {
		return defaultValue
	}
	return int(millis)
}

func generateFSP(espSize uint16) []byte {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[0:2], espSize)

	return buf
}

// generates HTTP request, that is ready to have tag prepended to it
func generateHTTPRequestBeginning(decoyHostname string) []byte {
	sharedHeaders := `Host: ` + decoyHostname +
		"\nUser-Agent: TapDance/1.2 (+https://refraction.network/info)"
	httpTag := fmt.Sprintf(`GET / HTTP/1.1
%s
X-Ignore: %s`, sharedHeaders, getRandPadding(7, maxInt(612-len(sharedHeaders), 7), 10))
	return []byte(strings.Replace(httpTag, "\n", "\r\n", -1))
}

// Get padding of length [minLen, maxLen).
// Distributed in pseudogaussian style.
// Padded using symbol '#'. Known plaintext attacks, anyone?
func getRandPadding(minLen int, maxLen int, smoothness int) string {
	paddingLen := 0
	for j := 0; j < smoothness; j++ {
		paddingLen += getRandInt(minLen, maxLen)
	}
	paddingLen = paddingLen / smoothness

	return strings.Repeat("#", paddingLen)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func reverseEncrypt(ciphertext []byte, keyStream []byte) []byte {
	var plaintext string
	// our plaintext can be antyhing where x & 0xc0 == 0x40
	// i.e. 64-127 in ascii (@, A-Z, [\]^_`, a-z, {|}~ DEL)
	// This means that we are allowed to choose the last 6 bits
	// of each byte in the ciphertext arbitrarily; the upper 2
	// bits will have to be 01, so that our plaintext ends up
	// in the desired range.
	var ka, kb, kc, kd byte // key stream bytes
	var ca, cb, cc, cd byte // ciphertext bytes
	var pa, pb, pc, pd byte // plaintext bytes
	var sa, sb, sc byte     // secret bytes

	var tagIdx, keystreamIdx int

	for tagIdx < len(ciphertext) {
		ka = keyStream[keystreamIdx]
		kb = keyStream[keystreamIdx+1]
		kc = keyStream[keystreamIdx+2]
		kd = keyStream[keystreamIdx+3]
		keystreamIdx += 4

		// read 3 bytes
		sa = ciphertext[tagIdx]
		sb = ciphertext[tagIdx+1]
		sc = ciphertext[tagIdx+2]
		tagIdx += 3

		// figure out what plaintext needs to be in base64 encode
		ca = (ka & 0xc0) | ((sa & 0xfc) >> 2)                        // 6 bits sa
		cb = (kb & 0xc0) | (((sa & 0x03) << 4) | ((sb & 0xf0) >> 4)) // 2 bits sa, 4 bits sb
		cc = (kc & 0xc0) | (((sb & 0x0f) << 2) | ((sc & 0xc0) >> 6)) // 4 bits sb, 2 bits sc
		cd = (kd & 0xc0) | (sc & 0x3f)                               // 6 bits sc

		// Xor with key_stream, and add on 0x40 so it's in range of allowed
		pa = (ca ^ ka) + 0x40
		pb = (cb ^ kb) + 0x40
		pc = (cc ^ kc) + 0x40
		pd = (cd ^ kd) + 0x40

		plaintext += string(pa)
		plaintext += string(pb)
		plaintext += string(pc)
		plaintext += string(pd)
	}
	return []byte(plaintext)
}

func readAndClose(c net.Conn, readDeadline time.Duration) {
	tinyBuf := []byte{0}
	err := c.SetReadDeadline(time.Now().Add(readDeadline))
	if err != nil {
		return
	}
	_, err = c.Read(tinyBuf)
	if err != nil {
		return
	}
	c.Close()
}

// Below are functions adapted from tapdance/conjure.go that originally had receiver of
// type *ConjureReg. For now, we can pass the *ConjureSession to work with and avoid any
// receiver, but eventually we may want to change the receiver type to *ConjureSession,
// or use type alias to another name so we can define functions with that receiver here.

func getPbTransportParams(cjSession *td.ConjureSession) (*anypb.Any, error) {
	var m proto.Message
	m, err := cjSession.Transport.GetParams()
	if err != nil {
		return nil, err
	} else if m == nil {
		return nil, nil
	}
	return anypb.New(m)
}

func generateVSP(cjSession *td.ConjureSession) ([]byte, error) {
	c2s, err := generateClientToStation(cjSession)
	if err != nil {
		return nil, err
	}
	//[reference] Marshal ClientToStation protobuf
	return proto.Marshal(c2s)
}

func generateClientToStation(cjSession *td.ConjureSession) (*pb.ClientToStation, error) {
	if cjSession == nil {
		return nil, fmt.Errorf("cannot generate C2S with nil session")
	}
	var covert *string
	if len(cjSession.CovertAddress) > 0 {
		//[TODO]{priority:medium} this isn't the correct place to deal with signaling to the station
		//transition = pb.C2S_Transition_C2S_SESSION_COVERT_INIT
		covert = &cjSession.CovertAddress
	}

	//[reference] Generate ClientToStation protobuf
	// transition := pb.C2S_Transition_C2S_SESSION_INIT
	currentGen := assets.Assets().GetGeneration()
	currentLibVer := core.CurrentClientLibraryVersion()

	if cjSession.Transport == nil {
		return nil, fmt.Errorf("nil transport not allowed")
	}
	transport := cjSession.Transport.ID()

	transportParams, err := getPbTransportParams(cjSession)
	if err != nil {
		log.Debugf("%s failed to marshal transport parameters ", cjSession.IDString())
	}
	// remove type url to save space for DNS registration
	// for server side changes see https://github.com/refraction-networking/conjure/pull/163
	transportParams.TypeUrl = ""

	initProto := &pb.ClientToStation{
		ClientLibVersion:    &currentLibVer,
		CovertAddress:       covert,
		DecoyListGeneration: &currentGen,
		V6Support:           cjSession.GetV6Support(),
		V4Support:           cjSession.GetV4Support(),
		Transport:           &transport,
		Flags:               generateFlags(cjSession),
		TransportParams:     transportParams,

		DisableRegistrarOverrides: &cjSession.DisableRegistrarOverrides,

		//[TODO]{priority:medium} specify width in C2S because different width might
		// 		be useful in different regions (constant for now.)
	}

	// phantomSNI field no longer supported
	// if len(reg.phantomSNI) > 0 {
	// 	initProto.MaskedDecoyServerName = &reg.phantomSNI
	// }

	for (proto.Size(initProto)+td.AES_GCM_TAG_SIZE)%3 != 0 {
		initProto.Padding = append(initProto.Padding, byte(0))
	}

	return initProto, nil
}

func generateFlags(cjSession *td.ConjureSession) *pb.RegistrationFlags {
	flags := &pb.RegistrationFlags{}
	mask := default_flags
	if cjSession.UseProxyHeader {
		mask |= tdFlagProxyHeader
	}

	uploadOnly := mask&tdFlagUploadOnly == tdFlagUploadOnly
	proxy := mask&tdFlagProxyHeader == tdFlagProxyHeader
	til := mask&tdFlagUseTIL == tdFlagUseTIL

	flags.UploadOnly = &uploadOnly
	flags.ProxyHeader = &proxy
	flags.Use_TIL = &til

	return flags
}
