package tapdance

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/refraction-networking/utls"
	"os"
	"strconv"
	"time"
)

const timeoutMax = 30000
const timeoutMin = 20000

const sendLimitMax = 15614
const sendLimitMin = 14400

// timeout for sending TD request and getting a response
const deadlineConnectTDStationMin = 11175
const deadlineConnectTDStationMax = 14231

// deadline to establish TCP connection to decoy
const deadlineTCPtoDecoyMin = deadlineConnectTDStationMin
const deadlineTCPtoDecoyMax = deadlineConnectTDStationMax

// during reconnects we send FIN to server and wait until we get FIN back
const waitForFINDieMin = 2 * deadlineConnectTDStationMin
const waitForFINDieMax = 2 * deadlineConnectTDStationMax

const maxInt16 = int16(^uint16(0) >> 1) // max msg size -> might have to chunk
//const minInt16 = int16(-maxInt16 - 1)

type flowType int8

const (
	flowUpload        flowType = 0x1
	flowReadOnly      flowType = 0x2
	flowBidirectional flowType = 0x4
)

func (m *flowType) Str() string {
	switch *m {
	case flowUpload:
		return "FlowUpload"
	case flowReadOnly:
		return "FlowReadOnly"
	case flowBidirectional:
		return "FlowBidirectional"
	default:
		return strconv.Itoa(int(*m))
	}
}

type msgType int8

const (
	msgRawData  msgType = 1
	msgProtobuf msgType = 2
)

func (m *msgType) Str() string {
	switch *m {
	case msgRawData:
		return "msg raw_data"
	case msgProtobuf:
		return "msg protobuf"
	default:
		return strconv.Itoa(int(*m))
	}
}

var errMsgClose = errors.New("MSG CLOSE")
var errNotImplemented = errors.New("Not implemented")

type tdTagType int8

const (
	tagHttpGetIncomplete  tdTagType = 0
	tagHttpGetComplete    tdTagType = 1
	tagHttpPostIncomplete tdTagType = 2
)

func (m *tdTagType) Str() string {
	switch *m {
	case tagHttpGetIncomplete:
		return "HTTP GET Incomplete"
	case tagHttpGetComplete:
		return "HTTP GET Complete"
	case tagHttpPostIncomplete:
		return "HTTP POST Incomplete"
	default:
		return strconv.Itoa(int(*m))
	}
}

// First byte of tag is for FLAGS
// bit 0 (1 << 7) determines if flow is bidirectional(0) or upload-only(1)
// bits 1-5 are unassigned
// bit 6 determines whether PROXY-protocol-formatted string will be sent
// bit 7 (1 << 0) signals to use TypeLen outer proto
var (
	tdFlagUploadOnly  = uint8(1 << 7)
	tdFlagProxyHeader = uint8(1 << 1)
	tdFlagUseTIL      = uint8(1 << 0)
)

var default_flags = tdFlagUseTIL

// Requests station to proxy client IP to upstream in following form:
// CONNECT 1.2.3.4:443 HTTP/1.1\r\n
// Host: 1.2.3.4\r\n
// \r\n
// PROXY TCP4 x.x.x.x 127.0.0.1 1111 1234\r\n
//       ^__^ ^_____^ ^_________________^
//      proto clientIP      garbage
func EnableProxyProtocol() {
	default_flags |= tdFlagProxyHeader
}

var tlsSecretLog string

func SetTlsLogFilename(filename string) error {
	tlsSecretLog = filename
	// Truncate file
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	return f.Close()
}

func WriteTlsLog(clientRandom, masterSecret []byte) error {
	if tlsSecretLog != "" {
		f, err := os.OpenFile(tlsSecretLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(f, "CLIENT_RANDOM %s %s\n",
			hex.EncodeToString(clientRandom),
			hex.EncodeToString(masterSecret))
		if err != nil {
			return err
		}

		return f.Close()
	}
	return nil
}

// List of actually supported ciphers(not a list of offered ciphers!)
// Essentially all working AES_GCM_128 ciphers
var tapDanceSupportedCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
}

// How much time to sleep on trying to connect to decoys to prevent overwhelming them
func sleepBeforeConnect(attempt int) (waitTime <-chan time.Time) {
	if attempt >= 6 { // return nil for first 6 attempts
		waitTime = time.After(time.Second * 1)
	}
	return
}
