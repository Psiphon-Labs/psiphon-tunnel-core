package tapdance

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	pb "github.com/sergeyfrolov/gotapdance/protobuf"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/refraction-networking/utls"
)

// Simply establishes TLS and TapDance connection.
// Both reader and writer flows shall have this underlying raw connection.
// Knows about but doesn't keep track of timeout and upload limit
type tdRawConn struct {
	tcpConn closeWriterConn
	tlsConn *tls.UConn

	flowId      uint64
	sessionId   uint64
	strIdSuffix string

	customDialer func(string, string) (net.Conn, error)

	decoySpec     pb.TLSDecoySpec
	establishedAt time.Time
	pinDecoySpec  bool // don't ever change decoy (still changeable from outside)

	remoteConnId  []byte
	stationPubkey []byte

	failedDecoys []string
	initialMsg   pb.StationToClient
	tagType      tdTagType

	UploadLimit int // used only in POST-based tags

	closed    chan struct{}
	closeOnce sync.Once
}

func makeTdRaw(handshakeType tdTagType,
	stationPubkey []byte,
	remoteConnId []byte) *tdRawConn {
	tdRaw := &tdRawConn{tagType: handshakeType,
		stationPubkey: stationPubkey,
		remoteConnId:  remoteConnId}
	tdRaw.flowId = 0
	tdRaw.closed = make(chan struct{})
	return tdRaw
}

func (tdRaw *tdRawConn) Redial() error {
	tdRaw.flowId += 1
	return tdRaw.dial(true)
}

func (tdRaw *tdRawConn) Dial() error {
	return tdRaw.dial(false)
}

func (tdRaw *tdRawConn) dial(reconnect bool) error {
	var maxConnectionAttempts int
	var err error

	/*
		// Randomize tdConn.maxSend to avoid heuristics
		tdConn.maxSend = getRandInt(sendLimitMin, sendLimitMax)
		tdConn.maxSend -= transitionMsgSize // reserve space for transition msg
		tdConn.maxSend -= 2                 // reserve 2 bytes for transition msg header
	*/
	var expectedTransition pb.S2C_Transition
	if reconnect {
		maxConnectionAttempts = 2
		expectedTransition = pb.S2C_Transition_S2C_CONFIRM_RECONNECT
		tdRaw.tlsConn.Close()
	} else {
		maxConnectionAttempts = 6
		expectedTransition = pb.S2C_Transition_S2C_SESSION_INIT
	}

	for i := 0; i < maxConnectionAttempts; i++ {
		if tdRaw.IsClosed() {
			return errors.New("Closed")
		}
		// sleep to prevent overwhelming decoy servers
		if waitTime := sleepBeforeConnect(i); waitTime != nil {
			select {
			case <-waitTime:
			case <-tdRaw.closed:
				return errors.New("Closed")
			}
		}
		if tdRaw.pinDecoySpec {
			if tdRaw.decoySpec.Ipv4Addr == nil {
				return errors.New("decoySpec is pinned, but empty!")
			}
		} else {
			if !reconnect {
				tdRaw.decoySpec = Assets().GetDecoy()
				if tdRaw.decoySpec.GetIpv4AddrStr() == "" {
					return errors.New("tdConn.decoyAddr is empty!")
				}
			}
		}

		err = tdRaw.tryDialOnce(expectedTransition)
		if err == nil {
			return err
		}
		tdRaw.failedDecoys = append(tdRaw.failedDecoys,
			tdRaw.decoySpec.GetHostname()+" "+tdRaw.decoySpec.GetIpv4AddrStr())
	}
	return err
}

func (tdRaw *tdRawConn) tryDialOnce(expectedTransition pb.S2C_Transition) (err error) {
	Logger().Infoln(tdRaw.idStr() + " Attempting to connect to decoy " +
		tdRaw.decoySpec.GetHostname() + " (" + tdRaw.decoySpec.GetIpv4AddrStr() + ")")
	err = tdRaw.establishTLStoDecoy()
	if err != nil {
		Logger().Errorf(tdRaw.idStr() + " establishTLStoDecoy(" +
			tdRaw.decoySpec.GetHostname() + "," + tdRaw.decoySpec.GetIpv4AddrStr() +
			") failed with " + err.Error())
		return err
	}
	Logger().Infof(tdRaw.idStr() + " Connected to decoy " +
		tdRaw.decoySpec.GetHostname() + " (" + tdRaw.decoySpec.GetIpv4AddrStr() + ")")

	if tdRaw.IsClosed() {
		// if connection was closed externally while in establishTLStoDecoy()
		tdRaw.tlsConn.Close()
		return errors.New("Closed")
	}

	// Check if cipher is supported
	cipherIsSupported := func(id uint16) bool {
		for _, c := range tapDanceSupportedCiphers {
			if c == id {
				return true
			}
		}
		return false
	}
	if !cipherIsSupported(tdRaw.tlsConn.ConnectionState().CipherSuite) {
		Logger().Errorf("%s decoy %s offered unsupported cipher %d\n Client ciphers: %#v\n",
			tdRaw.idStr(), tdRaw.decoySpec.GetHostname(),
			tdRaw.tlsConn.ConnectionState().CipherSuite,
			tdRaw.tlsConn.HandshakeState.Hello.CipherSuites)
		err = errors.New("Unsupported cipher.")
		tdRaw.tlsConn.Close()
		return err
	}

	tdRaw.tlsConn.SetDeadline(time.Now().Add(
		getRandomDuration(deadlineConnectTDStationMin, deadlineConnectTDStationMax)))

	var tdRequest string
	tdRequest, err = tdRaw.prepareTDRequest(tdRaw.tagType)
	if err != nil {
		Logger().Errorf(tdRaw.idStr() +
			" Preparation of initial TD request failed with " + err.Error())
		tdRaw.tlsConn.Close()
		return
	}
	tdRaw.establishedAt = time.Now() // TODO: recheck how ClientConf's timeout is calculated and move, if needed

	Logger().Infoln(tdRaw.idStr() + " Attempting to connect to TapDance Station" +
		" with connection ID: " + hex.EncodeToString(tdRaw.remoteConnId[:]) + ", method: " +
		tdRaw.tagType.Str())
	_, err = tdRaw.tlsConn.Write([]byte(tdRequest))
	if err != nil {
		Logger().Errorf(tdRaw.idStr() +
			" Could not send initial TD request, error: " + err.Error())
		tdRaw.tlsConn.Close()
		return
	}

	switch tdRaw.tagType {
	case tagHttpGetIncomplete:
		tdRaw.initialMsg, err = tdRaw.readProto()
		if err != nil {
			if errIsTimeout(err) {
				Logger().Errorf("%s %s: %v", tdRaw.idStr(),
					"TapDance station didn't pick up the request", err)

				// lame fix for issue #38 with abrupt drop of not picked up flows
				tdRaw.tlsConn.SetDeadline(time.Now().Add(
					getRandomDuration(deadlineTCPtoDecoyMin,
						deadlineTCPtoDecoyMax)))
				tdRaw.tlsConn.Write([]byte(getRandPadding(456, 789, 5) + "\r\n" +
					"Connection: close\r\n\r\n"))
				go readAndClose(tdRaw.tlsConn,
					getRandomDuration(deadlineTCPtoDecoyMin,
						deadlineTCPtoDecoyMax))
			} else {
				// any other error will be fatal
				Logger().Errorf(tdRaw.idStr() +
					" fatal error reading from TapDance station: " +
					err.Error())
				tdRaw.tlsConn.Close()
				return
			}
			return
		}
		if tdRaw.initialMsg.GetStateTransition() != expectedTransition {
			err = errors.New("Init error: state transition mismatch!" +
				" Received: " + tdRaw.initialMsg.GetStateTransition().String() +
				" Expected: " + expectedTransition.String())
			// this exceptional error implies that station has lost state, thus is fatal
			return err
		}
		Logger().Infoln(tdRaw.idStr() + " Successfully connected to TapDance Station [" + tdRaw.initialMsg.GetStationId() + "]")
	case tagHttpPostIncomplete:
		// don't wait for response
	default:
		panic("Unsupported td handshake type:" + tdRaw.tagType.Str())
	}

	// TapDance should NOT have a timeout, timeouts have to be handled by client and server
	tdRaw.tlsConn.SetDeadline(time.Time{}) // unsets timeout
	/*
		if !reconnect && len(tdConn.failedDecoys) > 0 {
			tdConn.writeListFailedDecoys()
		}*/
	return nil
}

func (tdRaw *tdRawConn) establishTLStoDecoy() (err error) {
	var dialConn net.Conn
	if tdRaw.customDialer != nil {
		dialConn, err = tdRaw.customDialer("tcp", tdRaw.decoySpec.GetIpv4AddrStr())
		if err != nil {
			return err
		}
	} else {
		dialConn, err = net.DialTimeout("tcp", tdRaw.decoySpec.GetIpv4AddrStr(),
			getRandomDuration(deadlineTCPtoDecoyMin, deadlineTCPtoDecoyMax))
		if err != nil {
			return err
		}
	}
	config := tls.Config{ServerName: tdRaw.decoySpec.GetHostname()}
	if config.ServerName == "" {
		// if SNI is unset -- try IP
		config.ServerName, _, err = net.SplitHostPort(tdRaw.decoySpec.GetIpv4AddrStr())
		if err != nil {
			dialConn.Close()
			return
		}
		Logger().Infoln(tdRaw.idStr() + ": SNI was nil. Setting it to" +
			config.ServerName)
	}
	// parrot Chrome 62 ClientHello
	tdRaw.tlsConn = tls.UClient(dialConn, &config, tls.HelloChrome_62)
	err = tdRaw.tlsConn.BuildHandshakeState()
	if err != nil {
		dialConn.Close()
		return
	}
	err = tdRaw.tlsConn.MarshalClientHello()
	if err != nil {
		dialConn.Close()
		return
	}
	err = tdRaw.tlsConn.Handshake()
	if err != nil {
		dialConn.Close()
		return
	}
	closeWriter, ok := dialConn.(closeWriterConn)
	if !ok {
		return errors.New("dialConn is not a closeWriter")
	}
	tdRaw.tcpConn = closeWriter
	return
}

func (tdRaw *tdRawConn) Close() error {
	var err error
	tdRaw.closeOnce.Do(func() {
		close(tdRaw.closed)
		if tdRaw.tlsConn != nil {
			err = tdRaw.tlsConn.Close()
		}
	})
	return err
}

type closeWriterConn interface {
	net.Conn
	CloseWrite() error
}

func (tdRaw *tdRawConn) closeWrite() error {
	return tdRaw.tcpConn.CloseWrite()
}

func (tdRaw *tdRawConn) prepareTDRequest(handshakeType tdTagType) (string, error) {
	// Generate initial TapDance request
	buf := new(bytes.Buffer) // What we have to encrypt with the shared secret using AES

	masterKey := tdRaw.tlsConn.HandshakeState.MasterSecret

	// write flags
	flags := default_flags
	if tdRaw.tagType == tagHttpPostIncomplete {
		flags |= tdFlagUploadOnly
	}
	if err := binary.Write(buf, binary.BigEndian, flags); err != nil {
		return "", err
	}
	buf.Write([]byte{0}) // Unassigned byte
	negotiatedCipher := tdRaw.tlsConn.HandshakeState.Suite.Id
	buf.Write([]byte{byte(negotiatedCipher >> 8),
		byte(negotiatedCipher & 0xff)})
	buf.Write(masterKey[:])
	buf.Write(tdRaw.tlsConn.HandshakeState.ServerHello.Random)
	buf.Write(tdRaw.tlsConn.HandshakeState.Hello.Random)
	buf.Write(tdRaw.remoteConnId[:]) // connection id for persistence

	tag, err := obfuscateTag(buf.Bytes(), tdRaw.stationPubkey) // What we encode into the ciphertext
	if err != nil {
		return "", err
	}
	return tdRaw.genHTTP1Tag(tag)
}

// mutates tdRaw: sets tdRaw.UploadLimit
func (tdRaw *tdRawConn) genHTTP1Tag(tag []byte) (string, error) {
	var httpTag string
	switch tdRaw.tagType {
	// for complete copy http generator of golang
	case tagHttpGetComplete:
		fallthrough
	case tagHttpGetIncomplete:
		tdRaw.UploadLimit = int(tdRaw.decoySpec.GetTcpwin()) - getRandInt(1, 1045)
		httpTag = `GET / HTTP/1.1
Host: ` + tdRaw.decoySpec.GetHostname() + `
User-Agent: TapDance/1.2 (+https://refraction.network/info)
Accept-Encoding: None
X-Ignore: ` + getRandPadding(7, 612, 10)
		httpTag = strings.Replace(httpTag, "\n", "\r\n", -1)
	case tagHttpPostIncomplete:
		ContentLength := getRandInt(900000, 1045000)
		tdRaw.UploadLimit = ContentLength - 1
		httpTag = `POST / HTTP/1.1
Accept-Encoding: None
Host: ` + tdRaw.decoySpec.GetHostname() + `
User-Agent: TapDance/1.2 (+https://refraction.network/info)
X-Padding: ` + getRandPadding(1, 461, 10) + `
Content-Type: application/zip; boundary=----WebKitFormBoundaryaym16ehT29q60rUx
Content-Length: ` + strconv.Itoa(ContentLength) + `

----WebKitFormBoundaryaym16ehT29q60rUx
Content-Disposition: form-data; name=\"td.zip\"
`
		httpTag = strings.Replace(httpTag, "\n", "\r\n", -1)
	}

	keystreamOffset := len(httpTag)
	keystreamSize := (len(tag)/3+1)*4 + keystreamOffset // we can't use first 2 bits of every byte
	wholeKeystream, err := tdRaw.tlsConn.GetOutKeystream(keystreamSize)
	if err != nil {
		return httpTag, err
	}
	keystreamAtTag := wholeKeystream[keystreamOffset:]

	httpTag += reverseEncrypt(tag, keystreamAtTag)
	if tdRaw.tagType == tagHttpGetComplete {
		httpTag += "\r\n\r\n"
	}
	Logger().Debugf("Generated HTTP TAG:\n%s\n", httpTag)
	return httpTag, nil
}

func (tdRaw *tdRawConn) idStr() string {
	return "[Session " + strconv.FormatUint(tdRaw.sessionId, 10) + ", " +
		"Flow " + strconv.FormatUint(tdRaw.flowId, 10) + tdRaw.strIdSuffix + "]"
}

// Simply reads and returns protobuf
// Returns error if it's not a protobuf
func (tdRaw *tdRawConn) readProto() (msg pb.StationToClient, err error) {
	var readBytes int
	var readBytesTotal uint32 // both header and body
	headerSize := uint32(2)

	var msgLen uint32 // just the body(e.g. raw data or protobuf)
	var outerProtoMsgType msgType

	headerBuffer := make([]byte, 6) // TODO: allocate once at higher level?

	for readBytesTotal < headerSize {
		readBytes, err = tdRaw.tlsConn.Read(headerBuffer[readBytesTotal:headerSize])
		readBytesTotal += uint32(readBytes)
		if err != nil {
			return
		}
	}

	// Get TIL
	typeLen := uint16toInt16(binary.BigEndian.Uint16(headerBuffer[0:2]))
	if typeLen < 0 {
		outerProtoMsgType = msgRawData
		msgLen = uint32(-typeLen)
	} else if typeLen > 0 {
		outerProtoMsgType = msgProtobuf
		msgLen = uint32(typeLen)
	} else {
		// protobuf with size over 32KB, not fitting into 2-byte TL
		outerProtoMsgType = msgProtobuf
		headerSize += 4
		for readBytesTotal < headerSize {
			readBytes, err = tdRaw.tlsConn.Read(headerBuffer[readBytesTotal:headerSize])

			readBytesTotal += uint32(readBytes)
			if err == io.EOF && readBytesTotal == headerSize {
				break
			}
			if err != nil {
				return
			}
		}
		msgLen = binary.BigEndian.Uint32(headerBuffer[2:6])
	}
	if outerProtoMsgType == msgRawData {
		err = errors.New("Received data message in uninitialized flow")
		return
	}

	totalBytesToRead := headerSize + msgLen
	readBuffer := make([]byte, msgLen)

	// Get the message itself
	for readBytesTotal < totalBytesToRead {
		readBytes, err = tdRaw.tlsConn.Read(readBuffer[readBytesTotal-headerSize : msgLen])
		readBytesTotal += uint32(readBytes)

		if err != nil {
			return
		}
	}

	err = proto.Unmarshal(readBuffer[:], &msg)
	if err != nil {
		return
	}
	Logger().Debugln(tdRaw.idStr() + " INIT: received protobuf: " + msg.String())
	return
}

// Generates padding and stuff
// Currently guaranteed to be less than 1024 bytes long
func (tdRaw *tdRawConn) writeTransition(transition pb.C2S_Transition) (n int, err error) {
	currGen := Assets().GetGeneration()
	msg := pb.ClientToStation{Padding: []byte(getRandPadding(150, 900, 10)),
		DecoyListGeneration: &currGen,
		StateTransition:     &transition,
		UploadSync:          new(uint64)} // TODO: remove

	msgBytes, err := proto.Marshal(&msg)
	if err != nil {
		return
	}

	Logger().Infoln(tdRaw.idStr()+" sending transition: ", msg.String())
	b := getMsgWithHeader(msgProtobuf, msgBytes)
	n, err = tdRaw.tlsConn.Write(b)
	return
}

func (tdRaw *tdRawConn) IsClosed() bool {
	select {
	case <-tdRaw.closed:
		return true
	default:
		return false
	}
}
