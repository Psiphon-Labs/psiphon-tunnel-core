package tapdance

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/refraction-networking/conjure/proto"
	tls "github.com/refraction-networking/utls"
	"google.golang.org/protobuf/proto"
)

// Simply establishes TLS and TapDance connection.
// Both reader and writer flows shall have this underlying raw connection.
// Knows about but doesn't keep track of timeout and upload limit
type tdRawConn struct {
	tcpConn closeWriterConn // underlying TCP connection with CloseWrite() function that sends FIN
	tlsConn *tls.UConn      // TLS connection to decoy (and station)

	covert string // hostname that tapdance station will connect client to

	Dialer func(context.Context, string, string) (net.Conn, error)

	decoySpec     *pb.TLSDecoySpec
	pinDecoySpec  bool // don't ever change decoy (still changeable from outside)
	initialMsg    *pb.StationToClient
	stationPubkey []byte
	tagType       tdTagType

	remoteConnId []byte // 32 byte ID of the connection to station, used for reconnection

	establishedAt time.Time // right after TLS connection to decoy is established, but not to station
	UploadLimit   int       // used only in POST-based tags

	closed    chan struct{}
	closeOnce sync.Once

	useProxyHeader bool // request the station to prepend the connection with PROXY header

	// dark decoy variables
	darkDecoyUsed      bool
	darkDecoySNI       string
	darkDecoyV6Support bool // *bool so that it is a nullable type. that can be overridden by the dialer

	// stats to report
	sessionStats pb.SessionStats
	failedDecoys []string

	// purely for logging and stats reporting purposes:
	flowId      uint64 // id of the flow within the session (=how many times reconnected)
	sessionId   uint64 // id of the local session
	strIdSuffix string // suffix for every log string (e.g. to mark upload-only flows)

	tdKeys tapdanceSharedKeys
}

func makeTdRaw(handshakeType tdTagType, stationPubkey []byte) *tdRawConn {
	tdRaw := &tdRawConn{tagType: handshakeType,
		stationPubkey: stationPubkey,
	}
	tdRaw.closed = make(chan struct{})
	return tdRaw
}

func (tdRaw *tdRawConn) DialContext(ctx context.Context) error {
	return tdRaw.dial(ctx, false)
}

func (tdRaw *tdRawConn) RedialContext(ctx context.Context) error {
	tdRaw.flowId++
	return tdRaw.dial(ctx, true)
}

func (tdRaw *tdRawConn) dial(ctx context.Context, reconnect bool) error {
	var maxConnectionAttempts int
	var err error

	dialStartTs := time.Now()
	var expectedTransition pb.S2C_Transition
	if reconnect {
		maxConnectionAttempts = 5
		expectedTransition = pb.S2C_Transition_S2C_CONFIRM_RECONNECT
		tdRaw.tlsConn.Close()
	} else {
		maxConnectionAttempts = 20
		expectedTransition = pb.S2C_Transition_S2C_SESSION_INIT
		if len(tdRaw.covert) > 0 {
			expectedTransition = pb.S2C_Transition_S2C_SESSION_COVERT_INIT
		}
	}

	for i := 0; i < maxConnectionAttempts; i++ {
		if tdRaw.IsClosed() {
			return errors.New("Closed")
		}
		// sleep to prevent overwhelming decoy servers
		if waitTime := sleepBeforeConnect(i); waitTime != nil {
			select {
			case <-waitTime:
			case <-ctx.Done():
				return context.Canceled
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
				if tdRaw.decoySpec.GetIpAddrStr() == "" {
					return errors.New("tdConn.decoyAddr is empty!")
				}
			}
		}

		if !reconnect {
			// generate a new remove conn ID for each attempt to dial
			// keep same remote conn ID for reconnect, since that's what it is for
			tdRaw.remoteConnId = make([]byte, 16)
			rand.Read(tdRaw.remoteConnId[:])
		}

		err = tdRaw.tryDialOnce(ctx, expectedTransition)
		if err == nil {
			tdRaw.sessionStats.TotalTimeToConnect = durationToU32ptrMs(time.Since(dialStartTs))
			return nil
		}
		tdRaw.failedDecoys = append(tdRaw.failedDecoys,
			tdRaw.decoySpec.GetHostname()+" "+tdRaw.decoySpec.GetIpAddrStr())
		if tdRaw.sessionStats.FailedDecoysAmount == nil {
			tdRaw.sessionStats.FailedDecoysAmount = new(uint32)
		}
		*tdRaw.sessionStats.FailedDecoysAmount += uint32(1)
	}
	return err
}

func (tdRaw *tdRawConn) tryDialOnce(ctx context.Context, expectedTransition pb.S2C_Transition) (err error) {
	Logger().Infoln(tdRaw.idStr() + " Attempting to connect to decoy " +
		tdRaw.decoySpec.GetHostname() + " (" + tdRaw.decoySpec.GetIpAddrStr() + ")")

	tlsToDecoyStartTs := time.Now()
	err = tdRaw.establishTLStoDecoy(ctx)
	tlsToDecoyTotalTs := time.Since(tlsToDecoyStartTs)
	if err != nil {
		Logger().Errorf(tdRaw.idStr() + " establishTLStoDecoy(" +
			tdRaw.decoySpec.GetHostname() + "," + tdRaw.decoySpec.GetIpAddrStr() +
			") failed with " + err.Error())
		return err
	}

	err = WriteTlsLog(tdRaw.tlsConn.HandshakeState.Hello.Random,
		tdRaw.tlsConn.HandshakeState.MasterSecret)
	if err != nil {
		Logger().Warningf("Failed to write TLS secret log: %s", err)
	}

	tdRaw.sessionStats.TlsToDecoy = durationToU32ptrMs(tlsToDecoyTotalTs)
	Logger().Infof("%s Connected to decoy %s(%s) in %s", tdRaw.idStr(), tdRaw.decoySpec.GetHostname(),
		tdRaw.decoySpec.GetIpAddrStr(), tlsToDecoyTotalTs.String())

	if tdRaw.IsClosed() {
		// if connection was closed externally while in establishTLStoDecoy()
		tdRaw.tlsConn.Close()
		return errors.New("Closed")
	}

	tdRequest, err := tdRaw.prepareTDRequest(tdRaw.tagType)
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

	rttToStationStartTs := time.Now()
	_, err = tdRaw.tlsConn.Write([]byte(tdRequest))
	if err != nil {
		Logger().Errorf(tdRaw.idStr() +
			" Could not send initial TD request, error: " + err.Error())
		tdRaw.tlsConn.Close()
		return
	}

	// Give up waiting for the station pretty quickly (2x handshake time == ~4RTT)
	tdRaw.tlsConn.SetDeadline(time.Now().Add(tlsToDecoyTotalTs * 2))

	switch tdRaw.tagType {
	case tagHttpGetIncomplete:
		tdRaw.initialMsg, err = tdRaw.readProto()
		rttToStationTotalTs := time.Since(rttToStationStartTs)
		tdRaw.sessionStats.RttToStation = durationToU32ptrMs(rttToStationTotalTs)
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
			Logger().Infof("%s Failed to connect to TapDance Station [%s]: %s",
				tdRaw.idStr(), tdRaw.initialMsg.GetStationId(), err.Error())
			// this exceptional error implies that station has lost state, thus is fatal
			return err
		}
		Logger().Infoln(tdRaw.idStr() + " Successfully connected to TapDance Station [" + tdRaw.initialMsg.GetStationId() + "]")
	case tagHttpPostIncomplete, tagHttpGetComplete:
		// don't wait for response
	default:
		panic("Unsupported td handshake type:" + tdRaw.tagType.Str())
	}

	// TapDance should NOT have a timeout, timeouts have to be handled by client and server
	tdRaw.tlsConn.SetDeadline(time.Time{}) // unsets timeout
	return nil
}

func (tdRaw *tdRawConn) establishTLStoDecoy(ctx context.Context) error {
	deadline, deadlineAlreadySet := ctx.Deadline()
	if !deadlineAlreadySet {
		deadline = time.Now().Add(getRandomDuration(deadlineTCPtoDecoyMin, deadlineTCPtoDecoyMax))
	}
	childCtx, childCancelFunc := context.WithDeadline(ctx, deadline)
	defer childCancelFunc()

	dialer := tdRaw.Dialer
	if dialer == nil {
		// custom dialer is not set, use default
		d := net.Dialer{}
		dialer = d.DialContext
	}

	tcpToDecoyStartTs := time.Now()
	dialConn, err := dialer(childCtx, "tcp", tdRaw.decoySpec.GetIpAddrStr())
	tcpToDecoyTotalTs := time.Since(tcpToDecoyStartTs)
	if err != nil {
		return err
	}
	tdRaw.sessionStats.TcpToDecoy = durationToU32ptrMs(tcpToDecoyTotalTs)

	config := tls.Config{ServerName: tdRaw.decoySpec.GetHostname()}
	if config.ServerName == "" {
		// if SNI is unset -- try IP
		config.ServerName, _, err = net.SplitHostPort(tdRaw.decoySpec.GetIpAddrStr())
		if err != nil {
			dialConn.Close()
			return err
		}
		Logger().Infoln(tdRaw.idStr() + ": SNI was nil. Setting it to" +
			config.ServerName)
	}
	// parrot Chrome 62 ClientHello
	tdRaw.tlsConn = tls.UClient(dialConn, &config, tls.HelloChrome_62)
	err = tdRaw.tlsConn.BuildHandshakeState()
	if err != nil {
		dialConn.Close()
		return err
	}
	err = tdRaw.tlsConn.MarshalClientHello()
	if err != nil {
		dialConn.Close()
		return err
	}
	tdRaw.tlsConn.SetDeadline(deadline)
	err = tdRaw.tlsConn.Handshake()
	if err != nil {
		dialConn.Close()
		return err
	}
	closeWriter, ok := dialConn.(closeWriterConn)
	if !ok {
		return errors.New("dialConn is not a closeWriter")
	}
	tdRaw.tcpConn = closeWriter
	return nil
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

// func (tdRaw *tdRawConn) generateFSP(espSize uint16) []byte {
// 	buf := make([]byte, 6)
// 	binary.BigEndian.PutUint16(buf[0:2], espSize)
// 	flags := default_flags
// 	if tdRaw.tagType == tagHttpPostIncomplete {
// 		flags |= tdFlagUploadOnly
// 	}
// 	if tdRaw.useProxyHeader {
// 		flags |= tdFlagProxyHeader
// 	}
// 	buf[2] = flags

// 	return buf
// }

func (tdRaw *tdRawConn) generateVSP() ([]byte, error) {
	// Generate and marshal protobuf
	transition := pb.C2S_Transition_C2S_SESSION_INIT
	var covert *string
	if len(tdRaw.covert) > 0 {
		transition = pb.C2S_Transition_C2S_SESSION_COVERT_INIT
		covert = &tdRaw.covert
	}
	currGen := Assets().GetGeneration()
	initProto := &pb.ClientToStation{
		CovertAddress:       covert,
		StateTransition:     &transition,
		DecoyListGeneration: &currGen,
	}

	Logger().Debugln(tdRaw.idStr()+" Initial protobuf", initProto)
	const AES_GCM_TAG_SIZE = 16
	for (proto.Size(initProto)+AES_GCM_TAG_SIZE)%3 != 0 {
		initProto.Padding = append(initProto.Padding, byte(0))
	}
	return proto.Marshal(initProto)
}

func (tdRaw *tdRawConn) prepareTDRequest(handshakeType tdTagType) (string, error) {
	// Generate tag for the initial TapDance request
	buf := new(bytes.Buffer) // What we have to encrypt with the shared secret using AES

	masterKey := tdRaw.tlsConn.HandshakeState.MasterSecret

	// write flags
	flags := default_flags
	if tdRaw.tagType == tagHttpPostIncomplete {
		flags |= tdFlagUploadOnly
	}
	if tdRaw.useProxyHeader {
		flags |= tdFlagProxyHeader
	}
	if err := binary.Write(buf, binary.BigEndian, flags); err != nil {
		return "", err
	}
	buf.Write([]byte{0}) // Unassigned byte
	negotiatedCipher := tdRaw.tlsConn.HandshakeState.State12.Suite.Id
	if tdRaw.tlsConn.HandshakeState.ServerHello.Vers == tls.VersionTLS13 {
		negotiatedCipher = tdRaw.tlsConn.HandshakeState.State13.Suite.Id
	}
	buf.Write([]byte{byte(negotiatedCipher >> 8),
		byte(negotiatedCipher & 0xff)})
	buf.Write(masterKey[:])
	buf.Write(tdRaw.tlsConn.HandshakeState.ServerHello.Random)
	buf.Write(tdRaw.tlsConn.HandshakeState.Hello.Random)
	buf.Write(tdRaw.remoteConnId[:]) // connection id for persistence

	err := WriteTlsLog(tdRaw.tlsConn.HandshakeState.Hello.Random,
		tdRaw.tlsConn.HandshakeState.MasterSecret)
	if err != nil {
		Logger().Warningf("Failed to write TLS secret log: %s", err)
	}

	// Generate and marshal protobuf
	transition := pb.C2S_Transition_C2S_SESSION_INIT
	var covert *string
	if len(tdRaw.covert) > 0 {
		transition = pb.C2S_Transition_C2S_SESSION_COVERT_INIT
		covert = &tdRaw.covert
	}
	currGen := Assets().GetGeneration()
	initProto := &pb.ClientToStation{
		CovertAddress:       covert,
		StateTransition:     &transition,
		DecoyListGeneration: &currGen,
	}
	initProtoBytes, err := proto.Marshal(initProto)
	if err != nil {
		return "", err
	}
	Logger().Debugln(tdRaw.idStr()+" Initial protobuf", initProto)

	// Choose the station pubkey
	pubkey := tdRaw.stationPubkey
	if perDecoyKey := tdRaw.decoySpec.GetPubkey().GetKey(); perDecoyKey != nil {
		pubkey = perDecoyKey // per-decoy key takes preference over default global pubkey
	}

	// Obfuscate/encrypt tag and protobuf
	tag, encryptedProtoMsg, err := obfuscateTagAndProtobuf(buf.Bytes(), initProtoBytes, pubkey)
	if err != nil {
		return "", err
	}
	return tdRaw.genHTTP1Tag(tag, encryptedProtoMsg)
}

func (tdRaw *tdRawConn) idStr() string {
	return "[Session " + strconv.FormatUint(tdRaw.sessionId, 10) + ", " +
		"Flow " + strconv.FormatUint(tdRaw.flowId, 10) + tdRaw.strIdSuffix + "]"
}

// Simply reads and returns protobuf
// Returns error if it's not a protobuf
// TODO: redesign it pb, data, err
func (tdRaw *tdRawConn) readProto() (msg *pb.StationToClient, err error) {
	var readBuffer bytes.Buffer

	var outerProtoMsgType msgType
	var msgLen int64 // just the body (e.g. raw data or protobuf)

	// Get TIL
	_, err = io.CopyN(&readBuffer, tdRaw.tlsConn, 2)
	if err != nil {
		return
	}

	typeLen := uint16toInt16(binary.BigEndian.Uint16(readBuffer.Next(2)))
	if typeLen < 0 {
		outerProtoMsgType = msgRawData
		msgLen = int64(-typeLen)
	} else if typeLen > 0 {
		outerProtoMsgType = msgProtobuf
		msgLen = int64(typeLen)
	} else {
		// protobuf with size over 32KB, not fitting into 2-byte TL
		outerProtoMsgType = msgProtobuf
		_, err = io.CopyN(&readBuffer, tdRaw.tlsConn, 4)
		if err != nil {
			return
		}
		msgLen = int64(binary.BigEndian.Uint32(readBuffer.Next(4)))
	}

	if outerProtoMsgType == msgRawData {
		err = errors.New("Received data message in uninitialized flow")
		return
	}

	// Get the message itself
	_, err = io.CopyN(&readBuffer, tdRaw.tlsConn, msgLen)
	if err != nil {
		return
	}

	msg = &pb.StationToClient{}
	err = proto.Unmarshal(readBuffer.Bytes(), msg)
	if err != nil {
		return
	}

	Logger().Debugln(tdRaw.idStr() + " INIT: received protobuf: " + msg.String())
	return
}

// Generates padding and stuff
// Currently guaranteed to be less than 1024 bytes long
func (tdRaw *tdRawConn) writeTransition(transition pb.C2S_Transition) (n int, err error) {
	const paddingMinSize = 250
	const paddingMaxSize = 800
	const paddingSmoothness = 5
	paddingDecrement := 0 // reduce potential padding size by this value

	currGen := Assets().GetGeneration()
	msg := pb.ClientToStation{
		DecoyListGeneration: &currGen,
		StateTransition:     &transition,
		UploadSync:          new(uint64)} // TODO: remove
	if tdRaw.flowId == 0 {
		// we have stats for each reconnect, but only send stats for the initial connection
		msg.Stats = &tdRaw.sessionStats
	}

	if len(tdRaw.failedDecoys) > 0 {
		failedDecoysIdx := 0 // how many failed decoys to report now
		for failedDecoysIdx < len(tdRaw.failedDecoys) {
			if paddingMinSize < proto.Size(&pb.ClientToStation{
				FailedDecoys: tdRaw.failedDecoys[:failedDecoysIdx+1]}) {
				// if failedDecoys list is too big to fit in place of min padding
				// then send the rest on the next reconnect
				break
			}
			failedDecoysIdx += 1
		}
		paddingDecrement = proto.Size(&pb.ClientToStation{
			FailedDecoys: tdRaw.failedDecoys[:failedDecoysIdx]})

		msg.FailedDecoys = tdRaw.failedDecoys[:failedDecoysIdx]
		tdRaw.failedDecoys = tdRaw.failedDecoys[failedDecoysIdx:]
	}
	msg.Padding = []byte(getRandPadding(paddingMinSize-paddingDecrement,
		paddingMaxSize-paddingDecrement, paddingSmoothness))

	msgBytes, err := proto.Marshal(&msg)
	if err != nil {
		return
	}

	Logger().Infoln(tdRaw.idStr()+" sending transition: ", msg.String())
	b := getMsgWithHeader(msgProtobuf, msgBytes)
	n, err = tdRaw.tlsConn.Write(b)
	return
}

// mutates tdRaw: sets tdRaw.UploadLimit
func (tdRaw *tdRawConn) genHTTP1Tag(tag, encryptedProtoMsg []byte) (string, error) {
	sharedHeaders := `Host: ` + tdRaw.decoySpec.GetHostname() +
		"\nUser-Agent: TapDance/1.2 (+https://refraction.network/info)"
	if len(encryptedProtoMsg) > 0 {
		sharedHeaders += "\nX-Proto: " + base64.StdEncoding.EncodeToString(encryptedProtoMsg)
	}
	var httpTag string
	switch tdRaw.tagType {
	// for complete copy http generator of golang
	case tagHttpGetComplete:
		fallthrough
	case tagHttpGetIncomplete:
		tdRaw.UploadLimit = int(tdRaw.decoySpec.GetTcpwin()) - getRandInt(1, 1045)
		httpTag = fmt.Sprintf(`GET / HTTP/1.1
%s
X-Ignore: %s`, sharedHeaders, getRandPadding(7, maxInt(612-len(sharedHeaders), 7), 10))
		httpTag = strings.Replace(httpTag, "\n", "\r\n", -1)
	case tagHttpPostIncomplete:
		ContentLength := getRandInt(900000, 1045000)
		tdRaw.UploadLimit = ContentLength - 1
		httpTag = fmt.Sprintf(`POST / HTTP/1.1
%s
Accept-Encoding: None
X-Padding: %s
Content-Type: application/zip; boundary=----WebKitFormBoundaryaym16ehT29q60rUx
Content-Length: %s
----WebKitFormBoundaryaym16ehT29q60rUx
Content-Disposition: form-data; name=\"td.zip\"
`, sharedHeaders, getRandPadding(1, maxInt(461-len(sharedHeaders), 1), 10), strconv.Itoa(ContentLength))
		httpTag = strings.Replace(httpTag, "\n", "\r\n", -1)
	}

	keystreamOffset := len(httpTag)
	keystreamSize := (len(tag)/3+1)*4 + keystreamOffset // we can't use first 2 bits of every byte
	wholeKeystream, err := tdRaw.tlsConn.GetOutKeystream(keystreamSize)
	if err != nil {
		return httpTag, err
	}
	keystreamAtTag := wholeKeystream[keystreamOffset:]

	httpTag += string(reverseEncrypt(tag, keystreamAtTag))
	if tdRaw.tagType == tagHttpGetComplete {
		httpTag += "\r\n\r\n"
	}
	Logger().Debugf("Generated HTTP TAG:\n%s\n", httpTag)
	return httpTag, nil
}

func (tdRaw *tdRawConn) IsClosed() bool {
	select {
	case <-tdRaw.closed:
		return true
	default:
		return false
	}
}
