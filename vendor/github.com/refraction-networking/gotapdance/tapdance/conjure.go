package tapdance

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	ca "github.com/refraction-networking/conjure/pkg/client/assets"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	ps "github.com/refraction-networking/conjure/pkg/phantoms"
	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// V6 - Struct to track V6 support and cache result across sessions
type V6 struct {
	support bool
	include uint
}

const (
	v4 uint = iota
	v6
	both
)

// Include returns a private field of the V6 Support struct.
func (v *V6) Include() uint {
	if v == nil {
		return 0
	}
	return v.include
}

// [TODO]{priority:winter-break} make this not constant
const defaultRegWidth = 5

// DialConjure - Perform Registration and Dial on an existing Conjure session
func DialConjure(ctx context.Context, cjSession *ConjureSession, registrationMethod Registrar, registerOnly bool) (net.Conn, error) {

	if cjSession == nil {
		return nil, fmt.Errorf("No Session Provided")
	}

	err := cjSession.Transport.Prepare(ctx, cjSession.Dialer)
	if err != nil {
		return nil, err
	}

	//cjSession.setV6Support(both)	 // We don't want to override this here; defaults set in MakeConjureSession
	// Prepare registrar specific keys
	registrationMethod.PrepareRegKeys(getStationKey(), cjSession.Keys.SharedSecret)
	// Choose Phantom Address in Register depending on v6 support.

	registration, err := registrationMethod.Register(cjSession, ctx)
	if err != nil {
		Logger().Debugf("%v Failed to register: %v", cjSession.IDString(), err)
		return nil, err
	}

	if registerOnly {
		fmt.Printf("%v Successfully registered to use IPv4 phantom: %s:%d or IPv6 phantom: %s:%d", cjSession.IDString(), registration.phantom4.String(), registration.phantomDstPort, registration.phantom6.String(), registration.phantomDstPort)
		return nil, err
	}

	// registration, ok := reg.(*ConjureReg)
	// if !ok {
	// 	return nil, fmt.Errorf("Unknown registration Returned")
	// }

	tp, isconnecting := cjSession.Transport.(interfaces.ConnectingTransport)
	if isconnecting {
		if tp.DisableRegDelay() {
			cjSession.RegDelay = 0
		}
	}

	sleepWithContext(ctx, cjSession.RegDelay)

	Logger().Debugf("%v Attempting to Connect using %s libcj_v%d...", cjSession.IDString(), registration.Transport.Name(), core.CurrentClientLibraryVersion())
	return registration.Connect(ctx, cjSession.Dialer)
}

// // testV6 -- This is over simple and incomplete (currently unused)
// // checking for unreachable alone does not account for local ipv6 addresses
// // [TODO]{priority:winter-break} use getifaddr reverse bindings
// func testV6() bool {
// 	dialError := make(chan error, 1)
// 	d := Assets().GetV6Decoy()
// 	go func() {
// 		conn, err := net.Dial("tcp", d.GetIpAddrStr())
// 		if err != nil {
// 			dialError <- err
// 			return
// 		}
// 		conn.Close()
// 		dialError <- nil
// 	}()

// 	time.Sleep(500 * time.Microsecond)
// 	// The only error that would return before this is a network unreachable error
// 	select {
// 	case err := <-dialError:
// 		Logger().Debugf("v6 unreachable received: %v", err)
// 		return false
// 	default:
// 		return true
// 	}
// }

// ConjureSession - Create a session with details for registration and connection
type ConjureSession struct {
	Keys           *core.SharedKeys
	V6Support      *V6
	UseProxyHeader bool
	SessionID      uint64
	Phantom        *net.IP
	Transport      Transport
	CovertAddress  string
	// rtt			   uint // tracked in stats

	DisableRegistrarOverrides bool

	// TcpDialer allows the caller to provide a custom dialer for outgoing proxy connections.
	//
	// THIS IS REQUIRED TO INTERFACE WITH PSIPHON ANDROID
	//		we use their dialer to prevent connection loopback into our own proxy
	//		connection when tunneling the whole device.
	Dialer dialFunc

	// RegDelay is the delay duration to wait for registration ingest.
	RegDelay time.Duration

	// performance tracking
	stats *pb.SessionStats
}

// MakeConjureSessionSilent creates a conjure session without logging anything
func MakeConjureSessionSilent(covert string, transport Transport) *ConjureSession {
	keys, err := core.GenerateClientSharedKeys(getStationKey())

	if err != nil {
		return nil
	}
	//[TODO]{priority:NOW} move v6support initialization to assets so it can be tracked across dials
	cjSession := &ConjureSession{
		Keys:                      keys,
		V6Support:                 &V6{support: true, include: both},
		UseProxyHeader:            false,
		Transport:                 transport,
		CovertAddress:             covert,
		SessionID:                 sessionsTotal.GetAndInc(),
		DisableRegistrarOverrides: false,
	}

	return cjSession
}

func LogConjureSession(cjSession *ConjureSession) {

	keys := cjSession.Keys

	sharedSecretStr := make([]byte, hex.EncodedLen(len(keys.SharedSecret)))
	hex.Encode(sharedSecretStr, keys.SharedSecret)
	Logger().Debugf("%v Shared Secret  - %s", cjSession.IDString(), sharedSecretStr)

	Logger().Debugf("%v covert %s", cjSession.IDString(), cjSession.CovertAddress)

	reprStr := make([]byte, hex.EncodedLen(len(keys.Representative)))
	hex.Encode(reprStr, keys.Representative)
	Logger().Debugf("%v Representative - %s", cjSession.IDString(), reprStr)

}

func MakeConjureSession(covert string, transport Transport) *ConjureSession {

	cjSession := MakeConjureSessionSilent(covert, transport)
	if cjSession == nil {
		return nil
	}

	// Print out the session details (debug)
	LogConjureSession(cjSession)

	return cjSession
}

func FindConjureSessionInRange(covert string, transport Transport, phantomSubnet *net.IPNet) *ConjureSession {

	count := 0
	Logger().Debugf("Searching for a seed for phantom subnet %v...", phantomSubnet)
	for count < 100000 {
		// Generate a random session
		cjSession := MakeConjureSessionSilent(covert, transport)
		count += 1

		// Get the phantoms this seed would generate
		phantom4, phantom6, _, err := SelectPhantom(cjSession.Keys.ConjureSeed, cjSession.V6Support.include)
		if err != nil {
			Logger().Warnf("%v failed to select Phantom: %v", cjSession.IDString(), err)
		}

		// See if our phantoms are in the subnet
		if phantomSubnet.Contains(*phantom4) || phantomSubnet.Contains(*phantom6) {
			Logger().Debugf("Generated %d sessions to find one in %v", count, phantomSubnet)
			// Print out what we got
			LogConjureSession(cjSession)

			return cjSession
		}
	}
	Logger().Warnf("Failed to find a session in %v", phantomSubnet)
	return nil
}

// IDString - Get the ID string for the session
func (cjSession *ConjureSession) IDString() string {
	if cjSession.Keys == nil || cjSession.Keys.SharedSecret == nil {
		return fmt.Sprintf("[%v-000000]", strconv.FormatUint(cjSession.SessionID, 10))
	}

	secret := make([]byte, hex.EncodedLen(len(cjSession.Keys.SharedSecret)))
	n := hex.Encode(secret, cjSession.Keys.SharedSecret)
	if n < 6 {
		return fmt.Sprintf("[%v-000000]", strconv.FormatUint(cjSession.SessionID, 10))
	}
	return fmt.Sprintf("[%v-%s]", strconv.FormatUint(cjSession.SessionID, 10), secret[:6])
}

// String - Print the string for debug and/or logging
func (cjSession *ConjureSession) String() string {
	return cjSession.IDString()
	// expand for debug??
}

// conjureReg generates ConjureReg from the corresponding ConjureSession
func (cjSession *ConjureSession) conjureReg() *ConjureReg {
	return &ConjureReg{
		ConjureSession: cjSession,
		sessionIDStr:   cjSession.IDString(),
		keys:           cjSession.Keys,
		stats:          &pb.SessionStats{},
		v6Support:      cjSession.V6Support.include,
		covertAddress:  cjSession.CovertAddress,
		Transport:      cjSession.Transport,
		Dialer:         removeLaddr(cjSession.Dialer),
		useProxyHeader: cjSession.UseProxyHeader,
	}
}

// BidirectionalRegData returns a C2SWrapper for bidirectional registration
func (cjSession *ConjureSession) BidirectionalRegData(ctx context.Context, regSource *pb.RegistrationSource) (*ConjureReg, *pb.C2SWrapper, error) {
	reg := cjSession.conjureReg()

	c2s, err := reg.generateClientToStation(ctx)
	if err != nil {
		return nil, nil, err
	}

	return reg, &pb.C2SWrapper{
		SharedSecret:        cjSession.Keys.SharedSecret,
		RegistrationPayload: c2s,
		RegistrationSource:  regSource,
	}, nil

}

// UnidirectionalRegData returns a C2SWrapper for unidirectional registration
func (cjSession *ConjureSession) UnidirectionalRegData(ctx context.Context, regSource *pb.RegistrationSource) (*ConjureReg, *pb.C2SWrapper, error) {
	reg := cjSession.conjureReg()

	phantom4, phantom6, supportRandomPort, err := SelectPhantom(cjSession.Keys.ConjureSeed, cjSession.V6Support.include)
	if err != nil {
		Logger().Warnf("%v failed to select Phantom: %v", cjSession.IDString(), err)
		return nil, nil, err
	}

	reg.phantom4 = phantom4
	reg.phantom6 = phantom6

	if supportRandomPort {
		reg.phantomDstPort, err = cjSession.Transport.GetDstPort(reg.keys.ConjureSeed)
		if err != nil {
			return nil, nil, err
		}
	} else {
		reg.phantomDstPort = 443
	}

	c2s, err := reg.generateClientToStation(ctx)
	if err != nil {
		return nil, nil, err
	}

	return reg, &pb.C2SWrapper{
		SharedSecret:        cjSession.Keys.SharedSecret,
		RegistrationPayload: c2s,
		RegistrationSource:  regSource,
	}, nil
}

// GetV6Support created for the sake of removing ConjureReg
func (cjSession *ConjureSession) GetV6Support() *bool {
	support := true
	if cjSession.V6Support.include == v4 {
		support = false
	}
	return &support
}

// GetV4Support created for the sake of removing ConjureReg
func (cjSession *ConjureSession) GetV4Support() *bool {
	// for now return true and register both
	support := true
	if cjSession.V6Support.include == v6 {
		support = false
	}
	return &support
}

// GetV6Include - returns the Include var of the clients V6 support
func (cjSession *ConjureSession) GetV6Include() uint {
	return cjSession.V6Support.include
}

type resultTuple struct {
	conn net.Conn
	err  error
}

// Simple type alias for brevity
type dialFunc = func(ctx context.Context, network, laddr, raddr string) (net.Conn, error)

func (reg *ConjureReg) connect(ctx context.Context, addr string, dialer dialFunc) (net.Conn, error) {
	//[reference] Create Context with deadline
	deadline, deadlineAlreadySet := ctx.Deadline()
	if !deadlineAlreadySet {
		//[reference] randomized timeout to Dial dark decoy address
		deadline = time.Now().Add(reg.GetRandomDuration(0, 1461*2, 2453*3))
	}
	childCtx, childCancelFunc := context.WithDeadline(ctx, deadline)
	defer childCancelFunc()

	//[reference] Connect to Phantom Host
	phantomAddr := net.JoinHostPort(addr, strconv.Itoa(int(reg.phantomDstPort)))

	// conn, err := reg.Dialer(childCtx, "tcp", phantomAddr)
	return dialer(childCtx, "tcp", "", phantomAddr)
}

// ErrNoOpenConns indicates that the client Failed to establish a connection with any phantom addr
var ErrNoOpenConns = errors.New("no open connections")

func (reg *ConjureReg) getFirstConnection(ctx context.Context, dialer dialFunc, phantoms []*net.IP) (net.Conn, error) {
	connChannel := make(chan resultTuple, len(phantoms))
	for _, p := range phantoms {
		if p == nil {
			connChannel <- resultTuple{nil, fmt.Errorf("nil addr")}
			continue
		}
		go func(phantom *net.IP) {
			conn, err := reg.connect(ctx, phantom.String(), dialer)
			if err != nil {
				Logger().Infof("%v failed to dial phantom %v: %v", reg.sessionIDStr, phantom.String(), err)
				connChannel <- resultTuple{nil, err}
				return
			}
			Logger().Infof("%v Connected to phantom %v using transport %s", reg.sessionIDStr, net.JoinHostPort(phantom.String(), strconv.Itoa(int(reg.phantomDstPort))), reg.Transport)
			connChannel <- resultTuple{conn, nil}
		}(p)
	}

	open := len(phantoms)
	for open > 0 {
		rt := <-connChannel
		if rt.err != nil {
			open--
			continue
		}

		// If we made it here we're returning the connection, so
		// set up a goroutine to close the others
		go func() {
			// Close all but one connection (the good one)
			for open > 1 {
				t := <-connChannel
				if t.err == nil {
					t.conn.Close()
				}
				open--
			}
		}()

		return rt.conn, nil
	}

	return nil, ErrNoOpenConns
}

// Connect - Use a registration (result of calling Register) to connect to a phantom
// Note: This is hacky but should work for v4, v6, or both as any nil phantom addr will
// return a dial error and be ignored.
func (reg *ConjureReg) Connect(ctx context.Context, dialer dialFunc) (net.Conn, error) {
	phantoms := []*net.IP{reg.phantom4, reg.phantom6}

	// Prepare the transport by generating any necessary keys
	pubKey := getStationKey()
	reg.Transport.PrepareKeys(pubKey, reg.keys.SharedSecret, reg.keys.Reader)

	switch transport := reg.Transport.(type) {
	case interfaces.WrappingTransport:
		conn, err := reg.getFirstConnection(ctx, dialer, phantoms)
		if err != nil {
			Logger().Infof("%v failed to form phantom connection: %v", reg.sessionIDStr, err)
			return nil, err
		}

		conn, err = transport.WrapConn(conn)
		if err != nil {
			Logger().Infof("WrapConn failed")
			return nil, err
		}

		return conn, nil
	case interfaces.ConnectingTransport:
		transportDialer, err := transport.WrapDial(dialer)
		if err != nil {
			return nil, fmt.Errorf("error wrapping transport dialer: %v", err)
		}

		conn, err := reg.getFirstConnection(ctx, transportDialer, phantoms)
		if err != nil {
			return nil, fmt.Errorf("failed to dialing connecting transport: %v", err)
		}

		return conn, nil
	}

	return nil, fmt.Errorf("transport does not implement any transport interface")
}

// ConjureReg - Registration structure created for each individual registration within a session.
type ConjureReg struct {
	Transport
	*ConjureSession

	seed           []byte
	sessionIDStr   string
	phantom4       *net.IP
	phantom6       *net.IP
	phantomDstPort uint16
	useProxyHeader bool
	covertAddress  string
	phantomSNI     string
	v6Support      uint

	// THIS IS REQUIRED TO INTERFACE WITH PSIPHON ANDROID
	//		we use their dialer to prevent connection loopback into our own proxy
	//		connection when tunneling the whole device.
	Dialer func(context.Context, string, string) (net.Conn, error)

	stats *pb.SessionStats
	keys  *core.SharedKeys
	m     sync.Mutex
}

// UnpackRegResp unpacks the RegistrationResponse message sent back by the station. This unpacks
// any field overrides sent by the registrar. When using a bidirectional registration method
// the server chooses the phantom IP and Port by default. Overrides to transport parameters
// are applied when reg.DisableRegistrarOverrides is false.
func (reg *ConjureReg) UnpackRegResp(regResp *pb.RegistrationResponse) error {
	if regResp == nil {
		return nil
	}
	if reg.v6Support == v4 {
		// Save the ipv4address in the Conjure Reg struct (phantom4) to return
		ip4 := make(net.IP, 4)
		addr4 := regResp.GetIpv4Addr()
		binary.BigEndian.PutUint32(ip4, addr4)
		reg.phantom4 = &ip4
	} else if reg.v6Support == v6 {
		// Save the ipv6address in the Conjure Reg struct (phantom6) to return
		addr6 := net.IP(regResp.GetIpv6Addr())
		reg.phantom6 = &addr6
	} else {
		// Case where cjSession.V6Support == both
		// Save the ipv4address in the Conjure Reg struct (phantom4) to return
		ip4 := make(net.IP, 4)
		addr4 := regResp.GetIpv4Addr()
		binary.BigEndian.PutUint32(ip4, addr4)
		reg.phantom4 = &ip4

		// Save the ipv6address in the Conjure Reg struct (phantom6) to return
		addr6 := net.IP(regResp.GetIpv6Addr())
		reg.phantom6 = &addr6
	}

	p := uint16(regResp.GetDstPort())
	if p != 0 {
		reg.phantomDstPort = p
	} else if reg.phantomDstPort == 0 {
		// If a bidirectional registrar does not support randomization (or doesn't set the port in the
		// registration response we default to the original port we used for all transports).
		reg.phantomDstPort = 443
	}

	maybeTP := regResp.GetTransportParams()
	if maybeTP != nil && !reg.DisableRegistrarOverrides {
		// If an error occurs while setting transport parameters give up as continuing would likely
		// lead to incongruence between the client and station and an unserviceable connection.
		err := reg.Transport.SetSessionParams(maybeTP, true)
		if err != nil {
			return fmt.Errorf("Param Parse error: %w", err)
		}
	} else if maybeTP != nil && reg.DisableRegistrarOverrides {
		return fmt.Errorf("registrar failed to respect disabled overrides")
	}

	// Client config -- check if not nil in the registration response
	if regResp.GetClientConf() != nil {
		currGen := ca.Assets().GetGeneration()
		incomingGen := regResp.GetClientConf().GetGeneration()
		Logger().Debugf("received clientconf in regResponse w/ gen %d", incomingGen)
		if currGen < incomingGen {
			Logger().Debugf("Updating clientconf %d -> %d", currGen, incomingGen)
			_err := ca.Assets().SetClientConf(regResp.GetClientConf())
			if _err != nil {
				Logger().Warnf("could not set ClientConf in bidirectional API: %v", _err.Error())
			}
		}
	}

	return nil
}

func (reg *ConjureReg) getPbTransport() pb.TransportType {
	return reg.Transport.ID()
}

func (reg *ConjureReg) getPbTransportParams() (*anypb.Any, error) {
	var m proto.Message
	m, err := reg.Transport.GetParams()
	if err != nil {
		return nil, err
	} else if m == nil {
		return nil, nil
	}
	return anypb.New(m)
}

func (reg *ConjureReg) generateFlags() *pb.RegistrationFlags {
	flags := &pb.RegistrationFlags{}
	mask := default_flags
	if reg.useProxyHeader {
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

func (reg *ConjureReg) generateClientToStation(ctx context.Context) (*pb.ClientToStation, error) {
	var covert *string
	if len(reg.covertAddress) > 0 {
		//[TODO]{priority:medium} this isn't the correct place to deal with signaling to the station
		//transition = pb.C2S_Transition_C2S_SESSION_COVERT_INIT
		covert = &reg.covertAddress
	}

	//[reference] Generate ClientToStation protobuf
	// transition := pb.C2S_Transition_C2S_SESSION_INIT
	currentGen := ca.Assets().GetGeneration()
	currentLibVer := core.CurrentClientLibraryVersion()
	transport := reg.getPbTransport()

	transportParams, err := reg.getPbTransportParams()
	if err != nil {
		Logger().Debugf("%s failed to marshal transport parameters ", reg.sessionIDStr)
	}

	// remove type url to save space for DNS registration
	// for server side changes see https://github.com/refraction-networking/conjure/pull/163
	transportParams.TypeUrl = ""

	initProto := &pb.ClientToStation{
		ClientLibVersion:    &currentLibVer,
		CovertAddress:       covert,
		DecoyListGeneration: &currentGen,
		V6Support:           reg.ConjureSession.GetV6Support(),
		V4Support:           reg.ConjureSession.GetV4Support(),
		Transport:           &transport,
		Flags:               reg.generateFlags(),
		TransportParams:     transportParams,

		DisableRegistrarOverrides: &reg.ConjureSession.DisableRegistrarOverrides,

		//[TODO]{priority:medium} specify width in C2S because different width might
		// 		be useful in different regions (constant for now.)
	}

	if len(reg.phantomSNI) > 0 {
		initProto.MaskedDecoyServerName = &reg.phantomSNI
	}

	for (proto.Size(initProto)+AES_GCM_TAG_SIZE)%3 != 0 {
		initProto.Padding = append(initProto.Padding, byte(0))
	}

	return initProto, nil
}

func (reg *ConjureReg) v6SupportStr() string {
	switch reg.v6Support {
	case both:
		return "Both"
	case v4:
		return "V4"
	case v6:
		return "V6"
	default:
		return "unknown"
	}
}

// Phantom4 returns the ipv4 phantom address
func (reg *ConjureReg) Phantom4() net.IP {
	return *reg.phantom4
}

// Phantom6 returns the ipv6 phantom address
func (reg *ConjureReg) Phantom6() net.IP {
	return *reg.phantom6
}

func (reg *ConjureReg) digestStats() string {
	//[TODO]{priority:eventually} add decoy details to digest
	if reg == nil || reg.stats == nil {
		return fmt.Sprint("{result:\"no stats tracked\"}")
	}

	reg.m.Lock()
	defer reg.m.Unlock()
	return fmt.Sprintf("{result:\"success\", tcp_to_decoy:%v, tls_to_decoy:%v, total_time_to_connect:%v}",
		reg.stats.GetTcpToDecoy(),
		reg.stats.GetTlsToDecoy(),
		reg.stats.GetTotalTimeToConnect())
}

func (cjSession *ConjureSession) setV6Support(support uint) {
	switch support {
	case v4:
		cjSession.V6Support.support = false
		cjSession.V6Support.include = v4
	case v6:
		cjSession.V6Support.support = true
		cjSession.V6Support.include = v6
	case both:
		cjSession.V6Support.support = true
		cjSession.V6Support.include = both
	default:
		cjSession.V6Support.support = true
		cjSession.V6Support.include = v6
	}
}

func sleepWithContext(ctx context.Context, duration time.Duration) {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// SelectPhantom - select one phantom IP address based on shared secret
func SelectPhantom(seed []byte, support uint) (*net.IP, *net.IP, bool, error) {
	phantomSubnets := ca.Assets().GetPhantomSubnets()
	switch support {
	case v4:
		phantomIPv4, err := ps.SelectPhantom(seed, phantomSubnets, ps.V4Only, true)
		if err != nil {
			return nil, nil, false, err
		}
		return phantomIPv4.IP(), nil, phantomIPv4.SupportRandomPort(), nil
	case v6:
		phantomIPv6, err := ps.SelectPhantom(seed, phantomSubnets, ps.V6Only, true)
		if err != nil {
			return nil, nil, false, err
		}
		return nil, phantomIPv6.IP(), phantomIPv6.SupportRandomPort(), nil
	case both:
		phantomIPv4, err := ps.SelectPhantom(seed, phantomSubnets, ps.V4Only, true)
		if err != nil {
			return nil, nil, false, err
		}
		phantomIPv6, err := ps.SelectPhantom(seed, phantomSubnets, ps.V6Only, true)
		if err != nil {
			return nil, nil, false, err
		}
		return phantomIPv4.IP(), phantomIPv6.IP(), phantomIPv4.SupportRandomPort() && phantomIPv6.SupportRandomPort(), nil
	default:
		return nil, nil, false, fmt.Errorf("unknown v4/v6 support")
	}
}

func getStationKey() [32]byte {
	return *ca.Assets().GetConjurePubkey()
}

// GetRandomDuration returns a random duration that
func (reg *ConjureReg) GetRandomDuration(base, min, max int) time.Duration {
	addon := getRandInt(min, max) / 1000 // why this min and max???
	rtt := rttInt(reg.getTcpToDecoy())
	return time.Millisecond * time.Duration(base+rtt*addon)
}

func (reg *ConjureReg) getTcpToDecoy() uint32 {
	reg.m.Lock()
	defer reg.m.Unlock()
	if reg != nil {
		if reg.stats != nil {
			return reg.stats.GetTcpToDecoy()
		}
	}
	return 0
}

func rttInt(millis uint32) int {
	defaultValue := 300
	if millis == 0 {
		return defaultValue
	}
	return int(millis)
}

// RegError - Registration Error passed during registration to indicate failure mode
type RegError struct {
	code uint
	msg  string
}

func NewRegError(code uint, msg string) RegError {
	return RegError{code: code, msg: msg}
}

func (err RegError) Error() string {
	return fmt.Sprintf("Registration Error [%v]: %v", err.CodeStr(), err.msg)
}

func (err RegError) Code() uint {
	return err.code
}

// CodeStr - Get desctriptor associated with error code
func (err RegError) CodeStr() string {
	switch err.code {
	case Unreachable:
		return "UNREACHABLE"
	case DialFailure:
		return "DIAL_FAILURE"
	case NotImplemented:
		return "NOT_IMPLEMENTED"
	case TLSError:
		return "TLS_ERROR"
	default:
		return "UNKNOWN"
	}
}

// removeLaddr removes the laddr field in dialer
func removeLaddr(dialer func(ctx context.Context, network, laddr, raddr string) (net.Conn, error)) func(ctx context.Context, network, raddr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer(ctx, network, "", addr)
	}
}

const (
	// Unreachable -Dial Error Unreachable -- likely network unavailable (i.e. ipv6 error)
	Unreachable = iota

	// DialFailure - Dial Error Other than unreachable
	DialFailure

	// NotImplemented - Related Function Not Implemented
	NotImplemented

	// TLSError (Expired, Wrong-Host, Untrusted-Root, ...)
	TLSError

	// Unknown - Error occurred without obvious explanation
	Unknown
)
