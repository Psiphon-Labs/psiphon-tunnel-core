package tapdance

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	pt "git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	ps "github.com/refraction-networking/gotapdance/tapdance/phantoms"
	tls "github.com/refraction-networking/utls"
	"gitlab.com/yawning/obfs4.git/common/ntor"
	"gitlab.com/yawning/obfs4.git/transports/obfs4"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// V6 - Struct to track V6 support and cache result across sessions
type V6 struct {
	support bool
	include uint
}

// Registrar defines the interface for a service executing
// decoy registrations.
type Registrar interface {
	Register(*ConjureSession, context.Context) (*ConjureReg, error)
}

type DecoyRegistrar struct {

	// TcpDialer is a custom TCP dailer to use when establishing TCP connections
	// to decoys. When nil, Dialer.TcpDialer will be used.
	TcpDialer func(context.Context, string, string) (net.Conn, error)
}

func (r DecoyRegistrar) Register(cjSession *ConjureSession, ctx context.Context) (*ConjureReg, error) {
	Logger().Debugf("%v Registering V4 and V6 via DecoyRegistrar", cjSession.IDString())

	// Choose N (width) decoys from decoylist
	decoys, err := SelectDecoys(cjSession.Keys.SharedSecret, cjSession.V6Support.include, cjSession.Width)
	if err != nil {
		Logger().Warnf("%v failed to select decoys: %v", cjSession.IDString(), err)
		return nil, err
	}
	cjSession.RegDecoys = decoys

	phantom4, phantom6, err := SelectPhantom(cjSession.Keys.ConjureSeed, cjSession.V6Support.include)
	if err != nil {
		Logger().Warnf("%v failed to select Phantom: %v", cjSession.IDString(), err)
		return nil, err
	}

	//[reference] Prepare registration
	reg := &ConjureReg{
		sessionIDStr:   cjSession.IDString(),
		keys:           cjSession.Keys,
		stats:          &pb.SessionStats{},
		phantom4:       phantom4,
		phantom6:       phantom6,
		v6Support:      cjSession.V6Support.include,
		covertAddress:  cjSession.CovertAddress,
		transport:      cjSession.Transport,
		TcpDialer:      cjSession.TcpDialer,
		useProxyHeader: cjSession.UseProxyHeader,
	}

	if r.TcpDialer != nil {
		reg.TcpDialer = r.TcpDialer
	}

	// //[TODO]{priority:later} How to pass context to multiple registration goroutines?
	if ctx == nil {
		ctx = context.Background()
	}

	width := uint(len(cjSession.RegDecoys))
	if width < cjSession.Width {
		Logger().Warnf("%v Using width %v (default %v)", cjSession.IDString(), width, cjSession.Width)
	}

	Logger().Debugf("%v Registration - v6:%v, covert:%v, phantoms:%v,[%v], width:%v, transport:%v",
		reg.sessionIDStr,
		reg.v6SupportStr(),
		reg.covertAddress,
		reg.phantom4.String(),
		reg.phantom6.String(),
		cjSession.Width,
		cjSession.Transport,
	)

	//[reference] Send registrations to each decoy
	dialErrors := make(chan error, width)
	for _, decoy := range cjSession.RegDecoys {
		Logger().Debugf("%v Sending Reg: %v, %v", cjSession.IDString(), decoy.GetHostname(), decoy.GetIpAddrStr())
		//decoyAddr := decoy.GetIpAddrStr()

		// [Psiphon]
		//
		// Workaround: reference and pass in reg.TcpDialer rather than wait
		// and reference it within reg.send in the goroutine. This allows
		// gotapdance users to clear and reset the TcpDialer field for cached
		// ConjureRegs without risking a race condition or nil pointer
		// dereference. These conditions otherwise arise as reg.send
		// goroutines can remain running, and reference reg.TcpDialer, after
		// Register returns -- the point at which gotapdance users may cache
		// the ConjureReg.

		go reg.send(ctx, decoy, reg.TcpDialer, dialErrors, cjSession.registrationCallback)
	}

	//[reference] Dial errors happen immediately so block until all N dials complete
	var unreachableCount uint = 0
	for err := range dialErrors {
		if err != nil {
			Logger().Debugf("%v %v", cjSession.IDString(), err)
			if dialErr, ok := err.(RegError); ok && dialErr.code == Unreachable {
				// If we failed because ipv6 network was unreachable try v4 only.
				unreachableCount++
				if unreachableCount < width {
					continue
				} else {
					break
				}
			}
		}
		//[reference] if we succeed or fail for any other reason then the network is reachable and we can continue
		break
	}

	//[reference] if ALL fail to dial return error (retry in parent if ipv6 unreachable)
	if unreachableCount == width {
		Logger().Debugf("%v NETWORK UNREACHABLE", cjSession.IDString())
		return nil, &RegError{code: Unreachable, msg: "All decoys failed to register -- Dial Unreachable"}
	}

	// randomized sleeping here to break the intraflow signal
	toSleep := reg.getRandomDuration(3000, 212, 3449)
	Logger().Debugf("%v Successfully sent registrations, sleeping for: %v", cjSession.IDString(), toSleep)
	sleepWithContext(ctx, toSleep)

	return reg, nil
}

// Registration strategy using a centralized REST API to
// create registrations. Only the Endpoint need be specified;
// the remaining fields are valid with their zero values and
// provide the opportunity for additional control over the process.
type APIRegistrar struct {
	// Endpoint to use in registration request
	Endpoint string

	// HTTP client to use in request
	Client *http.Client

	// Length of time to delay after confirming successful
	// registration before attempting a connection,
	// allowing for propagation throughout the stations.
	ConnectionDelay time.Duration

	// Maximum number of retries before giving up
	MaxRetries int

	// A secondary registration method to use on failure.
	// Because the API registration can give us definite
	// indication of a failure to register, this can be
	// used as a "backup" in the case of the API being
	// down or being blocked.
	//
	// If this field is nil, no secondary registration will
	// be attempted. If it is non-nil, after failing to register
	// (retrying MaxRetries times) we will fall back to
	// the Register method on this field.
	SecondaryRegistrar Registrar
}

func (r APIRegistrar) Register(cjSession *ConjureSession, ctx context.Context) (*ConjureReg, error) {
	Logger().Debugf("%v registering via APIRegistrar", cjSession.IDString())
	// TODO: this section is duplicated from DecoyRegistrar; consider consolidating
	phantom4, phantom6, err := SelectPhantom(cjSession.Keys.ConjureSeed, cjSession.V6Support.include)
	if err != nil {
		Logger().Warnf("%v failed to select Phantom: %v", cjSession.IDString(), err)
		return nil, err
	}

	// [reference] Prepare registration
	reg := &ConjureReg{
		sessionIDStr:   cjSession.IDString(),
		keys:           cjSession.Keys,
		stats:          &pb.SessionStats{},
		phantom4:       phantom4,
		phantom6:       phantom6,
		v6Support:      cjSession.V6Support.include,
		covertAddress:  cjSession.CovertAddress,
		transport:      cjSession.Transport,
		TcpDialer:      cjSession.TcpDialer,
		useProxyHeader: cjSession.UseProxyHeader,
	}

	c2s := reg.generateClientToStation()

	protoPayload := pb.C2SWrapper{
		SharedSecret:        cjSession.Keys.SharedSecret,
		RegistrationPayload: c2s,
	}

	payload, err := proto.Marshal(&protoPayload)
	if err != nil {
		Logger().Warnf("%v failed to marshal ClientToStation payload: %v", cjSession.IDString(), err)
		return nil, err
	}

	if r.Client == nil {
		// Transports should ideally be re-used for TCP connection pooling,
		// but each registration is most likely making precisely one request,
		// or if it's making more than one, is most likely due to an underlying
		// connection issue rather than an application-level error anyways.
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.DialContext = reg.TcpDialer
		r.Client = &http.Client{Transport: t}
	}

	tries := 0
	for tries < r.MaxRetries+1 {
		tries++
		err = r.executeHTTPRequest(ctx, cjSession, payload)
		if err == nil {
			Logger().Debugf("%v API registration succeeded", cjSession.IDString())
			if r.ConnectionDelay != 0 {
				Logger().Debugf("%v sleeping for %v", cjSession.IDString(), r.ConnectionDelay)
				sleepWithContext(ctx, r.ConnectionDelay)
			}
			return reg, nil
		}
		Logger().Warnf("%v failed API registration, attempt %d/%d", cjSession.IDString(), tries, r.MaxRetries+1)
	}

	// If we make it here, we failed API registration
	Logger().Warnf("%v giving up on API registration", cjSession.IDString())

	if r.SecondaryRegistrar != nil {
		Logger().Debugf("%v trying secondary registration method", cjSession.IDString())
		return r.SecondaryRegistrar.Register(cjSession, ctx)
	}

	return nil, err
}

func (r APIRegistrar) executeHTTPRequest(ctx context.Context, cjSession *ConjureSession, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", r.Endpoint, bytes.NewReader(payload))
	if err != nil {
		Logger().Warnf("%v failed to create HTTP request to registration endpoint %s: %v", cjSession.IDString(), r.Endpoint, err)
		return err
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		Logger().Warnf("%v failed to do HTTP request to registration endpoint %s: %v", cjSession.IDString(), r.Endpoint, err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		Logger().Warnf("%v got non-success response code %d from registration endpoint %v", cjSession.IDString(), resp.StatusCode, r.Endpoint)
		return fmt.Errorf("non-success response code %d on %s", resp.StatusCode, r.Endpoint)
	}

	return nil
}

const (
	v4 uint = iota
	v6
	both
)

//[TODO]{priority:winter-break} make this not constant
const defaultRegWidth = 5

// DialConjureAddr - Perform Registration and Dial after creating  a Conjure session from scratch
func DialConjureAddr(ctx context.Context, address string, registrationMethod Registrar) (net.Conn, error) {
	cjSession := makeConjureSession(address, pb.TransportType_Min)
	return DialConjure(ctx, cjSession, registrationMethod)
}

// DialConjure - Perform Registration and Dial on an existing Conjure session
func DialConjure(ctx context.Context, cjSession *ConjureSession, registrationMethod Registrar) (net.Conn, error) {

	if cjSession == nil {
		return nil, fmt.Errorf("No Session Provided")
	}

	cjSession.setV6Support(both)

	// Choose Phantom Address in Register depending on v6 support.
	registration, err := registrationMethod.Register(cjSession, ctx)
	if err != nil {
		Logger().Debugf("%v Failed to register: %v", cjSession.IDString(), err)
		return nil, err
	}

	Logger().Debugf("%v Attempting to Connect ...", cjSession.IDString())

	return registration.Connect(ctx)
	// return Connect(cjSession)
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

// Connect - Dial the Phantom IP address after registration
func Connect(ctx context.Context, reg *ConjureReg) (net.Conn, error) {
	return reg.Connect(ctx)
}

// ConjureSession - Create a session with details for registration and connection
type ConjureSession struct {
	Keys           *sharedKeys
	Width          uint
	V6Support      *V6
	UseProxyHeader bool
	SessionID      uint64
	RegDecoys      []*pb.TLSDecoySpec // pb.DecoyList
	Phantom        *net.IP
	Transport      pb.TransportType
	CovertAddress  string
	// rtt			   uint // tracked in stats

	// THIS IS REQUIRED TO INTERFACE WITH PSIPHON ANDROID
	//		we use their dialer to prevent connection loopback into our own proxy
	//		connection when tunneling the whole device.
	TcpDialer func(context.Context, string, string) (net.Conn, error)

	// performance tracking
	stats *pb.SessionStats
}

func makeConjureSession(covert string, transport pb.TransportType) *ConjureSession {

	keys, err := generateSharedKeys(getStationKey())
	if err != nil {
		return nil
	}
	//[TODO]{priority:NOW} move v6support initialization to assets so it can be tracked across dials
	cjSession := &ConjureSession{
		Keys:           keys,
		Width:          defaultRegWidth,
		V6Support:      &V6{support: true, include: both},
		UseProxyHeader: false,
		Transport:      transport,
		CovertAddress:  covert,
		SessionID:      sessionsTotal.GetAndInc(),
	}

	sharedSecretStr := make([]byte, hex.EncodedLen(len(keys.SharedSecret)))
	hex.Encode(sharedSecretStr, keys.SharedSecret)
	Logger().Debugf("%v Shared Secret  - %s", cjSession.IDString(), sharedSecretStr)

	Logger().Debugf("%v covert %s", cjSession.IDString(), covert)

	reprStr := make([]byte, hex.EncodedLen(len(keys.Representative)))
	hex.Encode(reprStr, keys.Representative)
	Logger().Debugf("%v Representative - %s", cjSession.IDString(), reprStr)

	return cjSession
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

type resultTuple struct {
	conn net.Conn
	err  error
}

// Simple type alias for brevity
type dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

func (reg *ConjureReg) connect(ctx context.Context, addr string, dialer dialFunc) (net.Conn, error) {
	//[reference] Create Context with deadline
	deadline, deadlineAlreadySet := ctx.Deadline()
	if !deadlineAlreadySet {
		//[reference] randomized timeout to Dial dark decoy address
		deadline = time.Now().Add(reg.getRandomDuration(0, 1061*2, 1953*3))
		//[TODO]{priority:@sfrolov} explain these numbers and why they were chosen for the boundaries.
	}
	childCtx, childCancelFunc := context.WithDeadline(ctx, deadline)
	defer childCancelFunc()

	//[reference] Connect to Phantom Host
	phantomAddr := net.JoinHostPort(addr, "443")

	// conn, err := reg.TcpDialer(childCtx, "tcp", phantomAddr)
	return dialer(childCtx, "tcp", phantomAddr)
}

func (reg *ConjureReg) getFirstConnection(ctx context.Context, dialer dialFunc, phantoms []*net.IP) (net.Conn, error) {
	connChannel := make(chan resultTuple, len(phantoms))
	for _, p := range phantoms {
		if p == nil {
			continue
		}
		go func(phantom *net.IP) {
			conn, err := reg.connect(ctx, phantom.String(), dialer)
			if err != nil {
				Logger().Infof("%v failed to dial phantom %v: %v", reg.sessionIDStr, phantom.String(), err)
				connChannel <- resultTuple{nil, err}
				return
			}
			Logger().Infof("%v Connected to phantom %v using transport %d", reg.sessionIDStr, phantom.String(), reg.transport)
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

	return nil, fmt.Errorf("no open connections")
}

// Connect - Use a registration (result of calling Register) to connect to a phantom
// Note: This is hacky but should work for v4, v6, or both as any nil phantom addr will
// return a dial error and be ignored.
func (reg *ConjureReg) Connect(ctx context.Context) (net.Conn, error) {
	phantoms := []*net.IP{reg.phantom4, reg.phantom6}

	//[reference] Provide chosen transport to sent bytes (or connect) if necessary
	switch reg.transport {
	case pb.TransportType_Min:
		conn, err := reg.getFirstConnection(ctx, reg.TcpDialer, phantoms)
		if err != nil {
			Logger().Infof("%v failed to form phantom connection: %v", reg.sessionIDStr, err)
			return nil, err
		}

		// Send hmac(seed, str) bytes to indicate to station (min transport)
		connectTag := conjureHMAC(reg.keys.SharedSecret, "MinTrasportHMACString")
		conn.Write(connectTag)
		return conn, nil

	case pb.TransportType_Obfs4:
		args := pt.Args{}
		args.Add("node-id", reg.keys.Obfs4Keys.NodeID.Hex())
		args.Add("public-key", reg.keys.Obfs4Keys.PublicKey.Hex())
		args.Add("iat-mode", "1")

		Logger().Infof("%v node_id = %s; public key = %s", reg.sessionIDStr, reg.keys.Obfs4Keys.NodeID.Hex(), reg.keys.Obfs4Keys.PublicKey.Hex())

		t := obfs4.Transport{}
		c, err := t.ClientFactory("")
		if err != nil {
			Logger().Infof("%v failed to create client factory: %v", reg.sessionIDStr, err)
			return nil, err
		}

		parsedArgs, err := c.ParseArgs(&args)
		if err != nil {
			Logger().Infof("%v failed to parse obfs4 args: %v", reg.sessionIDStr, err)
			return nil, err
		}

		dialer := func(dialContext context.Context, network string, address string) (net.Conn, error) {
			d := func(network, address string) (net.Conn, error) { return reg.TcpDialer(dialContext, network, address) }
			return c.Dial("tcp", address, d, parsedArgs)
		}

		conn, err := reg.getFirstConnection(ctx, dialer, phantoms)
		if err != nil {
			Logger().Infof("%v failed to form obfs4 connection: %v", reg.sessionIDStr, err)
			return nil, err
		}

		return conn, err
	case pb.TransportType_Null:
		// Dial and do nothing to the connection before returning it to the user.
		return reg.getFirstConnection(ctx, reg.TcpDialer, phantoms)
	default:
		// If transport is unrecognized use min transport.
		return nil, fmt.Errorf("unknown transport")
	}
}

// ConjureReg - Registration structure created for each individual registration within a session.
type ConjureReg struct {
	seed           []byte
	sessionIDStr   string
	phantom4       *net.IP
	phantom6       *net.IP
	useProxyHeader bool
	covertAddress  string
	phantomSNI     string
	v6Support      uint
	transport      pb.TransportType

	// THIS IS REQUIRED TO INTERFACE WITH PSIPHON ANDROID
	//		we use their dialer to prevent connection loopback into our own proxy
	//		connection when tunneling the whole device.
	TcpDialer func(context.Context, string, string) (net.Conn, error)

	stats *pb.SessionStats
	keys  *sharedKeys
	m     sync.Mutex
}

func (reg *ConjureReg) createRequest(tlsConn *tls.UConn, decoy *pb.TLSDecoySpec) ([]byte, error) {
	//[reference] generate and encrypt variable size payload
	vsp, err := reg.generateVSP()
	if err != nil {
		return nil, err
	}
	if len(vsp) > int(^uint16(0)) {
		return nil, fmt.Errorf("Variable-Size Payload exceeds %v", ^uint16(0))
	}
	encryptedVsp, err := aesGcmEncrypt(vsp, reg.keys.VspKey, reg.keys.VspIv)
	if err != nil {
		return nil, err
	}

	//[reference] generate and encrypt fixed size payload
	fsp := reg.generateFSP(uint16(len(encryptedVsp)))
	encryptedFsp, err := aesGcmEncrypt(fsp, reg.keys.FspKey, reg.keys.FspIv)
	if err != nil {
		return nil, err
	}

	var tag []byte // tag will be base-64 style encoded
	tag = append(encryptedVsp, reg.keys.Representative...)
	tag = append(tag, encryptedFsp...)

	httpRequest := generateHTTPRequestBeginning(decoy.GetHostname())
	keystreamOffset := len(httpRequest)
	keystreamSize := (len(tag)/3+1)*4 + keystreamOffset // we can't use first 2 bits of every byte
	wholeKeystream, err := tlsConn.GetOutKeystream(keystreamSize)
	if err != nil {
		return nil, err
	}
	keystreamAtTag := wholeKeystream[keystreamOffset:]
	httpRequest = append(httpRequest, reverseEncrypt(tag, keystreamAtTag)...)
	httpRequest = append(httpRequest, []byte("\r\n\r\n")...)
	return httpRequest, nil
}

// Being called in parallel -> no changes to ConjureReg allowed in this function
func (reg *ConjureReg) send(ctx context.Context, decoy *pb.TLSDecoySpec, dialer dialFunc, dialError chan error, callback func(*ConjureReg)) {

	deadline, deadlineAlreadySet := ctx.Deadline()
	if !deadlineAlreadySet {
		deadline = time.Now().Add(getRandomDuration(deadlineTCPtoDecoyMin, deadlineTCPtoDecoyMax))
	}
	childCtx, childCancelFunc := context.WithDeadline(ctx, deadline)
	defer childCancelFunc()

	//[reference] TCP to decoy
	tcpToDecoyStartTs := time.Now()

	//[Note] decoy.GetIpAddrStr() will get only v4 addr if a decoy has both
	dialConn, err := dialer(childCtx, "tcp", decoy.GetIpAddrStr())

	reg.setTCPToDecoy(durationToU32ptrMs(time.Since(tcpToDecoyStartTs)))
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "connect: network is unreachable" {
			dialError <- RegError{msg: err.Error(), code: Unreachable}
			return
		}
		dialError <- err
		return
	}

	//[reference] connection stats tracking
	rtt := rttInt(uint32(time.Since(tcpToDecoyStartTs).Milliseconds()))
	delay := getRandomDuration(1061*rtt*2, 1953*rtt*3) //[TODO]{priority:@sfrolov} why these values??
	TLSDeadline := time.Now().Add(delay)

	tlsToDecoyStartTs := time.Now()
	tlsConn, err := reg.createTLSConn(dialConn, decoy.GetIpAddrStr(), decoy.GetHostname(), TLSDeadline)
	if err != nil {
		dialConn.Close()
		msg := fmt.Sprintf("%v - %v createConn: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		dialError <- RegError{msg: msg, code: TLSError}
		return
	}
	reg.setTLSToDecoy(durationToU32ptrMs(time.Since(tlsToDecoyStartTs)))

	//[reference] Create the HTTP request for the registration
	httpRequest, err := reg.createRequest(tlsConn, decoy)
	if err != nil {
		msg := fmt.Sprintf("%v - %v createReq: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		dialError <- RegError{msg: msg, code: TLSError}
		return
	}

	//[reference] Write reg into conn
	_, err = tlsConn.Write(httpRequest)
	if err != nil {
		// // This will not get printed because it is executed in a goroutine.
		// Logger().Errorf("%v - %v Could not send Conjure registration request, error: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		tlsConn.Close()
		msg := fmt.Sprintf("%v - %v Write: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		dialError <- RegError{msg: msg, code: TLSError}
		return
	}

	dialError <- nil
	readAndClose(dialConn, time.Second*15)
	callback(reg)
}

func (reg *ConjureReg) createTLSConn(dialConn net.Conn, address string, hostname string, deadline time.Time) (*tls.UConn, error) {
	var err error
	//[reference] TLS to Decoy
	config := tls.Config{ServerName: hostname}
	if config.ServerName == "" {
		// if SNI is unset -- try IP
		config.ServerName, _, err = net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		Logger().Debugf("%v SNI was nil. Setting it to %v ", reg.sessionIDStr, config.ServerName)
	}
	//[TODO]{priority:medium} parroting Chrome 62 ClientHello -- parrot newer.
	tlsConn := tls.UClient(dialConn, &config, tls.HelloChrome_62)
	err = tlsConn.BuildHandshakeState()
	if err != nil {
		return nil, err
	}
	err = tlsConn.MarshalClientHello()
	if err != nil {
		return nil, err
	}

	tlsConn.SetDeadline(deadline)
	err = tlsConn.Handshake()
	if err != nil {
		return nil, err
	}

	return tlsConn, nil
}

func (reg *ConjureReg) setTCPToDecoy(tcprtt *uint32) {
	reg.m.Lock()
	defer reg.m.Unlock()

	if reg.stats == nil {
		reg.stats = &pb.SessionStats{}
	}
	reg.stats.TcpToDecoy = tcprtt
}

func (reg *ConjureReg) setTLSToDecoy(tlsrtt *uint32) {
	reg.m.Lock()
	defer reg.m.Unlock()

	if reg.stats == nil {
		reg.stats = &pb.SessionStats{}
	}
	reg.stats.TlsToDecoy = tlsrtt
}

func (reg *ConjureReg) getPbTransport() pb.TransportType {
	return pb.TransportType(reg.transport)
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

func (reg *ConjureReg) generateClientToStation() *pb.ClientToStation {
	var covert *string
	if len(reg.covertAddress) > 0 {
		//[TODO]{priority:medium} this isn't the correct place to deal with signaling to the station
		//transition = pb.C2S_Transition_C2S_SESSION_COVERT_INIT
		covert = &reg.covertAddress
	}

	//[reference] Generate ClientToStation protobuf
	// transition := pb.C2S_Transition_C2S_SESSION_INIT
	currentGen := Assets().GetGeneration()
	transport := reg.getPbTransport()
	initProto := &pb.ClientToStation{
		CovertAddress:       covert,
		DecoyListGeneration: &currentGen,
		V6Support:           reg.getV6Support(),
		V4Support:           reg.getV4Support(),
		Transport:           &transport,
		Flags:               reg.generateFlags(),
		// StateTransition:     &transition,

		//[TODO]{priority:medium} specify width in C2S because different width might
		// 		be useful in different regions (constant for now.)
	}

	if len(reg.phantomSNI) > 0 {
		initProto.MaskedDecoyServerName = &reg.phantomSNI
	}

	for (proto.Size(initProto)+AES_GCM_TAG_SIZE)%3 != 0 {
		initProto.Padding = append(initProto.Padding, byte(0))
	}

	return initProto
}

func (reg *ConjureReg) generateVSP() ([]byte, error) {
	//[reference] Marshal ClientToStation protobuf
	return proto.Marshal(reg.generateClientToStation())
}

func (reg *ConjureReg) generateFSP(espSize uint16) []byte {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[0:2], espSize)

	return buf
}

func (reg *ConjureReg) getV4Support() *bool {
	// for now return true and register both
	support := true
	if reg.v6Support == v6 {
		support = false
	}
	return &support
}

func (reg *ConjureReg) getV6Support() *bool {
	support := true
	if reg.v6Support == v4 {
		support = false
	}
	return &support
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

func (reg *ConjureReg) getRandomDuration(base, min, max int) time.Duration {
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

// When a registration send goroutine finishes it will call this and log
//	 	session stats and/or errors.
func (cjSession *ConjureSession) registrationCallback(reg *ConjureReg) {
	//[TODO]{priority:NOW}
	Logger().Infof("%v %v", cjSession.IDString(), reg.digestStats())
}

func (cjSession *ConjureSession) getRandomDuration(base, min, max int) time.Duration {
	addon := getRandInt(min, max) / 1000 // why this min and max???
	rtt := rttInt(cjSession.getTcpToDecoy())
	return time.Millisecond * time.Duration(base+rtt*addon)
}

func (cjSession *ConjureSession) getTcpToDecoy() uint32 {
	if cjSession != nil {
		if cjSession.stats != nil {
			return cjSession.stats.GetTcpToDecoy()
		}
	}
	return 0
}

func sleepWithContext(ctx context.Context, duration time.Duration) {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

func rttInt(millis uint32) int {
	defaultValue := 300
	if millis == 0 {
		return defaultValue
	}
	return int(millis)
}

// SelectDecoys - Get an array of `width` decoys to be used for registration
func SelectDecoys(sharedSecret []byte, version uint, width uint) ([]*pb.TLSDecoySpec, error) {

	//[reference] prune to v6 only decoys if useV6 is true
	var allDecoys []*pb.TLSDecoySpec
	switch version {
	case v6:
		allDecoys = Assets().GetV6Decoys()
	case v4:
		allDecoys = Assets().GetV4Decoys()
	case both:
		allDecoys = Assets().GetAllDecoys()
	default:
		allDecoys = Assets().GetAllDecoys()
	}

	if len(allDecoys) == 0 {
		return nil, fmt.Errorf("no decoys")
	}

	decoys := make([]*pb.TLSDecoySpec, width)
	numDecoys := big.NewInt(int64(len(allDecoys)))
	hmacInt := new(big.Int)
	idx := new(big.Int)

	//[reference] select decoys
	for i := uint(0); i < width; i++ {
		macString := fmt.Sprintf("registrationdecoy%d", i)
		hmac := conjureHMAC(sharedSecret, macString)
		hmacInt = hmacInt.SetBytes(hmac[:8])
		hmacInt.SetBytes(hmac)
		hmacInt.Abs(hmacInt)
		idx.Mod(hmacInt, numDecoys)
		decoys[i] = allDecoys[int(idx.Int64())]
	}
	return decoys, nil
}

// var phantomSubnets = []conjurePhantomSubnet{
// 	{subnet: "192.122.190.0/24", weight: 90.0},
// 	{subnet: "2001:48a8:687f:1::/64", weight: 90.0},
// 	{subnet: "141.219.0.0/16", weight: 10.0},
// 	{subnet: "35.8.0.0/16", weight: 10.0},
// }

// SelectPhantom - select one phantom IP address based on shared secret
func SelectPhantom(seed []byte, support uint) (*net.IP, *net.IP, error) {
	phantomSubnets := Assets().GetPhantomSubnets()
	switch support {
	case v4:
		phantomIPv4, err := ps.SelectPhantom(seed, phantomSubnets, ps.V4Only, true)
		if err != nil {
			return nil, nil, err
		}
		return phantomIPv4, nil, nil
	case v6:
		phantomIPv6, err := ps.SelectPhantom(seed, phantomSubnets, ps.V6Only, true)
		if err != nil {
			return nil, nil, err
		}
		return nil, phantomIPv6, nil
	case both:
		phantomIPv4, err := ps.SelectPhantom(seed, phantomSubnets, ps.V4Only, true)
		if err != nil {
			return nil, nil, err
		}
		phantomIPv6, err := ps.SelectPhantom(seed, phantomSubnets, ps.V6Only, true)
		if err != nil {
			return nil, nil, err
		}
		return phantomIPv4, phantomIPv6, nil
	default:
		return nil, nil, fmt.Errorf("unknown v4/v6 support")
	}
}

func getStationKey() [32]byte {
	return *Assets().GetConjurePubkey()
}

type Obfs4Keys struct {
	PrivateKey *ntor.PrivateKey
	PublicKey  *ntor.PublicKey
	NodeID     *ntor.NodeID
}

func generateObfs4Keys(rand io.Reader) (Obfs4Keys, error) {
	keys := Obfs4Keys{
		PrivateKey: new(ntor.PrivateKey),
		PublicKey:  new(ntor.PublicKey),
		NodeID:     new(ntor.NodeID),
	}

	_, err := rand.Read(keys.PrivateKey[:])
	if err != nil {
		return keys, err
	}

	keys.PrivateKey[0] &= 248
	keys.PrivateKey[31] &= 127
	keys.PrivateKey[31] |= 64

	pub, err := curve25519.X25519(keys.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return keys, err
	}
	copy(keys.PublicKey[:], pub)

	_, err = rand.Read(keys.NodeID[:])
	return keys, err
}

type sharedKeys struct {
	SharedSecret, Representative                               []byte
	FspKey, FspIv, VspKey, VspIv, NewMasterSecret, ConjureSeed []byte
	Obfs4Keys                                                  Obfs4Keys
}

func generateSharedKeys(pubkey [32]byte) (*sharedKeys, error) {
	sharedSecret, representative, err := generateEligatorTransformedKey(pubkey[:])
	if err != nil {
		return nil, err
	}

	tdHkdf := hkdf.New(sha256.New, sharedSecret, []byte("conjureconjureconjureconjure"), nil)
	keys := &sharedKeys{
		SharedSecret:    sharedSecret,
		Representative:  representative,
		FspKey:          make([]byte, 16),
		FspIv:           make([]byte, 12),
		VspKey:          make([]byte, 16),
		VspIv:           make([]byte, 12),
		NewMasterSecret: make([]byte, 48),
		ConjureSeed:     make([]byte, 16),
	}

	if _, err := tdHkdf.Read(keys.FspKey); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.FspIv); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.VspKey); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.VspIv); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.NewMasterSecret); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.ConjureSeed); err != nil {
		return keys, err
	}
	keys.Obfs4Keys, err = generateObfs4Keys(tdHkdf)
	return keys, err
}

//
func conjureHMAC(key []byte, str string) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write([]byte(str))
	return hash.Sum(nil)
}

// RegError - Registration Error passed during registration to indicate failure mode
type RegError struct {
	code uint
	msg  string
}

func (err RegError) Error() string {
	return fmt.Sprintf("Registration Error [%v]: %v", err.CodeStr(), err.msg)
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

const (
	// Unreachable -Dial Error Unreachable -- likely network unavailable (i.e. ipv6 error)
	Unreachable = iota

	// DialFailure - Dial Error Other than unreachable
	DialFailure

	// NotImplemented - Related Function Not Implemented
	NotImplemented

	// TLS Error (Expired, Wrong-Host, Untrusted-Root, ...)
	TLSError

	// Unknown - Error occurred without obvious explanation
	Unknown
)
