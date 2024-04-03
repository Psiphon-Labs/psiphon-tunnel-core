package decoy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/refraction-networking/conjure/pkg/client/assets"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/registrars/lib"
	pb "github.com/refraction-networking/conjure/proto"
	tls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"

	// td imports assets, RegError, generateHTTPRequestBeginning
	td "github.com/refraction-networking/gotapdance/tapdance"

	"github.com/sirupsen/logrus"
)

// deadline to establish TCP connection to decoy - magic numbers chosen arbitrarily to prevent
// distribution from aligning directly with second boundaries. These are intentionally short as TCP
// establishment is one round trip and we do not want to block our dial any longer than we
// absolutely have to to ensure that at least one TCP connection to a decoy could be established.
const deadlineTCPtoDecoyMin = 1931
const deadlineTCPtoDecoyMax = 4013

// Fixed-Size-Payload has a 1 byte flags field.
// bit 0 (1 << 7) determines if flow is bidirectional(0) or upload-only(1)
// bit 1 (1 << 6) enables dark-decoys
// bits 2-5 are unassigned
// bit 6 determines whether PROXY-protocol-formatted string will be sent
// bit 7 (1 << 0) signals to use TypeLen outer proto
var (
	tdFlagUploadOnly = uint8(1 << 7)
	// tdFlagDarkDecoy   = uint8(1 << 6)
	tdFlagProxyHeader = uint8(1 << 1)
	tdFlagUseTIL      = uint8(1 << 0)
)

var default_flags = tdFlagUseTIL

type DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

type DecoyRegistrar struct {

	// dialContext is a custom dialer to use when establishing TCP connections
	// to decoys. When nil, Dialer.dialContex will be used.
	dialContext DialFunc

	logger logrus.FieldLogger

	// Only used for testing. Always false otherwise.
	insecureSkipVerify bool

	// Fields taken from ConjureReg struct
	m       sync.Mutex
	stats   *pb.SessionStats
	onceTCP sync.Once
	onceTLS sync.Once

	// add Width, sharedKeys necessary stuff (2nd line in struct except ConjureSeed)
	// Keys
	fspKey, fspIv, vspKey, vspIv []byte

	Width uint

	ClientHelloID tls.ClientHelloID
}

func NewDecoyRegistrar() *DecoyRegistrar {
	return &DecoyRegistrar{
		logger:        td.Logger(),
		ClientHelloID: tls.HelloChrome_62,
		Width:         5,
	}
}

// NewDecoyRegistrarWithDialer returns a decoy registrar with custom dialer.
//
// Deprecated: Set dialer in tapdace.Dialer.DialerWithLaddr instead.
func NewDecoyRegistrarWithDialer(dialer DialFunc) *DecoyRegistrar {
	return &DecoyRegistrar{
		dialContext:   dialer,
		logger:        td.Logger(),
		ClientHelloID: tls.HelloChrome_62,
		Width:         5,
	}
}

// setTCPToDecoy takes in a value for the measured RTT, if the value is greater
// than 1.5 seconds (1500 ms) then that value will be used to limit the RTT
// used in future delay calculations.
func (r *DecoyRegistrar) setTCPToDecoy(tcprtt *uint32) {
	r.m.Lock()
	defer r.m.Unlock()

	if r.stats == nil {
		r.stats = &pb.SessionStats{}
	}

	var maxRTT uint32 = 1500

	if *tcprtt > maxRTT {
		tcprtt = &maxRTT
	}

	r.stats.TcpToDecoy = tcprtt
}

func (r *DecoyRegistrar) setTLSToDecoy(tlsrtt *uint32) {
	r.m.Lock()
	defer r.m.Unlock()

	var maxRTT uint32 = 1500

	if r.stats == nil {
		r.stats = &pb.SessionStats{}
	}

	if *tlsrtt > maxRTT {
		tlsrtt = &maxRTT
	}

	r.stats.TlsToDecoy = tlsrtt
}

var conjureGeneralHkdfSalt = []byte("conjureconjureconjureconjure")

// PrepareRegKeys prepares key materials specific to the registrar
func (r *DecoyRegistrar) PrepareRegKeys(stationPubkey [32]byte, sessionSecret []byte) error {

	reader := hkdf.New(sha256.New, sessionSecret, conjureGeneralHkdfSalt, nil)

	r.fspKey = make([]byte, 16)
	r.fspIv = make([]byte, 12)
	r.vspKey = make([]byte, 16)
	r.vspIv = make([]byte, 12)

	if _, err := reader.Read(r.fspKey); err != nil {
		return err
	}
	if _, err := reader.Read(r.fspIv); err != nil {
		return err
	}
	if _, err := reader.Read(r.vspKey); err != nil {
		return err
	}
	if _, err := reader.Read(r.vspIv); err != nil {
		return err
	}

	return nil
}

// getRandomDurationByRTT returns a random duration between min and max in milliseconds adding base.
func (r *DecoyRegistrar) getRandomDurationByRTT(base, min, max int) time.Duration {
	addon := getRandInt(min, max) / 1000 // why this min and max???
	rtt := rttInt(r.getTcpToDecoy())
	return time.Millisecond * time.Duration(base+rtt*addon)
}

func (r *DecoyRegistrar) getTcpToDecoy() uint32 {
	if r == nil {
		return 0
	}
	r.m.Lock()
	defer r.m.Unlock()
	if r.stats != nil {
		return r.stats.GetTcpToDecoy()
	}
	return 0
}

func (r *DecoyRegistrar) createTLSConn(dialConn net.Conn, address string, hostname string, deadline time.Time) (*tls.UConn, error) {
	var err error
	//[reference] TLS to Decoy
	config := tls.Config{ServerName: hostname, InsecureSkipVerify: r.insecureSkipVerify}
	if config.ServerName == "" {
		// if SNI is unset -- try IP
		config.ServerName, _, err = net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		// Logger().Debugf("%v SNI was nil. Setting it to %v ", r.sessionIDStr, config.ServerName)
	}
	//[TODO]{priority:medium} parroting Chrome 62 ClientHello -- parrot newer.
	tlsConn := tls.UClient(dialConn, &config, r.ClientHelloID)

	err = tlsConn.BuildHandshakeState()
	if err != nil {
		return nil, err
	}
	err = tlsConn.MarshalClientHello()
	if err != nil {
		return nil, err
	}

	err = tlsConn.SetDeadline(deadline)
	if err != nil {
		return nil, err
	}

	err = tlsConn.Handshake()
	if err != nil {
		return nil, err
	}

	return tlsConn, nil
}

func (r *DecoyRegistrar) createRequest(tlsConn *tls.UConn, decoy *pb.TLSDecoySpec, cjSession *td.ConjureSession) ([]byte, error) {
	//[reference] generate and encrypt variable size payload
	vsp, err := generateVSP(cjSession)
	if err != nil {
		return nil, err
	}
	if len(vsp) > int(^uint16(0)) {
		return nil, fmt.Errorf("Variable-Size Payload exceeds %v", ^uint16(0))
	}
	encryptedVsp, err := aesGcmEncrypt(vsp, r.vspKey, r.vspIv)
	if err != nil {
		return nil, err
	}

	//[reference] generate and encrypt fixed size payload
	fsp := generateFSP(uint16(len(encryptedVsp)))
	encryptedFsp, err := aesGcmEncrypt(fsp, r.fspKey, r.fspIv)
	if err != nil {
		return nil, err
	}

	var tag []byte // tag will be base-64 style encoded
	tag = append(encryptedVsp, cjSession.Keys.Representative...)
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

// Register initiates the decoy registrar to connect and send the multiple registration requests
// to the various decoys.
func (r *DecoyRegistrar) Register(cjSession *td.ConjureSession, ctx context.Context) (*td.ConjureReg, error) {
	logger := r.logger.WithFields(logrus.Fields{"type": "unidirectional", "sessionID": cjSession.IDString()})

	logger.Debugf("Registering V4 and V6 via DecoyRegistrar")

	reg, _, err := cjSession.UnidirectionalRegData(ctx, pb.RegistrationSource_Detector.Enum())
	if err != nil {
		logger.Errorf("Failed to prepare registration data: %v", err)
		return nil, lib.ErrRegFailed
	}

	// Choose N (width) decoys from decoylist
	decoys, err := selectDecoys(cjSession.Keys.SharedSecret, cjSession.V6Support.Include(), r.Width)
	if err != nil {
		logger.Warnf("failed to select decoys: %v", err)
		return nil, err
	}

	if r.dialContext != nil {
		reg.Dialer = r.dialContext
	}

	// //[TODO]{priority:later} How to pass context to multiple registration goroutines?
	if ctx == nil {
		ctx = context.Background()
	}

	width := uint(len(decoys))
	if width < r.Width {
		logger.Warnf("Using width %v (default %v)", width, r.Width)
	}

	//[reference] Send registrations to each decoy
	dialErrors := make(chan error, width)
	for _, decoy := range decoys {
		logger.Debugf("\tSending Reg: %v, %v", decoy.GetHostname(), decoy.GetIpAddrStr())
		//decoyAddr := decoy.GetIpAddrStr()
		go r.Send(ctx, cjSession, decoy, dialErrors)
	}

	//[reference] Dial errors happen immediately so block until all N dials complete
	var unreachableCount uint = 0
	for err := range dialErrors {
		if err != nil {
			logger.Debugf("%v", err)
			if dialErr, ok := err.(td.RegError); ok && dialErr.Code() == td.Unreachable {
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
		logger.Debugf("NETWORK UNREACHABLE")
		return nil, td.NewRegError(td.Unreachable, "All decoys failed to register -- Dial Unreachable")
	}

	// randomized sleeping here to break the intraflow signal
	toSleep := r.getRandomDurationByRTT(3000, 212, 3449)
	logger.Debugf("Successfully sent registrations, sleeping for: %v", toSleep)
	lib.SleepWithContext(ctx, toSleep)

	return reg, nil
}

func (r *DecoyRegistrar) Send(ctx context.Context, cjSession *td.ConjureSession, decoy *pb.TLSDecoySpec, dialError chan error) {

	deadline, deadlineAlreadySet := ctx.Deadline()
	if !deadlineAlreadySet {
		deadline = time.Now().Add(getRandomDuration(deadlineTCPtoDecoyMin, deadlineTCPtoDecoyMax))
	}
	childCtx, childCancelFunc := context.WithDeadline(ctx, deadline)
	defer childCancelFunc()

	//[reference] TCP to decoy
	tcpToDecoyStartTs := time.Now()

	//[Note] decoy.GetIpAddrStr() will get only v4 addr if a decoy has both
	dialConn, err := cjSession.Dialer(childCtx, "tcp", "", decoy.GetIpAddrStr())

	setTCPRtt := func() {
		r.setTCPToDecoy(durationToU32ptrMs(time.Since(tcpToDecoyStartTs)))
	}
	r.onceTCP.Do(setTCPRtt)
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "connect: network is unreachable" {
			dialError <- td.NewRegError(td.Unreachable, err.Error())
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
	tlsConn, err := r.createTLSConn(dialConn, decoy.GetIpAddrStr(), decoy.GetHostname(), TLSDeadline)
	if err != nil {
		dialConn.Close()
		msg := fmt.Sprintf("%v - %v createConn: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		dialError <- td.NewRegError(td.TLSError, msg)
		return
	}

	setTLSRtt := func() {
		r.setTLSToDecoy(durationToU32ptrMs(time.Since(tlsToDecoyStartTs)))
	}
	r.onceTLS.Do(setTLSRtt)

	//[reference] Create the HTTP request for the registration
	httpRequest, err := r.createRequest(tlsConn, decoy, cjSession)
	if err != nil {
		msg := fmt.Sprintf("%v - %v createReq: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		dialError <- td.NewRegError(td.TLSError, msg)
		return
	}

	//[reference] Write reg into conn
	_, err = tlsConn.Write(httpRequest)
	if err != nil {
		// This will not get printed because it is executed in a goroutine.
		// Logger().Errorf("%v - %v Could not send Conjure registration request, error: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		tlsConn.Close()
		msg := fmt.Sprintf("%v - %v Write: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		dialError <- td.NewRegError(td.TLSError, msg)
		return
	}

	dialError <- nil
	readAndClose(dialConn, time.Second*15)
}

const (
	v4 uint = iota
	v6
	both
)

// SelectDecoys - Get an array of `width` decoys to be used for registration
func selectDecoys(sharedSecret []byte, version uint, width uint) ([]*pb.TLSDecoySpec, error) {

	//[reference] prune to v6 only decoys if useV6 is true
	var allDecoys []*pb.TLSDecoySpec
	switch version {
	case v6:
		allDecoys = assets.Assets().GetV6Decoys()
	case v4:
		allDecoys = assets.Assets().GetV4Decoys()
	case both:
		allDecoys = assets.Assets().GetAllDecoys()
	default:
		allDecoys = assets.Assets().GetAllDecoys()
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
		hmac := core.ConjureHMAC(sharedSecret, macString)
		hmacInt = hmacInt.SetBytes(hmac[:8])
		hmacInt.SetBytes(hmac)
		hmacInt.Abs(hmacInt)
		idx.Mod(hmacInt, numDecoys)
		decoys[i] = allDecoys[int(idx.Int64())]
	}
	return decoys, nil
}
