package registration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/refraction-networking/conjure/pkg/registrars/lib"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/gotapdance/tapdance"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// APIRegistrar implements a registration strategy using a centralized REST API to create
// registrations. Only the Endpoint need be specified; the remaining fields are valid with their
// zero values and provide the opportunity for additional control over the process.
type APIRegistrar struct {
	// endpoint to use in registration request
	endpoint string

	// HTTP client to use in request
	client *http.Client

	// Wether registrations should be bidirectional
	bidirectional bool

	// Length of time to delay after confirming successful
	// registration before attempting a connection,
	// allowing for propagation throughout the stations.
	connectionDelay time.Duration

	// Maximum number of retries before giving up
	maxRetries int

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
	secondaryRegistrar tapdance.Registrar

	// Logger to use.
	logger logrus.FieldLogger
}

func NewAPIRegistrar(config *Config) (*APIRegistrar, error) {
	return &APIRegistrar{
		endpoint:           config.Target,
		bidirectional:      config.Bidirectional,
		connectionDelay:    config.Delay,
		maxRetries:         config.MaxRetries,
		secondaryRegistrar: config.SecondaryRegistrar,
		client:             config.HTTPClient,
		logger:             tapdance.Logger().WithField("registrar", "API"),
	}, nil
}

// PrepareRegKeys prepares key materials specific to the registrar
func (r *APIRegistrar) PrepareRegKeys(stationPubkey [32]byte, sessionSecret []byte) error {

	return nil
}

// registerUnidirectional sends unidirectional registration data to the registration server
func (r *APIRegistrar) registerUnidirectional(cjSession *tapdance.ConjureSession, ctx context.Context) (*tapdance.ConjureReg, error) {
	logger := r.logger.WithFields(logrus.Fields{"type": "unidirectional", "sessionID": cjSession.IDString()})

	reg, protoPayload, err := cjSession.UnidirectionalRegData(ctx, pb.RegistrationSource_API.Enum())
	if err != nil {
		logger.Errorf("Failed to prepare registration data: %v", err)
		return nil, lib.ErrRegFailed
	}

	payload, err := proto.Marshal(protoPayload)
	if err != nil {
		logger.Errorf("failed to marshal ClientToStation payload: %v", err)
		return nil, lib.ErrRegFailed
	}

	r.setHTTPClient(reg)

	for tries := 0; tries < r.maxRetries+1; tries++ {
		logger := logger.WithField("attempt", strconv.Itoa(tries+1)+"/"+strconv.Itoa(r.maxRetries+1))
		err = r.executeHTTPRequest(ctx, payload, logger)
		if err != nil {
			logger.Warnf("error in registration attempt: %v", err)
			continue
		}
		logger.Debugf("registration succeeded")
		return reg, nil
	}

	// If we make it here, we failed API registration
	logger.WithField("attempts", r.maxRetries+1).Warnf("all registration attempt(s) failed")

	if r.secondaryRegistrar != nil {
		logger.Debugf("trying secondary registration method")
		return r.secondaryRegistrar.Register(cjSession, ctx)
	}

	return nil, lib.ErrRegFailed
}

// registerBidirectional sends bidirectional registration data to the registration server and reads the response
func (r *APIRegistrar) registerBidirectional(cjSession *tapdance.ConjureSession, ctx context.Context) (*tapdance.ConjureReg, error) {
	logger := r.logger.WithFields(logrus.Fields{"type": "bidirectional", "sessionID": cjSession.IDString()})

	reg, protoPayload, err := cjSession.BidirectionalRegData(ctx, pb.RegistrationSource_BidirectionalAPI.Enum())
	if err != nil {
		logger.Errorf("Failed to prepare registration data: %v", err)
		return nil, lib.ErrRegFailed
	}

	payload, err := proto.Marshal(protoPayload)
	if err != nil {
		logger.Errorf("failed to marshal ClientToStation payload: %v", err)
		return nil, lib.ErrRegFailed
	}

	r.setHTTPClient(reg)

	for tries := 0; tries < r.maxRetries+1; tries++ {
		logger := logger.WithField("attempt", strconv.Itoa(tries+1)+"/"+strconv.Itoa(r.maxRetries+1))

		regResp, err := r.executeHTTPRequestBidirectional(ctx, payload, logger)
		if err != nil {
			logger.Warnf("error in registration attempt: %v", err)
			continue
		}

		err = reg.UnpackRegResp(regResp)
		if err != nil {
			return nil, err
		}

		return reg, nil
	}

	// If we make it here, we failed API registration
	logger.WithField("attempts", r.maxRetries+1).Warnf("all registration attempt(s) failed")

	if r.secondaryRegistrar != nil {
		logger.Debugf("trying secondary registration method")
		return r.secondaryRegistrar.Register(cjSession, ctx)
	}

	return nil, lib.ErrRegFailed
}

func (r *APIRegistrar) setHTTPClient(reg *tapdance.ConjureReg) {
	if r.client == nil {
		// Transports should ideally be re-used for TCP connection pooling,
		// but each registration is most likely making precisely one request,
		// or if it's making more than one, is most likely due to an underlying
		// connection issue rather than an application-level error anyways.
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.DialContext = reg.Dialer
		r.client = &http.Client{Transport: t}
	}
}

func (r APIRegistrar) Register(cjSession *tapdance.ConjureSession, ctx context.Context) (*tapdance.ConjureReg, error) {
	defer lib.SleepWithContext(ctx, r.connectionDelay)
	if r.bidirectional {
		return r.registerBidirectional(cjSession, ctx)
	}

	return r.registerUnidirectional(cjSession, ctx)

}

func (r APIRegistrar) executeHTTPRequest(ctx context.Context, payload []byte, logger logrus.FieldLogger) error {
	req, err := http.NewRequestWithContext(ctx, "POST", r.endpoint, bytes.NewReader(payload))
	if err != nil {
		logger.Warnf("failed to create HTTP request to registration endpoint %s: %v", r.endpoint, err)
		return err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		logger.Warnf("failed to do HTTP request to registration endpoint %s: %v", r.endpoint, err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// logger.Warnf("got non-success response code %d from registration endpoint %v", resp.StatusCode, r.endpoint)
		return fmt.Errorf("non-success response code %d on %s", resp.StatusCode, r.endpoint)
	}

	return nil
}

func (r APIRegistrar) executeHTTPRequestBidirectional(ctx context.Context, payload []byte, logger logrus.FieldLogger) (*pb.RegistrationResponse, error) {
	// Create an instance of the ConjureReg struct to return; this will hold the updated phantom4 and phantom6 addresses received from registrar response
	regResp := &pb.RegistrationResponse{}
	// Make new HTTP request with given context, registrar, and paylaod
	req, err := http.NewRequestWithContext(ctx, "POST", r.endpoint, bytes.NewReader(payload))
	if err != nil {
		logger.Warnf("%v failed to create HTTP request to registration endpoint %s: %v", r.endpoint, err)
		return regResp, err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		logger.Warnf("%v failed to do HTTP request to registration endpoint %s: %v", r.endpoint, err)
		return regResp, err
	}
	defer resp.Body.Close()

	// Check that the HTTP request returned a success code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// logger.Warnf("got non-success response code %d from registration endpoint %v", resp.StatusCode, r.endpoint)
		return regResp, fmt.Errorf("non-success response code %d on %s", resp.StatusCode, r.endpoint)
	}

	// Read the HTTP response body into []bytes
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Warnf("error in serializing Registration Response protobuf in bytes: %v", err)
		return regResp, err
	}

	// Unmarshal response body into Registration Response protobuf
	if err = proto.Unmarshal(bodyBytes, regResp); err != nil {
		logger.Warnf("error in storing Registration Response protobuf: %v", err)
		return regResp, err
	}

	return regResp, nil
}
