package tapdance

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

// Registration strategy using a centralized REST API to
// create registrations. Only the Endpoint need be specified;
// the remaining fields are valid with their zero values and
// provide the opportunity for additional control over the process.
type APIRegistrarBidirectional struct {
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

func (r APIRegistrarBidirectional) Register(cjSession *ConjureSession, ctx context.Context) (*ConjureReg, error) {
	Logger().Debugf("%v registering via APIRegistrarBidirectional", cjSession.IDString())

	// Differences from APIRegistrar Register(): Client now does not generate
	// phantom addresses, leave the phantom4 and phantom6 fields blank for now
	// [reference] Prepare registration
	reg := &ConjureReg{
		sessionIDStr: cjSession.IDString(),
		keys:         cjSession.Keys,
		stats:        &pb.SessionStats{},
		// phantom4:       phantom4,
		// phantom6:       phantom6,
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
		regResp := &pb.RegistrationResponse{}
		// executeHTTPRequestBidirectional() returns the Registration Response protobuf --> save that in regResp
		regResp, err = r.executeHTTPRequestBidirectional(ctx, cjSession, payload)
		if err != nil || regResp == nil {
			Logger().Warnf("%v failed bidirectional API registration, attempt %d/%d", cjSession.IDString(), tries, r.MaxRetries+1)
			continue
		}

		// Handle server error
		if regResp.GetError() != "" {
			Logger().Debugf("%v bidirectional API registration returned err: %s", cjSession.IDString(), regResp.GetError())
			continue
		}

		Logger().Debugf("%v bidirectional API registration succeeded", cjSession.IDString())
		if r.ConnectionDelay != 0 {
			Logger().Debugf("%v sleeping for %v", cjSession.IDString(), r.ConnectionDelay)
			sleepWithContext(ctx, r.ConnectionDelay)
		}

		// Helper function defined below that takes in the registraion response protobuf from the
		// executeHTTPRequestBidireectional() func and the ConjureReg that we want to return and
		// unpacks the returned ipv addresses into the conjureReg
		// LATER: carry more stuff in registration response protobuf and unpack helper will handle that too
		conjReg := r.unpackRegResp(reg, regResp)

		// Return conjReg (ConjureReg struct) containing the ipv4 and ipv6 addresses from the server
		return conjReg, nil
	}

	// If we make it here, we failed API registration
	Logger().Warnf("%v giving up on bidirectional API registration", cjSession.IDString())

	if r.SecondaryRegistrar != nil {
		Logger().Debugf("%v trying secondary registration method", cjSession.IDString())
		return r.SecondaryRegistrar.Register(cjSession, ctx)
	}

	return nil, err
}

func (r APIRegistrarBidirectional) executeHTTPRequestBidirectional(ctx context.Context, cjSession *ConjureSession, payload []byte) (*pb.RegistrationResponse, error) {
	// Create an instance of the ConjureReg struct to return; this will hold the updated phantom4 and phantom6 addresses received from registrar response
	regResp := &pb.RegistrationResponse{}
	// Make new HTTP request with given context, registrar, and paylaod
	req, err := http.NewRequestWithContext(ctx, "POST", r.Endpoint, bytes.NewReader(payload))
	if err != nil {
		Logger().Warnf("%v failed to create HTTP request to registration endpoint %s: %v", cjSession.IDString(), r.Endpoint, err)
		return regResp, err
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		Logger().Warnf("%v failed to do HTTP request to registration endpoint %s: %v", cjSession.IDString(), r.Endpoint, err)
		return regResp, err
	}
	defer resp.Body.Close()

	// Check that the HTTP request returned a success code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		Logger().Warnf("%v got non-success response code %d from registration endpoint %v", cjSession.IDString(), resp.StatusCode, r.Endpoint)
		return regResp, fmt.Errorf("non-success response code %d on %s", resp.StatusCode, r.Endpoint)
	}

	// Read the HTTP response body into []bytes
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		Logger().Warnf("error in serializing Registrtion Response protobuf in bytes: %v", err)
		return regResp, err
	}

	// Unmarshal response body into Registration Response protobuf
	if err = proto.Unmarshal(bodyBytes, regResp); err != nil {
		Logger().Warnf("error in storing Registrtion Response protobuf: %v", err)
		return regResp, err
	}

	return regResp, nil
}

func (r APIRegistrarBidirectional) unpackRegResp(reg *ConjureReg, regResp *pb.RegistrationResponse) *ConjureReg {
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

	// Client config -- check if not nil in the registration response
	if regResp.GetClientConf() != nil {
		currGen := Assets().GetGeneration()
		incomingGen := regResp.GetClientConf().GetGeneration()
		Logger().Debugf("received clientconf in regResponse w/ gen %d", incomingGen)
		if currGen < incomingGen {
			Logger().Debugf("Updating clientconf %d -> %d", currGen, incomingGen)
			_err := Assets().SetClientConf(regResp.GetClientConf())
			if _err != nil {
				Logger().Warnf("could not set ClientConf in bidirectional API: %v", _err.Error())
			}
		}
	}

	return reg
}
