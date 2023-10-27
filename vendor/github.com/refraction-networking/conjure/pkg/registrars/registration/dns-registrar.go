package registration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/pion/stun"
	"github.com/refraction-networking/conjure/pkg/registrars/dns-registrar/requester"
	"github.com/refraction-networking/conjure/pkg/registrars/lib"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/gotapdance/tapdance"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type DNSRegistrar struct {
	req             *requester.Requester
	maxRetries      int
	connectionDelay time.Duration
	bidirectional   bool
	ip              []byte
	logger          logrus.FieldLogger
}

func createRequester(config *Config) (*requester.Requester, error) {
	switch config.DNSTransportMethod {
	case UDP:
		return requester.NewRequester(&requester.Config{
			TransportMethod: requester.UDP,
			Target:          config.Target,
			BaseDomain:      config.BaseDomain,
			Pubkey:          config.Pubkey,
		})
	case DoT:
		return requester.NewRequester(&requester.Config{
			TransportMethod:  requester.DoT,
			UtlsDistribution: config.UTLSDistribution,
			Target:           config.Target,
			BaseDomain:       config.BaseDomain,
			Pubkey:           config.Pubkey,
		})
	case DoH:
		return requester.NewRequester(&requester.Config{
			TransportMethod:  requester.DoH,
			UtlsDistribution: config.UTLSDistribution,
			Target:           config.Target,
			BaseDomain:       config.BaseDomain,
			Pubkey:           config.Pubkey,
		})
	}

	return nil, fmt.Errorf("invalid DNS transport method")
}

// NewDNSRegistrar creates a DNSRegistrar from config
func NewDNSRegistrar(config *Config) (*DNSRegistrar, error) {
	req, err := createRequester(config)
	if err != nil {
		return nil, fmt.Errorf("error creating requester: %v", err)
	}

	ip, err := getPublicIp(config.STUNAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get public IP: %v", err)
	}

	return &DNSRegistrar{
		req:             req,
		ip:              ip,
		maxRetries:      config.MaxRetries,
		bidirectional:   config.Bidirectional,
		connectionDelay: config.Delay,
		logger:          tapdance.Logger().WithField("registrar", "DNS"),
	}, nil
}

// registerUnidirectional sends unidirectional registration data to the registration server
func (r *DNSRegistrar) registerUnidirectional(ctx context.Context, cjSession *tapdance.ConjureSession) (*tapdance.ConjureReg, error) {
	logger := r.logger.WithFields(logrus.Fields{"type": "unidirectional", "sessionID": cjSession.IDString()})

	reg, protoPayload, err := cjSession.UnidirectionalRegData(ctx, pb.RegistrationSource_DNS.Enum())
	if err != nil {
		logger.Errorf("Failed to prepare registration data: %v", err)
		return nil, lib.ErrRegFailed
	}

	if reg.Dialer != nil {
		err := r.req.SetDialer(reg.Dialer)
		if err != nil {
			return nil, fmt.Errorf("failed to set dialer to requester: %v", err)
		}
	}

	protoPayload.RegistrationAddress = r.ip

	payload, err := proto.Marshal(protoPayload)
	if err != nil {
		logger.Errorf("failed to marshal ClientToStation payload: %v", err)
		return nil, lib.ErrRegFailed
	}

	logger.Debugf("DNS payload length: %d", len(payload))

	for i := 0; i < r.maxRetries+1; i++ {
		logger := logger.WithField("attempt", strconv.Itoa(i+1)+"/"+strconv.Itoa(r.maxRetries))
		_, err := r.req.RequestAndRecv(payload)
		if err != nil {
			logger.Warnf("error in registration attempt: %v", err)
			continue
		}

		// for unidirectional registration, do not check for response and immediatly return
		logger.Debugf("registration succeeded")
		return reg, nil
	}

	logger.WithField("maxTries", r.maxRetries).Warnf("all registration attempt(s) failed")

	return nil, lib.ErrRegFailed

}

// registerBidirectional sends bidirectional registration data to the registration server and reads the response
func (r *DNSRegistrar) registerBidirectional(ctx context.Context, cjSession *tapdance.ConjureSession) (*tapdance.ConjureReg, error) {
	logger := r.logger.WithFields(logrus.Fields{"type": "bidirectional", "sessionID": cjSession.IDString()})

	reg, protoPayload, err := cjSession.BidirectionalRegData(ctx, pb.RegistrationSource_BidirectionalDNS.Enum())
	if err != nil {
		logger.Errorf("Failed to prepare registration data: %v", err)
		return nil, lib.ErrRegFailed
	}

	if reg.Dialer != nil {
		err := r.req.SetDialer(reg.Dialer)
		if err != nil {
			return nil, fmt.Errorf("failed to set dialer to requester: %v", err)
		}
	}

	protoPayload.RegistrationAddress = r.ip

	payload, err := proto.Marshal(protoPayload)
	if err != nil {
		logger.Errorf("failed to marshal ClientToStation payload: %v", err)
		return nil, lib.ErrRegFailed
	}

	logger.Debugf("DNS payload length: %d", len(payload))

	for i := 0; i < r.maxRetries+1; i++ {
		logger := logger.WithField("attempt", strconv.Itoa(i+1)+"/"+strconv.Itoa(r.maxRetries))

		bdResponse, err := r.req.RequestAndRecv(payload)
		if err != nil {
			logger.Warnf("error in sending request to DNS registrar: %v", err)
			continue
		}

		dnsResp := &pb.DnsResponse{}
		err = proto.Unmarshal(bdResponse, dnsResp)
		if err != nil {
			logger.Warnf("error in storing Registrtion Response protobuf: %v", err)
			continue
		}
		if !dnsResp.GetSuccess() {
			logger.Warnf("registrar indicates that registration failed")
			continue
		}
		if dnsResp.GetClientconfOutdated() {
			logger.Warnf("registrar indicates that ClinetConf is outdated")
		}

		err = reg.UnpackRegResp(dnsResp.GetBidirectionalResponse())
		if err != nil {
			logger.Warnf("failed to unpack registration response: %v", err)
			continue
		}
		return reg, nil
	}

	logger.WithField("maxTries", r.maxRetries).Warnf("all registration attemps failed")

	return nil, lib.ErrRegFailed
}

// Register prepares and sends the registration request.
func (r *DNSRegistrar) Register(cjSession *tapdance.ConjureSession, ctx context.Context) (*tapdance.ConjureReg, error) {
	defer lib.SleepWithContext(ctx, r.connectionDelay)

	if r.bidirectional {
		return r.registerBidirectional(ctx, cjSession)
	}
	return r.registerUnidirectional(ctx, cjSession)
}

func getPublicIp(server string) ([]byte, error) {

	c, err := stun.Dial("udp4", server)
	if err != nil {
		return nil, errors.New("Failed to connect to STUN server: " + err.Error())
	}

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	ip := net.IP{}

	err = c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			err = res.Error
			return
		}

		var xorAddr stun.XORMappedAddress
		err = xorAddr.GetFrom(res.Message)
		if err != nil {
			return
		}

		ip = xorAddr.IP
	})

	if err != nil {
		err = errors.New("Failed to get IP address from STUN: " + err.Error())
	}

	return ip.To4(), nil
}

// PrepareRegKeys prepares key materials specific to the registrar
func (r *DNSRegistrar) PrepareRegKeys(stationPubkey [32]byte, sessionSecret []byte) error {

	return nil
}
