package requester

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/flynn/noise"
	"github.com/refraction-networking/conjure/pkg/registrars/dns-registrar/dns"
	"github.com/refraction-networking/conjure/pkg/registrars/dns-registrar/encryption"
	"github.com/refraction-networking/conjure/pkg/registrars/dns-registrar/msgformat"
	"github.com/refraction-networking/conjure/pkg/registrars/dns-registrar/queuepacketconn"
	utls "github.com/refraction-networking/utls"
)

type dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

type Requester struct {
	// transport is the underlying transport used for the dns request
	transport net.PacketConn
	// dialTransport is used for constructing the transport on the first request
	// this allows us to not dial anything until the first request, while avoid storing
	// a lot of internal state in Requester
	dialTransport func(dialer dialFunc) (net.PacketConn, error)

	// dialer is the dialer to be used for the underlying TCP/UDP transport
	dialer dialFunc

	// remote address
	remoteAddr net.Addr

	// server public key
	pubkey []byte
}

// New Requester using DoT as transport
func dialDoT(dotaddr string, utlsDistribution string, dialTransport dialFunc) (net.Conn, error) {
	utlsClientHelloID, err := sampleUTLSDistribution(utlsDistribution)
	if err != nil {
		return nil, err
	}

	var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
	if utlsClientHelloID == nil {
		dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialTransport(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return tls.Client(conn, &tls.Config{}), nil
		}
	} else {
		dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID, dialTransport)
		}
	}
	dotconn, err := NewTLSPacketConn(dotaddr, dialTLSContext)
	if err != nil {
		return nil, err
	}

	return dotconn, nil
}

// New Requester using DoH as transport
func dialDoH(dohurl string, utlsDistribution string, dialTransport dialFunc) (net.Conn, error) {
	utlsClientHelloID, err := sampleUTLSDistribution(utlsDistribution)
	if err != nil {
		return nil, err
	}

	var rt http.RoundTripper
	if utlsClientHelloID == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		// Disable DefaultTransport's default Proxy =
		// ProxyFromEnvironment setting, for conformity
		// with utlsRoundTripper and with DoT mode,
		// which do not take a proxy from the
		// environment.
		transport.DialContext = dialTransport
		transport.Proxy = nil
		rt = transport
	} else {
		rt = NewUTLSRoundTripper(nil, utlsClientHelloID, dialTransport)
	}

	dohconn, err := NewHTTPPacketConn(rt, dohurl, 32)
	if err != nil {
		return nil, err
	}

	return dohconn, nil
}

// New Requester using UDP as transport
func dialUDP(remoteAddr string, dialContext dialFunc) (net.Conn, error) {
	udpConn, err := dialContext(context.Background(), "udp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing udp connection: %v", err)
	}

	return udpConn, nil
}

func resolveAddr(config *Config) (net.Addr, error) {
	switch config.TransportMethod {
	case DoH, DoT:
		return queuepacketconn.DummyAddr{}, nil
	case UDP:
		addr, err := net.ResolveUDPAddr("udp", config.Target)
		if err != nil {
			return nil, fmt.Errorf("error resolving UDP addr: %v", err)
		}
		return addr, nil
	}

	return nil, fmt.Errorf("invalid transport type configured")
}

func NewRequester(config *Config) (*Requester, error) {
	err := validateConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error validaing config: %v", err)
	}

	baseDomain, err := dns.ParseName(config.BaseDomain)
	if err != nil {
		return nil, fmt.Errorf("error parsing domain: %v", err)
	}

	addr, err := resolveAddr(config)
	if err != nil {
		return nil, fmt.Errorf("error resolving addr from config: %v", err)
	}

	dialTransport := func(dialer dialFunc) (net.PacketConn, error) {
		switch config.TransportMethod {
		case DoT:
			conn, err := dialDoT(config.Target, config.UtlsDistribution, dialer)
			if err != nil {
				return nil, fmt.Errorf("error dialing DoT connection: %v", err)
			}

			return NewDNSPacketConn(conn, addr, baseDomain), nil
		case DoH:
			conn, err := dialDoH(config.Target, config.UtlsDistribution, dialer)
			if err != nil {
				return nil, fmt.Errorf("error dialing DoH connection: %v", err)
			}

			return NewDNSPacketConn(conn, addr, baseDomain), nil
		case UDP:
			conn, err := dialUDP(config.Target, dialer)
			if err != nil {
				return nil, fmt.Errorf("error dialing UDP connection: %v", err)
			}

			return NewDNSPacketConn(conn, addr, baseDomain), nil
		}

		return nil, fmt.Errorf("invalid transport type configured")
	}

	return &Requester{
		dialTransport: dialTransport,
		dialer:        config.dialTransport(),
		remoteAddr:    addr,
		pubkey:        config.Pubkey,
	}, nil
}

// Send the payload together with noise handshake, returns noise recvCipher for decrypting response
func (r *Requester) sendHandshake(payload []byte) (*noise.CipherState, *noise.CipherState, error) {
	config := encryption.NewConfig()
	config.Initiator = true
	config.PeerStatic = r.pubkey
	handshakeState, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, err
	}
	msgToSend, recvCipher, sendCipher, err := handshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, err
	}
	msgToSend, err = msgformat.AddRequestFormat([]byte(msgToSend))
	if err != nil {
		return nil, nil, err
	}
	_, err = r.transport.WriteTo(msgToSend, r.remoteAddr)
	if err != nil {
		return nil, nil, err
	}
	return recvCipher, sendCipher, nil
}

// SetDialer sets a custom dialer for the underlying TCP/UDP transport
func (r *Requester) SetDialer(dialer dialFunc) error {
	if dialer == nil {
		return fmt.Errorf("no dialer provided")
	}

	r.dialer = dialer
	return nil
}

func (r *Requester) RequestAndRecv(sendBytes []byte) ([]byte, error) {
	if r.transport == nil {
		transport, err := r.dialTransport(r.dialer)
		if err != nil {
			return nil, fmt.Errorf("error dialing transport: %v", err)
		}

		r.transport = transport
	}

	recvCipher, _, err := r.sendHandshake(sendBytes)
	if err != nil {
		return nil, err
	}

	var recvBuf [4096]byte
	for {
		_, recvAddr, err := r.transport.ReadFrom(recvBuf[:])
		if err != nil {
			return nil, err
		}
		if recvAddr.String() == r.remoteAddr.String() {
			break
		}
	}

	encryptedBuf, err := msgformat.RemoveResponseFormat(recvBuf[:])
	if err != nil {
		return nil, err
	}

	recvBytes, err := recvCipher.Decrypt(nil, nil, encryptedBuf)
	if err != nil {
		return nil, err
	}

	return recvBytes, nil
}

func (r *Requester) Close() error {
	return r.transport.Close()
}

// sampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func sampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = utlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}
