package obfs4

import (
	"bytes"
	"fmt"
	"net"

	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/obfs4/common/drbg"
	"github.com/refraction-networking/obfs4/common/ntor"
	"github.com/refraction-networking/obfs4/transports/obfs4"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	// Earliest client library version ID that supports destination port randomization
	randomizeDstPortMinVersion uint = 3

	// port range boundaries for min when randomizing
	portRangeMin = 22
	portRangeMax = 65535
)

// Transport implements the station Transport interface for the obfs4 transport
type Transport struct{}

// Name implements the station Transport interface
func (Transport) Name() string { return "obfs4" }

// LogPrefix implements the station Transport interface
func (Transport) LogPrefix() string { return "OBFS4" }

// GetIdentifier implements the station Transport interface
func (Transport) GetIdentifier(r transports.Registration) string {
	if r == nil {
		return ""
	} else if r.TransportKeys() == nil {
		keys, err := generateObfs4Keys(r.TransportReader())
		if err != nil {
			return ""
		}
		err = r.SetTransportKeys(keys)
		if err != nil {
			return ""
		}
	}
	obfs4Keys, ok := r.TransportKeys().(Obfs4Keys)
	if !ok {
		return ""
	}
	return string(obfs4Keys.PublicKey.Bytes()[:]) + string(obfs4Keys.NodeID.Bytes()[:])
}

// GetProto returns the next layer protocol that the transport uses. Implements
// the Transport interface.
func (Transport) GetProto() pb.IPProto {
	return pb.IPProto_Tcp
}

// ParseParams gives the specific transport an option to parse a generic object
// into parameters provided by the client during registration.
func (Transport) ParseParams(libVersion uint, data *anypb.Any) (any, error) {
	if data == nil {
		return nil, nil
	}

	// For backwards compatibility we create a generic transport params object
	// for transports that existed before the transportParams fields existed.
	if libVersion < randomizeDstPortMinVersion {
		f := false
		return &pb.GenericTransportParams{
			RandomizeDstPort: &f,
		}, nil
	}

	var m = &pb.GenericTransportParams{}
	err := transports.UnmarshalAnypbTo(data, m)
	return m, err
}

// ParamStrings returns an array of tag string that will be added to tunStats when a proxy
// session is closed. For now, no params of interest.
func (t Transport) ParamStrings(p any) []string {
	return nil
}

// WrapConnection implements the station Transport interface
func (Transport) WrapConnection(data *bytes.Buffer, c net.Conn, phantom net.IP, regManager transports.RegManager) (transports.Registration, net.Conn, error) {
	if data.Len() < ClientMinHandshakeLength {
		return nil, nil, transports.ErrTryAgain
	}

	var representative ntor.Representative
	copy(representative[:ntor.RepresentativeLength], data.Bytes()[:ntor.RepresentativeLength])

	for _, r := range getObfs4Registrations(regManager, phantom) {
		if r == nil {
			return nil, nil, fmt.Errorf("broken registration")
		} else if r.TransportKeys() == nil {
			keys, err := generateObfs4Keys(r.TransportReader())
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to generate obfs4 keys: %w", err)
			}
			err = r.SetTransportKeys(keys)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to set obfs4 keys: %w", err)
			}
		}
		obfs4Keys, ok := r.TransportKeys().(Obfs4Keys)
		if !ok {
			return nil, nil, fmt.Errorf("Incorrect Key Type")
		}

		mark := generateMark(obfs4Keys.NodeID, obfs4Keys.PublicKey, &representative)
		pos := findMarkMac(mark, data.Bytes(), ntor.RepresentativeLength+ClientMinPadLength, MaxHandshakeLength, true)
		if pos == -1 {
			continue
		}

		// We found the mark in the client handshake! We found our registration!
		args := pt.Args{}
		args.Add("node-id", obfs4Keys.NodeID.Hex())
		args.Add("private-key", obfs4Keys.PrivateKey.Hex())
		seed, err := drbg.NewSeed()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create DRBG seed: %w", err)
		}
		args.Add("drbg-seed", seed.Hex())

		t := &obfs4.Transport{}

		factory, err := t.ServerFactory("", &args)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create server factory: %w", err)
		}

		mc := transports.PrependToConn(c, data)
		wrapped, err := factory.WrapConn(mc)

		return r, wrapped, err
	}

	// If we read more than min handshake len, but less than max and didn't find
	// the mark get more bytes until we have reached the max handshake length.
	// If we have reached the max handshake len and didn't find it return NotTransport
	if data.Len() < MaxHandshakeLength {
		return nil, nil, transports.ErrTryAgain
	}

	// The only time we'll make it here is if there are no obfs4 registrations
	// for the given phantom.
	return nil, nil, transports.ErrNotTransport
}

// This function makes the assumption that any identifier with length 52 is an obfs4 registration.
// This may not be strictly true, but any other identifier will simply fail to form a connection and
// should be harmless.
func getObfs4Registrations(regManager transports.RegManager, darkDecoyAddr net.IP) []transports.Registration {
	var regs []transports.Registration

	for identifier, r := range regManager.GetRegistrations(darkDecoyAddr) {
		if len(identifier) == ntor.PublicKeyLength+ntor.NodeIDLength {
			regs = append(regs, r)
		}
	}

	return regs
}

// GetDstPort Given the library version, a seed, and a generic object
// containing parameters the transport should be able to return the
// destination port that a clients phantom connection will attempt to reach
func (Transport) GetDstPort(libVersion uint, seed []byte, params any) (uint16, error) {

	if libVersion < randomizeDstPortMinVersion {
		return 443, nil
	}

	if params == nil {
		return 443, nil
	}

	parameters, ok := params.(*pb.GenericTransportParams)
	if !ok {
		return 0, fmt.Errorf("bad parameters provided")
	}

	if parameters.GetRandomizeDstPort() {
		return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
	}

	return 443, nil
}

// func generateObfs4Keys(rand io.Reader) (core.Obfs4Keys, error) {
// 	keys := Obfs4Keys{
// 		PrivateKey: new(ntor.PrivateKey),
// 		PublicKey:  new(ntor.PublicKey),
// 		NodeID:     new(ntor.NodeID),
// 	}

// 	_, err := rand.Read(keys.PrivateKey[:])
// 	if err != nil {
// 		return keys, err
// 	}

// 	keys.PrivateKey[0] &= 248
// 	keys.PrivateKey[31] &= 127
// 	keys.PrivateKey[31] |= 64

// 	pub, err := curve25519.X25519(keys.PrivateKey[:], curve25519.Basepoint)
// 	if err != nil {
// 		return keys, err
// 	}
// 	copy(keys.PublicKey[:], pub)

// 	_, err = rand.Read(keys.NodeID[:])
// 	return keys, err
// }
