/*
 * Copyright (c) 2019, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package protocol

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	utls "github.com/Psiphon-Labs/utls"
)

// CustomTLSProfile specifies custom TLS profile. This is used to deploy
// custom ClientHellos as tactics data.
type CustomTLSProfile struct {
	Name     string
	UTLSSpec *UTLSSpec
}

type CustomTLSProfiles []*CustomTLSProfile

// Redefined uTLS extensions.
// uTLS added Unmarshaler interface to it's TLS extensions, which is not compatible
// with currently deployed tactics. We redefine the types to maintain
// compatibility. This may change in the future.
type NPNExtensionCompat utls.NPNExtension
type SNIExtensionCompat utls.SNIExtension
type StatusRequestExtensionCompat utls.StatusRequestExtension
type SupportedCurvesExtensionCompat utls.SupportedCurvesExtension
type SupportedPointsExtensionCompat utls.SupportedPointsExtension
type SignatureAlgorithmsExtensionCompat utls.SignatureAlgorithmsExtension
type RenegotiationInfoExtensionCompat utls.RenegotiationInfoExtension
type ALPNExtensionCompat utls.ALPNExtension
type SCTExtensionCompat utls.SCTExtension
type SessionTicketExtensionCompat utls.SessionTicketExtension
type GenericExtensionCompat utls.GenericExtension
type UtlsExtendedMasterSecretExtensionCompat utls.UtlsExtendedMasterSecretExtension
type UtlsGREASEExtensionCompat utls.UtlsGREASEExtension
type UtlsPaddingExtensionCompat utls.UtlsPaddingExtension
type PSKKeyExchangeModesExtensionCompat utls.PSKKeyExchangeModesExtension
type SupportedVersionsExtensionCompat utls.SupportedVersionsExtension
type FakeChannelIDExtensionCompat utls.FakeChannelIDExtension
type UtlsCompressCertExtensionCompat utls.UtlsCompressCertExtension
type FakeRecordSizeLimitExtensionCompat utls.FakeRecordSizeLimitExtension
type ApplicationSettingsExtensionCompat utls.ApplicationSettingsExtension
type DelegatedCredentialsExtensionCompat utls.DelegatedCredentialsExtension
type KeyShareExtensionCompat struct {
	KeyShares []struct {
		Group utls.CurveID
		Data  []byte
	}
}

// Validate checks that the profiles in CustomTLSProfiles are initialized and
// have no name conflicts.
func (profiles CustomTLSProfiles) Validate() error {
	names := make(map[string]bool)
	for _, p := range profiles {
		if p.Name == "" {
			return errors.Tracef("custom TLS profile missing name: %s", p.Name)
		}
		if p.UTLSSpec == nil {
			return errors.Tracef("custom TLS profile missing utls spec: %s", p.Name)
		}
		if common.Contains(SupportedTLSProfiles, p.Name) ||
			common.Contains(legacyTLSProfiles, p.Name) {
			return errors.Tracef("invalid custom TLS profile name: %s", p.Name)
		}
		if _, ok := names[p.Name]; ok {
			return errors.Tracef("duplicate custom TLS profile name: %s", p.Name)
		}
		names[p.Name] = true
	}
	return nil
}

// GetClientHelloSpec creates a new utls.ClientHelloSpec from the ClientHello
// definition in UTLSpec.
//
// A new utls.ClientHelloSpec, with no shared data, is created for each call,
// as per:
// https://github.com/refraction-networking/utls/blob/4da67951864128358459681399dd208c49d5d001/u_parrots.go#L483
func (profile *CustomTLSProfile) GetClientHelloSpec() (*utls.ClientHelloSpec, error) {

	spec := &utls.ClientHelloSpec{}

	spec.TLSVersMin = profile.UTLSSpec.TLSVersMin
	spec.TLSVersMax = profile.UTLSSpec.TLSVersMax
	spec.CipherSuites = append([]uint16(nil), profile.UTLSSpec.CipherSuites...)
	spec.CompressionMethods = append([]uint8(nil), profile.UTLSSpec.CompressionMethods...)

	spec.Extensions = make([]utls.TLSExtension, len(profile.UTLSSpec.Extensions))
	for i, extension := range profile.UTLSSpec.Extensions {
		var err error
		spec.Extensions[i], err = extension.GetUTLSExtension()
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if profile.UTLSSpec.GetSessionID == "SHA-256" {
		spec.GetSessionID = sha256.Sum256
	}

	return spec, nil
}

// UTLSSpec is a parallel data structure mirroring utls.ClientHelloSpec. Note
// that utls.ClientHelloSpec cannot be directly marshaled with encoding/json
// nor encoding/gob due to various type restrictions which
// utls.ClientHelloSpec does not meet. Nor can we simply transmit a static,
// raw ClientHello since concrete utls extension types must be instantiated in
// order for related functionality to be enabled.

// UTLSSpec specifies a utls.ClientHelloSpec.
type UTLSSpec struct {
	TLSVersMin         uint16
	TLSVersMax         uint16
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []*UTLSExtension
	GetSessionID       string
}

// UTLSExtension specifies one of the several utls.TLSExtension concrete
// implementations.
type UTLSExtension struct {
	Name string
	Data json.RawMessage
}

// GetUTLSExtension instantiates the specified utls.TLSExtension concrete
// implementation.
func (e *UTLSExtension) GetUTLSExtension() (utls.TLSExtension, error) {
	switch e.Name {
	case "NPN":
		var compat NPNExtensionCompat
		err := json.Unmarshal(e.Data, &compat)
		if err != nil {
			return nil, errors.Trace(err)
		}
		extension := utls.NPNExtension(compat)
		return &extension, nil
	case "SNI":
		return &utls.SNIExtension{}, nil
	case "StatusRequest":
		return &utls.StatusRequestExtension{}, nil
	case "SupportedCurves":
		var compat SupportedCurvesExtensionCompat
		err := json.Unmarshal(e.Data, &compat)
		if err != nil {
			return nil, errors.Trace(err)
		}
		extension := utls.SupportedCurvesExtension(compat)
		return &extension, nil
	case "SupportedPoints":
		var compat SupportedPointsExtensionCompat
		err := json.Unmarshal(e.Data, &compat)
		if err != nil {
			return nil, errors.Trace(err)
		}
		extension := utls.SupportedPointsExtension(compat)
		return &extension, nil
	case "SignatureAlgorithms":
		var compat SignatureAlgorithmsExtensionCompat
		err := json.Unmarshal(e.Data, &compat)
		if err != nil {
			return nil, errors.Trace(err)
		}
		extension := utls.SignatureAlgorithmsExtension(compat)
		return &extension, nil
	case "RenegotiationInfo":
		var compat RenegotiationInfoExtensionCompat
		err := json.Unmarshal(e.Data, &compat)
		if err != nil {
			return nil, errors.Trace(err)
		}
		extension := utls.RenegotiationInfoExtension(compat)
		return &extension, nil
	case "ALPN":
		var compat ALPNExtensionCompat
		err := json.Unmarshal(e.Data, &compat)
		if err != nil {
			return nil, errors.Trace(err)
		}
		extension := utls.ALPNExtension(compat)
		return &extension, nil
	case "SCT":
		return &utls.SCTExtension{}, nil
	case "SessionTicket":
		return &utls.SessionTicketExtension{}, nil
	case "Generic":
		var compat GenericExtensionCompat
		err := json.Unmarshal(e.Data, &compat)
		if err != nil {
			return nil, errors.Trace(err)
		}
		extension := utls.GenericExtension(compat)
		return &extension, nil
	case "ExtendedMasterSecret":
		return &utls.UtlsExtendedMasterSecretExtension{}, nil
	case "GREASE":
		return &utls.UtlsGREASEExtension{}, nil
	case "BoringPadding":
		return &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle}, nil
	case "KeyShare":
		var compat KeyShareExtensionCompat
		err := json.Unmarshal(e.Data, &compat)
		if err != nil {
			return nil, errors.Trace(err)
		}
		extension := utls.KeyShareExtension{
			KeyShares: make([]utls.KeyShare, len(compat.KeyShares)),
		}
		for i, keyShare := range compat.KeyShares {
			extension.KeyShares[i] = utls.KeyShare{
				Group: keyShare.Group,
				Data:  keyShare.Data,
			}
		}
		return &extension, nil
	case "PSKKeyExchangeModes":
		var compat PSKKeyExchangeModesExtensionCompat
		err := json.Unmarshal(e.Data, &compat)
		if err != nil {
			return nil, errors.Trace(err)
		}
		extension := utls.PSKKeyExchangeModesExtension(compat)
		return &extension, nil
	case "SupportedVersions":
		var compat SupportedVersionsExtensionCompat
		err := json.Unmarshal(e.Data, &compat)
		if err != nil {
			return nil, errors.Trace(err)
		}
		extension := utls.SupportedVersionsExtension(compat)
		return &extension, nil
	case "ChannelID":
		return &utls.FakeChannelIDExtension{}, nil
	case "CertCompressionAlgs":
		var compat UtlsCompressCertExtensionCompat
		err := json.Unmarshal(e.Data, &compat)
		if err != nil {
			return nil, errors.Trace(err)
		}
		extension := utls.UtlsCompressCertExtension(compat)
		return &extension, nil
	case "RecordSizeLimit":
		var compat FakeRecordSizeLimitExtensionCompat
		err := json.Unmarshal(e.Data, &compat)
		if err != nil {
			return nil, errors.Trace(err)
		}
		extension := utls.FakeRecordSizeLimitExtension(compat)
		return &extension, nil
	case "ALPS":
		var compat ApplicationSettingsExtensionCompat
		err := json.Unmarshal(e.Data, &compat)
		if err != nil {
			return nil, errors.Trace(err)
		}
		extension := utls.ApplicationSettingsExtension(compat)
		return &extension, nil
	case "DelegatedCredentials":
		var compat DelegatedCredentialsExtensionCompat
		err := json.Unmarshal(e.Data, &compat)
		if err != nil {
			return nil, errors.Trace(err)
		}
		extension := utls.DelegatedCredentialsExtension(compat)
		return &extension, nil
	}

	return nil, errors.Tracef("unknown utls extension: %s", e.Name)
}
