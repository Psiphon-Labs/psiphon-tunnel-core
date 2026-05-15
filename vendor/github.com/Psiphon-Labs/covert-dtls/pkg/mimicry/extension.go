package mimicry

import (
	"encoding/binary"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/Psiphon-Labs/covert-dtls/pkg/utils"
)

// Unmarshal many extensions at once.
func MimicExtensionsUnmarshal(buf []byte) ([]extension.Extension, error) {
	switch {
	case len(buf) == 0:
		return []extension.Extension{}, nil
	case len(buf) < 2:
		return nil, errBufferTooSmall
	}

	declaredLen := binary.BigEndian.Uint16(buf)
	if len(buf)-2 != int(declaredLen) {
		return nil, errLengthMismatch
	}

	extensions := []extension.Extension{}
	unmarshalAndAppend := func(data []byte, e extension.Extension) error {
		err := e.Unmarshal(data)
		if err != nil {
			return err
		}
		extensions = append(extensions, e)

		return nil
	}

	for offset := 2; offset < len(buf); {
		if len(buf) < (offset + 2) {
			return nil, errBufferTooSmall
		}
		var err error
		switch extension.TypeValue(binary.BigEndian.Uint16(buf[offset:])) {
		case extension.ServerNameTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.ServerName{})
		case extension.SupportedEllipticCurvesTypeValue:
			// Mimic
			err = unmarshalAndAppend(buf[offset:], &utils.FakeExt{})
		case extension.SupportedPointFormatsTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.SupportedPointFormats{})
		case extension.SupportedSignatureAlgorithmsTypeValue:
			// Mimic
			err = unmarshalAndAppend(buf[offset:], &utils.FakeExt{})
		case extension.UseSRTPTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.UseSRTP{})
		case extension.ALPNTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.ALPN{})
		case extension.UseExtendedMasterSecretTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.UseExtendedMasterSecret{})
		case extension.RenegotiationInfoTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.RenegotiationInfo{})
		case extension.ConnectionIDTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.ConnectionID{})
		case utils.KeyShareTypeValue:
			// Unmarshal mimicked KeyShare
			err = unmarshalAndAppend(buf[offset:], &utils.KeyShare{})
		default:
			// Unmarshal any mimicked unimplemented extension
			err = unmarshalAndAppend(buf[offset:], &utils.FakeExt{})
		}
		if err != nil {
			return nil, err
		}
		if len(buf) < (offset + 4) {
			return nil, errBufferTooSmall
		}
		extensionLength := binary.BigEndian.Uint16(buf[offset+2:])
		offset += (4 + int(extensionLength))
	}

	return extensions, nil
}
