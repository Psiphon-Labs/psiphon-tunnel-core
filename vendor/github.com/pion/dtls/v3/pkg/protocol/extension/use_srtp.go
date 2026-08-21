// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"encoding/binary"
)

const (
	useSRTPHeaderSize = 6
	maxUint16         = (1 << 16) - 1
)

// UseSRTP allows a Client/Server to negotiate what SRTPProtectionProfiles
// they both support
//
// https://datatracker.ietf.org/doc/html/rfc5764
type UseSRTP struct {
	ProtectionProfiles  []SRTPProtectionProfile
	MasterKeyIdentifier []byte
}

// TypeValue returns the extension TypeValue.
func (u UseSRTP) TypeValue() TypeValue {
	return UseSRTPTypeValue
}

// Marshal encodes the extension.
func (u *UseSRTP) Marshal() ([]byte, error) {
	if len(u.MasterKeyIdentifier) > 255 {
		return nil, errMasterKeyIdentifierTooLarge
	}

	extensionDataLen := 2 + (len(u.ProtectionProfiles) * 2) + 1 + len(u.MasterKeyIdentifier)
	if extensionDataLen > maxUint16 {
		return nil, errUseSRTPDataTooLarge
	}
	out := make([]byte, 4+extensionDataLen)

	binary.BigEndian.PutUint16(out, uint16(u.TypeValue()))
	//nolint:gosec // G115
	binary.BigEndian.PutUint16(
		out[2:],
		uint16(extensionDataLen),
	)
	binary.BigEndian.PutUint16(out[4:], uint16(len(u.ProtectionProfiles)*2)) //nolint:gosec // G115

	offset := useSRTPHeaderSize
	for _, v := range u.ProtectionProfiles {
		binary.BigEndian.PutUint16(out[offset:], uint16(v))
		offset += 2
	}

	//nolint:gosec // G115: MKI length is validated to be <= 255 above.
	out[offset] = byte(len(u.MasterKeyIdentifier))
	copy(out[offset+1:], u.MasterKeyIdentifier)

	return out, nil
}

// Unmarshal populates the extension from encoded data.
func (u *UseSRTP) Unmarshal(data []byte) error {
	if len(data) <= useSRTPHeaderSize {
		return errBufferTooSmall
	} else if TypeValue(binary.BigEndian.Uint16(data)) != u.TypeValue() {
		return errInvalidExtensionType
	}

	profileCount := int(binary.BigEndian.Uint16(data[4:]) / 2)
	masterKeyIdentifierIndex := supportedGroupsHeaderSize + (profileCount * 2)
	if masterKeyIdentifierIndex+1 > len(data) {
		return errLengthMismatch
	}

	declaredLength := int(binary.BigEndian.Uint16(data[2:4]))

	masterKeyIdentifierLen := int(data[masterKeyIdentifierIndex])
	end := masterKeyIdentifierIndex + masterKeyIdentifierLen
	if end >= len(data) || end-4 != declaredLength-1 {
		return errLengthMismatch
	}

	for i := range profileCount {
		supportedProfile := SRTPProtectionProfile(binary.BigEndian.Uint16(data[(useSRTPHeaderSize + (i * 2)):]))
		if _, ok := srtpProtectionProfiles()[supportedProfile]; ok {
			u.ProtectionProfiles = append(u.ProtectionProfiles, supportedProfile)
		}
	}

	u.MasterKeyIdentifier = append(
		[]byte{},
		data[masterKeyIdentifierIndex+1:end+1]...,
	)

	return nil
}
