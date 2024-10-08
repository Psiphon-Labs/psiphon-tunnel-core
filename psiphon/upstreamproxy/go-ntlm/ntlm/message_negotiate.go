//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	"encoding/binary"
)

// Supported negotiate flags
const (
	NEGOTIATE_FLAG_REQUEST_NTLMv1           = 0x00000200
	NEGOTIATE_FLAG_REQUEST_NTLM2_SESSION    = 0x00080000
	NEGOTIATE_FLAG_REQUEST_VERSION          = 0x02000000
	NEGOTIATE_FLAG_REQUEST_ALWAYS_SIGN      = 0x00008000
	NEGOTIATE_FLAG_REQUEST_128BIT_KEY_EXCH  = 0x20000000
	NEGOTIATE_FLAG_REQUEST_56BIT_ENCRYPTION = 0x80000000
	NEGOTIATE_FLAG_REQUEST_UNICODE_ENCODING = 0x00000001
)

type NegotiateMessage struct {
	// All bytes of the message
	// Bytes []byte

	// sig - 8 bytes
	Signature []byte
	// message type - 4 bytes
	MessageType uint32
	// negotiate flags - 4bytes
	NegotiateFlags uint32
	// If the NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no DomainName is supplied in Payload  - then this should have Len 0 / MaxLen 0
	// this contains a domain name
	DomainNameFields *PayloadStruct
	// If the NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no WorkstationName is supplied in Payload - then this should have Len 0 / MaxLen 0
	WorkstationFields *PayloadStruct
	// version - 8 bytes
	Version *VersionStruct
	// payload - variable
	Payload       []byte
	PayloadOffset int
}

func (nm *NegotiateMessage) Bytes() []byte {
	//Domain and Workstation payload are not supported
	messageLen := 40

	messageBytes := make([]byte, 0, messageLen)
	buffer := bytes.NewBuffer(messageBytes)

	//Signature 8
	buffer.Write(nm.Signature) //0
	//MessageType 4
	binary.Write(buffer, binary.LittleEndian, nm.MessageType) //8
	//Flags 4
	binary.Write(buffer, binary.LittleEndian, nm.NegotiateFlags) //12
	//DomainLen 2
	binary.Write(buffer, binary.LittleEndian, uint16(0))
	//DomainMaxLen == DomainLen 2
	binary.Write(buffer, binary.LittleEndian, uint16(0))
	//DomainOffset 4
	binary.Write(buffer, binary.LittleEndian, uint32(messageLen))
	//WorkstationLen 2
	binary.Write(buffer, binary.LittleEndian, uint16(0))
	//WorkstationMaxLen == WorkstationLen 2
	binary.Write(buffer, binary.LittleEndian, uint16(0))
	//WorkstationOffset 4
	binary.Write(buffer, binary.LittleEndian, uint32(40))
	//VersionStruct  1 + 1 + 2 + 1 + 1 + 1 + 1 = 8
	buffer.Write(nm.Version.Bytes())
	return buffer.Bytes()
}
