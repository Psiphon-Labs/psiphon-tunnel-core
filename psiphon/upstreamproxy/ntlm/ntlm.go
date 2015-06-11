/*
This project is licensed under the MIT license as stated below:

Copyright (C) 2013 James McKaskill

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package ntlm

import (
	"code.google.com/p/go.crypto/md4"
	"crypto/des"
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"
)

func append16(v []byte, val uint16) []byte {
	return append(v, byte(val), byte(val>>8))
}

func append32(v []byte, val uint16) []byte {
	return append(v, byte(val), byte(val>>8), byte(val>>16), byte(val>>24))
}

func consume16(v []byte) (uint16, []byte) {
	if len(v) < 2 {
		panic(ErrProtocol)
	}
	return uint16(v[0]) | uint16(v[1])<<8, v[2:]
}

func consume32(v []byte) (uint32, []byte) {
	if len(v) < 4 {
		panic(ErrProtocol)
	}
	return uint32(v[0]) | uint32(v[1])<<8 | uint32(v[2])<<16 | uint32(v[3])<<24, v[4:]
}

func consume(v []byte, n int) ([]byte, []byte) {
	if n < 0 || len(v) < n {
		panic(ErrProtocol)
	}
	return v[:n], v[n:]
}

var put32 = binary.LittleEndian.PutUint32
var put16 = binary.LittleEndian.PutUint16

const (
	negotiateUnicode    = 0x0001 // Text strings are in unicode
	negotiateOEM        = 0x0002 // Text strings are in OEM
	requestTarget       = 0x0004 // Server return its auth realm
	negotiateSign       = 0x0010 // Request signature capability
	negotiateSeal       = 0x0020 // Request confidentiality
	negotiateLMKey      = 0x0080 // Generate session key
	negotiateNTLM       = 0x0200 // NTLM authentication
	negotiateLocalCall  = 0x4000 // client/server on same machine
	negotiateAlwaysSign = 0x8000 // Sign for all security levels
)

var (
	ErrProtocol = errors.New("ntlm: protocol error")
)

func Negotiate() []byte {
	var ret []byte
	flags := negotiateAlwaysSign | negotiateNTLM | requestTarget | negotiateOEM

	ret = append(ret, "NTLMSSP\x00"...) // protocol
	ret = append32(ret, 1)              // type
	ret = append32(ret, uint16(flags))  // flags
	ret = append16(ret, 0)              // NT domain name length
	ret = append16(ret, 0)              // NT domain name max length
	ret = append32(ret, 0)              // NT domain name offset
	ret = append16(ret, 0)              // local workstation name length
	ret = append16(ret, 0)              // local workstation name max length
	ret = append32(ret, 0)              // local workstation name offset
	ret = append16(ret, 0)              // unknown name length
	ret = append16(ret, 0)              // ...
	ret = append16(ret, 0x30)           // unknown offset
	ret = append16(ret, 0)              // unknown name length
	ret = append16(ret, 0)              // ...
	ret = append16(ret, 0x30)           // unknown offset

	return ret
}

func fromUTF16LE(d []byte) string {
	u16 := make([]uint16, len(d)/2)
	for i := 0; i < len(d); i += 2 {
		u16 = append(u16, uint16(d[0])|uint16(d[1])<<8)
	}

	return string(utf16.Decode(u16))
}

func appendUTF16LE(v []byte, val string) []byte {
	for _, r := range val {
		if utf16.IsSurrogate(r) {
			r1, r2 := utf16.EncodeRune(r)
			v = append16(v, uint16(r1))
			v = append16(v, uint16(r2))
		} else {
			v = append16(v, uint16(r))
		}
	}
	return v
}

func des56To64(dst, src []byte) {
	dst[0] = src[0]
	dst[1] = (src[1] >> 1) | (src[0] << 7)
	dst[2] = (src[2] >> 2) | (src[1] << 6)
	dst[3] = (src[3] >> 3) | (src[2] << 5)
	dst[4] = (src[4] >> 4) | (src[3] << 4)
	dst[5] = (src[5] >> 5) | (src[4] << 3)
	dst[6] = (src[6] >> 6) | (src[5] << 2)
	dst[7] = src[6] << 1

	// fix parity
	for i := 0; i < 8; i++ {
		c := 0
		for bit := uint(0); bit < 8; bit++ {
			if (dst[i] & (1 << bit)) != 0 {
				c++
			}
		}
		if (c & 1) == 0 {
			dst[i] ^= 1
		}
	}
}

func calcNTLMResponse(nonce [8]byte, hash [21]byte) [24]byte {
	var ret [24]byte
	var key [24]byte

	des56To64(key[:8], hash[:7])
	des56To64(key[8:16], hash[7:14])
	des56To64(key[16:], hash[14:])

	blk, _ := des.NewCipher(key[:8])
	blk.Encrypt(ret[:8], nonce[:])

	blk, _ = des.NewCipher(key[8:16])
	blk.Encrypt(ret[8:16], nonce[:])

	blk, _ = des.NewCipher(key[16:])
	blk.Encrypt(ret[16:], nonce[:])

	return ret
}

func calcLanManResponse(nonce [8]byte, password string) [24]byte {
	var lmpass [14]byte
	var key [16]byte
	var hash [21]byte

	copy(lmpass[:14], []byte(strings.ToUpper(password)))

	des56To64(key[:8], lmpass[:7])
	des56To64(key[8:], lmpass[7:])

	blk, _ := des.NewCipher(key[:8])
	blk.Encrypt(hash[:8], []byte("KGS!@#$%"))

	blk, _ = des.NewCipher(key[8:])
	blk.Encrypt(hash[8:], []byte("KGS!@#$%"))

	return calcNTLMResponse(nonce, hash)
}

func calcNTResponse(nonce [8]byte, password string) [24]byte {
	var hash [21]byte
	h := md4.New()
	h.Write(appendUTF16LE(nil, password))
	h.Sum(hash[:0])
	return calcNTLMResponse(nonce, hash)
}

const (
	dataWINSName    = 1
	dataNTDomain    = 2
	dataDNSName     = 3
	dataWin2KDomain = 4
)

func Authenticate(chlg []byte, domain, user, password string) (v []byte, err error) {
	defer func() {
		if v := recover(); v != nil {
			err, _ = v.(error)
		}
	}()

	proto, chlg := consume(chlg, len("NTLMSSP\x00"))
	if string(proto) != "NTLMSSP\x00" {
		return nil, ErrProtocol
	}

	domain16 := appendUTF16LE(nil, domain)
	user16 := appendUTF16LE(nil, user)

	typ, chlg := consume32(chlg)       // Type 2
	domainLen, chlg := consume16(chlg) // NT domain name length
	_, chlg = consume16(chlg)          // NT domain name max length
	_, chlg = consume32(chlg)          // NT domain name offset
	_, chlg = consume32(chlg)          // flags
	nonce, chlg := consume(chlg, 8)    // nonce
	_, chlg = consume(chlg, 8)         // zero
	dataLen, chlg := consume16(chlg)   // length of data following domain
	_, chlg = consume16(chlg)          // max length of data following domain
	_, chlg = consume32(chlg)          // offset of data following domain

	_, chlg = consume(chlg, int(domainLen)) // server domain
	alldata, chlg := consume(chlg, int(dataLen))

	if typ != 2 {
		return nil, ErrProtocol
	}

	for len(alldata) > 0 {
		_, alldata := consume16(alldata) // type of this data item
		length, alldata := consume16(alldata)
		_, alldata = consume(alldata, int(length))
	}

	var noncev [8]byte
	copy(noncev[:], nonce)

	lanman := calcLanManResponse(noncev, password)
	nt := calcNTResponse(noncev, password)

	auth := make([]byte, 48)
	copy(auth, []byte("NTLMSSP\x00"))
	put32(auth[8:], 3) // type

	put16(auth[12:], uint16(len(lanman)))                              // LanManager response length
	put16(auth[14:], uint16(len(lanman)))                              // LanManager response max length
	put32(auth[16:], uint32(48+len(domain16)+len(user16)))             // LanManager response offset
	put16(auth[20:], uint16(len(nt)))                                  // NT response length
	put16(auth[22:], uint16(len(nt)))                                  // NT response max length
	put32(auth[24:], uint32(48+len(domain16)+len(user16)+len(lanman))) // NT repsonse offset
	put16(auth[28:], uint16(len(domain16)))                            // username NT domain length
	put16(auth[30:], uint16(len(domain16)))                            // username NT domain max length
	put32(auth[32:], 48)                                               // username NT domain offset
	put16(auth[36:], uint16(len(user16)))                              // username length
	put16(auth[38:], uint16(len(user16)))                              // username max length
	put32(auth[40:], uint32(48+len(domain16)))                         // username offset
	put16(auth[44:], 0)                                                // local workstation name length
	put16(auth[46:], 0)                                                // local workstation name max length
	put32(auth[48:], 0)                                                // local workstation name offset
	put16(auth[52:], 0)                                                // session key length
	put16(auth[54:], 0)                                                // session key max length
	put32(auth[56:], 0)                                                // session key offset
	put32(auth[60:], 0x8201)                                           // flags

	auth = append(auth, domain16...)
	auth = append(auth, user16...)
	auth = append(auth, lanman[:]...)
	auth = append(auth, nt[:]...)

	return auth, nil
}
