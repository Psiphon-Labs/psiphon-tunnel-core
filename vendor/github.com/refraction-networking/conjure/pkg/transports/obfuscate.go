package transports

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"

	"github.com/refraction-networking/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
)

// Obfuscator provides an interface for obfuscating the tags that are sent by transports in order to
// indicate their knowledge of the shared secret to the station.
type Obfuscator interface {
	// Take the plain text and perform an obfuscation to make it distinguishable to the station
	Obfuscate(plaintext []byte, stationPubkey []byte) ([]byte, error)

	// Take a cipher text and de-obfuscate to make it usable by the station
	TryReveal(cipherText []byte, privateKey [32]byte) ([]byte, error)
}

// GCMObfuscator implements the Obfuscator interface using ECDHE and AES GCM. Prevents tag re-use.
type GCMObfuscator struct{}

// TryReveal for GCMObfuscator expects a ciphertext object where the first 32 bytes is an elligator
// encoded public key with which the server can derive an ECDHE shared secret. This secret is then
// used to decrypt and authenticate the remainder of the plaintext using AES GCM.
func (GCMObfuscator) TryReveal(ciphertext []byte, privateKey [32]byte) ([]byte, error) {
	if len(ciphertext) < 48 {
		return nil, ErrPublicKeyLen
	}

	var representative, clientPubkey [32]byte
	copy(representative[:], ciphertext[:32])
	representative[31] &= 0x3F
	extra25519.RepresentativeToPublicKey(&clientPubkey, &representative)

	sharedSecret, err := curve25519.X25519(privateKey[:], clientPubkey[:])
	if err != nil {
		return nil, err
	}

	stationPubkeyHash := sha256.Sum256(sharedSecret[:])
	aesKey := stationPubkeyHash[:16]
	aesIvTag := stationPubkeyHash[16:28]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	// return block.Decrypt(nil, aesIvTag, cipherText[32:])

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, aesIvTag, ciphertext[32:], nil)
}

// Obfuscate for GCMObfuscator derives a shared key using ECDHE an then encrypts the plaintext under
// that key using AES GCM. The elligator representative for the clients public key is prepended
// to the returned byte array. This means that the result length will likely be:
//
//	32 + len(plaintext) + 16
//
// [elligator encoded client Pub][Ciphertext + Auth tag]
func (GCMObfuscator) Obfuscate(plainText []byte, stationPubkey []byte) ([]byte, error) {
	if len(stationPubkey) != 32 {
		return nil, fmt.Errorf("%w, received: %d", ErrPublicKeyLen, len(stationPubkey))
	}
	var clientPrivate, clientPublic, representative [32]byte
	var sharedSecret []byte
	for ok := false; !ok; {
		var sliceKeyPrivate []byte = clientPrivate[:]
		_, err := rand.Read(sliceKeyPrivate)
		if err != nil {
			return nil, err
		}

		ok = extra25519.ScalarBaseMult(&clientPublic, &representative, &clientPrivate)
	}

	sharedSecret, err := curve25519.X25519(clientPrivate[:], stationPubkey)
	if err != nil {
		return nil, err
	}

	// extra25519.ScalarBaseMult does not randomize most significant bit(sign of y_coord?)
	// Other implementations of elligator may have up to 2 non-random bits.
	// Here we randomize the bit, expecting it to be flipped back to 0 on station
	randByte := make([]byte, 1)
	_, err = rand.Read(randByte)
	if err != nil {
		return nil, err
	}
	representative[31] |= (0xC0 & randByte[0])

	tagBuf := new(bytes.Buffer) // What we have to encrypt with the shared secret using AES
	tagBuf.Write(representative[:])

	stationPubkeyHash := sha256.Sum256(sharedSecret[:])
	aesKey := stationPubkeyHash[:16]
	aesIvTag := stationPubkeyHash[16:28] // 12 bytes for plaintext nonce

	cipherText, err := aesGcmEncrypt(plainText, aesKey, aesIvTag)
	if err != nil {
		return nil, err
	}

	tagBuf.Write(cipherText)
	tag := tagBuf.Bytes()

	return tag, nil
}

// CTRObfuscator implements the Obfuscator interface using ECDHE and AES CTR. Prevents tag re-use.
type CTRObfuscator struct{}

// TryReveal for CTRObfuscator expects a ciphertext object where the first 32 bytes is an elligator
// encoded public key with which the server can derive an ECDHE shared secret. This secret is then
// used to decrypt the remainder of the plaintext using AES CTR.
func (CTRObfuscator) TryReveal(ciphertext []byte, privateKey [32]byte) ([]byte, error) {
	if len(ciphertext) < 32 {
		return nil, ErrPublicKeyLen
	}

	var representative, clientPubkey [32]byte
	copy(representative[:], ciphertext[:32])
	representative[31] &= 0x3F
	extra25519.RepresentativeToPublicKey(&clientPubkey, &representative)

	sharedSecret, err := curve25519.X25519(privateKey[:], clientPubkey[:])
	if err != nil {
		return nil, err
	}

	stationPubkeyHash := sha256.Sum256(sharedSecret[:])
	aesKey := stationPubkeyHash[:16]
	aesIvTag := stationPubkeyHash[16:32]

	return aesCTR(ciphertext[32:], aesKey, aesIvTag)
}

// Obfuscate for CTRObfuscator derives a shared key using ECDHE an then encrypts the plaintext under
// that key using AES CTR. The elligator representative for the clients public key is prepended
// to the returned byte array. This means that the result length will likely be:
//
//	32 + len(plaintext)
//
// [elligator encoded client Pub][Ciphertext]
func (CTRObfuscator) Obfuscate(plainText []byte, stationPubkey []byte) ([]byte, error) {
	if len(stationPubkey) != 32 {
		return nil, errors.New("Unexpected station pubkey length. Expected: 32." +
			" Received: " + strconv.Itoa(len(stationPubkey)) + ".")
	}
	var clientPrivate, clientPublic, representative [32]byte
	var sharedSecret []byte
	for ok := false; !ok; {
		var sliceKeyPrivate []byte = clientPrivate[:]
		_, err := rand.Read(sliceKeyPrivate)
		if err != nil {
			return nil, err
		}

		ok = extra25519.ScalarBaseMult(&clientPublic, &representative, &clientPrivate)
	}

	sharedSecret, err := curve25519.X25519(clientPrivate[:], stationPubkey)
	if err != nil {
		return nil, err
	}

	// extra25519.ScalarBaseMult does not randomize most significant bit(sign of y_coord?)
	// Other implementations of elligator may have up to 2 non-random bits.
	// Here we randomize the bit, expecting it to be flipped back to 0 on station
	randByte := make([]byte, 1)
	_, err = rand.Read(randByte)
	if err != nil {
		return nil, err
	}
	representative[31] |= (0xC0 & randByte[0])

	tagBuf := new(bytes.Buffer) // What we have to encrypt with the shared secret using AES
	tagBuf.Write(representative[:])

	stationPubkeyHash := sha256.Sum256(sharedSecret[:])
	aesKey := stationPubkeyHash[:16]
	aesIvTag := stationPubkeyHash[16:32] // 16 bytes for CTR IV

	cipherText, err := aesCTR(plainText, aesKey, aesIvTag)
	if err != nil {
		return nil, err
	}

	tagBuf.Write(cipherText)
	tag := tagBuf.Bytes()

	return tag, nil
}

// XORObfuscator implements the Obfuscator interface for no modification the provided tag /
// plaintext / ciphertext. Will NOT prevent tag re-use if a registration is re-used.
type XORObfuscator struct{}

// TryReveal for XORObfuscator just returns the provided ciphertext without modification
func (XORObfuscator) TryReveal(cipherText []byte, privateKey [32]byte) ([]byte, error) {
	if len(cipherText)%2 != 0 || len(cipherText) == 0 {
		return nil, errors.New("Unexpected message with even length")
	}

	n := len(cipherText) / 2
	out := make([]byte, n)
	for i, b := range cipherText[:n] {
		out[i] = b ^ cipherText[n+i]
	}
	return out, nil
}

// Obfuscate for XORObfuscator just returns the provided plaintext without modification
func (XORObfuscator) Obfuscate(plainText []byte, stationPubkey []byte) ([]byte, error) {
	lp := len(plainText)
	if lp == 0 {
		return []byte{}, nil
	}
	out := make([]byte, lp*2)

	randByte := make([]byte, lp)
	_, err := rand.Read(randByte)
	if err != nil {
		return nil, err
	}

	for i, b := range randByte {
		out[i] = b
		out[lp+i] = b ^ plainText[i]
	}

	return out, nil
}

// NilObfuscator implements the Obfuscator interface for no modification the provided tag /
// plaintext / ciphertext. Will NOT prevent tag re-use if a registration is re-used.
type NilObfuscator struct{}

// TryReveal for NilObfuscator just returns the provided ciphertext without modification
func (NilObfuscator) TryReveal(cipherText []byte, privateKey [32]byte) ([]byte, error) {
	return cipherText, nil
}

// Obfuscate for NilObfuscator just returns the provided plaintext without modification
func (NilObfuscator) Obfuscate(plainText []byte, stationPubkey []byte) ([]byte, error) {
	return plainText, nil
}

// The key argument should be the AES key, either 16 or 32 bytes
// to select AES-128 or AES-256.
func aesGcmEncrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGcmCipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesGcmCipher.Seal(nil, iv, plaintext, nil), nil
}

func aesCTR(in []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(in))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(out, in)

	return out, nil
}
