package fte

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"github.com/redjack/marionette/ecb"
)

// _MAC_LENGTH = AES.block_size
// _IV_LENGTH = 7
// _MSG_COUNTER_LENGTH = 8
// _CTXT_EXPANSION = 1 + _IV_LENGTH + _MSG_COUNTER_LENGTH + _MAC_LENGTH

var (
	ErrShortCiphertext        = errors.New("fte: short ciphertext")
	ErrInvalidMessageLength   = errors.New("fte: invalid message length")
	ErrHMACVerificationFailed = errors.New("fte: hmac verification failed")
)

var (
	K1 = []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")
	K2 = []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
)

const _IV_LENGTH = 7

type Encrypter struct {
	block     cipher.Block
	blockMode cipher.BlockMode

	IV []byte
}

func NewEncrypter() (*Encrypter, error) {
	blk, err := aes.NewCipher(K1)
	if err != nil {
		return nil, err
	}

	return &Encrypter{
		block:     blk,
		blockMode: ecb.NewEncrypter(blk),
	}, nil
}

func (enc *Encrypter) Encrypt(plaintext []byte) ([]byte, error) {
	plaintextN := len(plaintext)

	// Read random bytes for initialization vector.
	iv := make([]byte, _IV_LENGTH)
	if len(enc.IV) == _IV_LENGTH {
		copy(iv, enc.IV)
	} else {
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
	}

	// Encrypt length as AES ECB.
	iv1 := []byte{'\x01'}
	iv1 = append(iv1, iv...)
	iv1 = append(iv1, u64tob(uint64(plaintextN))...)
	W1 := make([]byte, len(iv1))
	enc.blockMode.CryptBlocks(W1, iv1)

	// Encrypt plaintext with AES CTR.
	iv2 := []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x02")
	iv2 = append(iv2, iv...)
	stream := cipher.NewCTR(enc.block, iv2)
	padN := aes.BlockSize - (plaintextN % aes.BlockSize)
	plaintext = append(plaintext, make([]byte, padN)...)
	W2 := make([]byte, len(plaintext))
	stream.XORKeyStream(W2, plaintext)
	W2, plaintext = W2[:plaintextN], plaintext[:plaintextN]

	// Concatenate both sections.
	ciphertext := append(W1[:len(W1):len(W1)], W2...)

	// Sign the message & limit size to AES block size.
	mac := hmac.New(sha512.New, K2)
	mac.Write(ciphertext)
	T := mac.Sum(nil)
	T = T[:aes.BlockSize]

	return append(ciphertext, T...), nil
}

type Decrypter struct {
	block     cipher.Block
	blockMode cipher.BlockMode
}

func NewDecrypter() (*Decrypter, error) {
	blk, err := aes.NewCipher(K1)
	if err != nil {
		return nil, err
	}

	return &Decrypter{
		block:     blk,
		blockMode: ecb.NewDecrypter(blk),
	}, nil
}

func (dec *Decrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 16 {
		return nil, ErrShortCiphertext
	}

	// Decrypt header.
	L := make([]byte, 16)
	dec.block.Decrypt(L, ciphertext[:16])

	plaintext_length := binary.BigEndian.Uint64(L[8:16])
	if plaintext_length > math.MaxUint32 {
		return nil, ErrInvalidMessageLength
	}

	ciphertext_length := plaintext_length + CTXT_EXPANSION
	if len(ciphertext) < int(ciphertext_length) {
		return nil, ErrShortCiphertext
	}
	ciphertext = ciphertext[:ciphertext_length:ciphertext_length]

	W1 := ciphertext[0:aes.BlockSize:aes.BlockSize]
	W2 := ciphertext[aes.BlockSize : aes.BlockSize+plaintext_length : aes.BlockSize+plaintext_length]

	T_start := aes.BlockSize + plaintext_length
	T_end := aes.BlockSize + plaintext_length + aes.BlockSize
	T_expected := ciphertext[T_start:T_end:T_end]

	// Sign the message & limit size to AES block size.
	mac := hmac.New(sha512.New, K2)
	mac.Write(append(W1, W2...))
	if !hmac.Equal(mac.Sum(nil)[:aes.BlockSize], T_expected) {
		return nil, ErrHMACVerificationFailed
	}

	// Decrypt ciphertext with AES CTR.
	iv := make([]byte, aes.BlockSize)
	dec.block.Decrypt(iv, W1)
	iv2 := make([]byte, aes.BlockSize)
	iv2[8] = '\x02'
	copy(iv2[9:], iv[1:8])

	stream := cipher.NewCTR(dec.block, iv2)
	plaintext := make([]byte, plaintext_length)
	stream.XORKeyStream(plaintext, W2)

	return plaintext, nil
}

func (dec *Decrypter) CiphertextLen(ciphertext []byte) int {
	L := make([]byte, 16)
	dec.block.Decrypt(L, ciphertext[:16])
	return int(binary.BigEndian.Uint32(L[12:16])) + CTXT_EXPANSION
}

// u64tob returns the big endian representation of a uint64 value.
func u64tob(i uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, i)
	return b
}
