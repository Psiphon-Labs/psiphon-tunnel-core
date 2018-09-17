package ecb

import (
	"crypto/cipher"
)

type encrypter struct {
	b         cipher.Block
	blockSize int
}

func NewEncrypter(b cipher.Block) cipher.BlockMode {
	return &encrypter{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

func (enc *encrypter) BlockSize() int { return enc.blockSize }

func (enc *encrypter) CryptBlocks(dst, src []byte) {
	if len(src)%enc.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	} else if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		enc.b.Encrypt(dst, src[:enc.blockSize])
		src = src[enc.blockSize:]
		dst = dst[enc.blockSize:]
	}
}

type decrypter struct {
	b         cipher.Block
	blockSize int
}

func NewDecrypter(b cipher.Block) cipher.BlockMode {
	return &decrypter{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

func (dec *decrypter) BlockSize() int { return dec.blockSize }

func (dec *decrypter) CryptBlocks(dst, src []byte) {
	if len(src)%dec.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	} else if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		dec.b.Decrypt(dst, src[:dec.blockSize])
		src = src[dec.blockSize:]
		dst = dst[dec.blockSize:]
	}
}
