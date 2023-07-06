/*
 * Copyright (c) 2015, Psiphon Inc.
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

package obfuscator

import (
	"bytes"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	"golang.org/x/crypto/hkdf"
)

const (
	OBFUSCATE_SEED_LENGTH         = 16
	OBFUSCATE_KEY_LENGTH          = 16
	OBFUSCATE_HASH_ITERATIONS     = 6000
	OBFUSCATE_MAX_PADDING         = 8192
	OBFUSCATE_MAGIC_VALUE         = 0x0BF5CA7E
	OBFUSCATE_CLIENT_TO_SERVER_IV = "client_to_server"
	OBFUSCATE_SERVER_TO_CLIENT_IV = "server_to_client"

	// Preamble header is the first 24 bytes of the connection. If no prefix is applied,
	// the first 24 bytes are the Obfuscated SSH seed, magic value and padding length.
	PREAMBLE_HEADER_LENGTH = OBFUSCATE_SEED_LENGTH + 8 // 4 bytes each for magic value and padding length

	PREFIX_TERMINATOR_LENGTH    = 16
	PREFIX_TERM_SEARCH_BUF_SIZE = 8192
	PREFIX_MAX_LENGTH           = 65536
	PREFIX_MAX_HEADER_LENGTH    = 4096
)

type OSSHPrefixSpec struct {
	Name string
	Spec transforms.Spec
	Seed *prng.Seed
}

// OSSHPrefixHeader is the prefix header. It is written by the client
// when a prefix is applied, and read by the server to determine the
// prefix-spec to use.
type OSSHPrefixHeader struct {
	SpecName string
}

// OSSHPrefixSplitConfig are parameters for splitting the
// preamble into two writes: prefix followed by rest of the preamble.
type OSSHPrefixSplitConfig struct {
	Seed     *prng.Seed
	MinDelay time.Duration
	MaxDelay time.Duration
}

// Obfuscator implements the seed message, key derivation, and
// stream ciphers for:
// https://github.com/brl/obfuscated-openssh/blob/master/README.obfuscation
//
// Limitation: the RC4 cipher is vulnerable to ciphertext malleability and
// the "magic" value provides only weak authentication due to its small
// size. Increasing the size of the magic field will break compatibility
// with legacy clients. New protocols and schemes should not use this
// obfuscator.
type Obfuscator struct {
	preamble []byte

	// Length of the prefix in the preamble.
	preambleOSSHPrefixLength int

	// osshPrefixHeader is the prefix header written by the client,
	// or the prefix header read by the server.
	osshPrefixHeader *OSSHPrefixHeader

	osshPrefixSplitConfig *OSSHPrefixSplitConfig

	keyword              string
	paddingLength        int
	clientToServerCipher *rc4.Cipher
	serverToClientCipher *rc4.Cipher
	paddingPRNGSeed      *prng.Seed
	paddingPRNG          *prng.PRNG
}

// ObfuscatorConfig specifies an Obfuscator configuration.
type ObfuscatorConfig struct {
	IsOSSH                              bool
	Keyword                             string
	ClientPrefixSpec                    *OSSHPrefixSpec
	ServerPrefixSpecs                   transforms.Specs
	OSSHPrefixSplitConfig               *OSSHPrefixSplitConfig
	PaddingPRNGSeed                     *prng.Seed
	MinPadding                          *int
	MaxPadding                          *int
	ObfuscatorSeedTransformerParameters *transforms.ObfuscatorSeedTransformerParameters

	// SeedHistory and IrregularLogger are optional parameters used only by
	// server obfuscators.

	SeedHistory       *SeedHistory
	StrictHistoryMode bool
	IrregularLogger   func(clientIP string, err error, logFields common.LogFields)
}

// NewClientObfuscator creates a new Obfuscator, staging a seed message to be
// sent to the server (by the caller) and initializing stream ciphers to
// obfuscate data.
//
// ObfuscatorConfig.PaddingPRNGSeed allows for optional replay of the
// obfuscator padding and must not be nil.
func NewClientObfuscator(
	config *ObfuscatorConfig) (obfuscator *Obfuscator, err error) {

	if config.Keyword == "" {
		return nil, errors.TraceNew("missing keyword")
	}

	if config.PaddingPRNGSeed == nil {
		return nil, errors.TraceNew("missing padding seed")
	}

	paddingPRNG := prng.NewPRNGWithSeed(config.PaddingPRNGSeed)

	obfuscatorSeed, err := common.MakeSecureRandomBytes(OBFUSCATE_SEED_LENGTH)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// This transform may reduce the entropy of the seed, which decreases
	// the security of the stream cipher key. However, the stream cipher is
	// for obfuscation purposes only.
	if config.IsOSSH && config.ObfuscatorSeedTransformerParameters != nil {
		err = config.ObfuscatorSeedTransformerParameters.Apply(obfuscatorSeed)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	clientToServerCipher, serverToClientCipher, err := initObfuscatorCiphers(config, obfuscatorSeed)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The first prng.SEED_LENGTH bytes of the initial obfuscator message
	// padding field is used by the server as a seed for its obfuscator
	// padding and other protocol attributes (directly and via
	// GetDerivedPRNG). This allows for optional downstream replay of these
	// protocol attributes. Accordingly, the minimum padding is set to at
	// least prng.SEED_LENGTH.

	minPadding := prng.SEED_LENGTH
	if config.MinPadding != nil &&
		*config.MinPadding >= prng.SEED_LENGTH &&
		*config.MinPadding <= OBFUSCATE_MAX_PADDING {
		minPadding = *config.MinPadding
	}

	maxPadding := OBFUSCATE_MAX_PADDING
	if config.MaxPadding != nil &&
		*config.MaxPadding >= prng.SEED_LENGTH &&
		*config.MaxPadding <= OBFUSCATE_MAX_PADDING &&
		*config.MaxPadding >= minPadding {
		maxPadding = *config.MaxPadding
	}

	preamble, prefixLen, prefixHeader, paddingLength, err := makeClientPreamble(
		config.Keyword, config.ClientPrefixSpec,
		paddingPRNG, minPadding, maxPadding, obfuscatorSeed,
		clientToServerCipher)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &Obfuscator{
		preamble:                 preamble,
		preambleOSSHPrefixLength: prefixLen,
		osshPrefixHeader:         prefixHeader,
		osshPrefixSplitConfig:    config.OSSHPrefixSplitConfig,
		keyword:                  config.Keyword,
		paddingLength:            paddingLength,
		clientToServerCipher:     clientToServerCipher,
		serverToClientCipher:     serverToClientCipher,
		paddingPRNGSeed:          config.PaddingPRNGSeed,
		paddingPRNG:              paddingPRNG}, nil
}

// NewServerObfuscator creates a new Obfuscator, reading a seed message directly
// from the clientReader and initializing stream ciphers to obfuscate data.
//
// ObfuscatorConfig.PaddingPRNGSeed is not used, as the server obtains a PRNG
// seed from the client's initial obfuscator message; this scheme allows for
// optional replay of the downstream obfuscator padding.
//
// The clientIP value is used by the SeedHistory, which retains client IP values
// for a short time. See SeedHistory documentation.
func NewServerObfuscator(
	config *ObfuscatorConfig, clientIP string, clientReader io.Reader) (obfuscator *Obfuscator, err error) {

	if config.Keyword == "" {
		return nil, errors.TraceNew("missing keyword")
	}

	clientToServerCipher, serverToClientCipher, paddingPRNGSeed, prefixHeader, err := readPreamble(
		config, clientIP, clientReader)
	if err != nil {
		return nil, errors.Trace(err)
	}

	preamble, prefixLen, err := makeServerPreamble(prefixHeader, config.ServerPrefixSpecs, config.Keyword)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &Obfuscator{
		preamble:                 preamble,
		preambleOSSHPrefixLength: prefixLen,
		osshPrefixHeader:         prefixHeader,
		osshPrefixSplitConfig:    config.OSSHPrefixSplitConfig,
		keyword:                  config.Keyword,
		paddingLength:            -1,
		clientToServerCipher:     clientToServerCipher,
		serverToClientCipher:     serverToClientCipher,
		paddingPRNGSeed:          paddingPRNGSeed,
		paddingPRNG:              prng.NewPRNGWithSeed(paddingPRNGSeed),
	}, nil
}

// GetDerivedPRNG creates a new PRNG with a seed derived from the obfuscator
// padding seed and distinguished by the salt, which should be a unique
// identifier for each usage context.
//
// For NewServerObfuscator, the obfuscator padding seed is obtained from the
// client, so derived PRNGs may be used to replay sequences post-initial
// obfuscator message.
func (obfuscator *Obfuscator) GetDerivedPRNG(salt string) (*prng.PRNG, error) {
	seed, err := prng.NewPRNGWithSaltedSeed(obfuscator.paddingPRNGSeed, salt)
	return seed, errors.Trace(err)
}

// GetDerivedPRNGSeed creates a new PRNG seed derived from the obfuscator
// padding seed and distinguished by the salt, which should be a unique
// identifier for each usage context.
//
// For NewServerObfuscator, the obfuscator padding seed is obtained from the
// client, so derived seeds may be used to replay sequences post-initial
// obfuscator message.
func (obfuscator *Obfuscator) GetDerivedPRNGSeed(salt string) (*prng.Seed, error) {
	seed, err := prng.NewSaltedSeed(obfuscator.paddingPRNGSeed, salt)
	return seed, errors.Trace(err)
}

// GetPaddingLength returns the client seed message padding length. Only valid
// for NewClientObfuscator.
func (obfuscator *Obfuscator) GetPaddingLength() int {
	return obfuscator.paddingLength
}

// SendPreamble returns the preamble created in NewObfuscatorClient or
// NewServerObfuscator, removing the reference so that it may be garbage collected.
func (obfuscator *Obfuscator) SendPreamble() ([]byte, int) {
	msg := obfuscator.preamble
	prefixLen := obfuscator.preambleOSSHPrefixLength
	obfuscator.preamble = nil
	obfuscator.preambleOSSHPrefixLength = 0
	return msg, prefixLen
}

// ObfuscateClientToServer applies the client RC4 stream to the bytes in buffer.
func (obfuscator *Obfuscator) ObfuscateClientToServer(buffer []byte) {
	obfuscator.clientToServerCipher.XORKeyStream(buffer, buffer)
}

// ObfuscateServerToClient applies the server RC4 stream to the bytes in buffer.
func (obfuscator *Obfuscator) ObfuscateServerToClient(buffer []byte) {
	obfuscator.serverToClientCipher.XORKeyStream(buffer, buffer)
}

func initObfuscatorCiphers(
	config *ObfuscatorConfig, obfuscatorSeed []byte) (*rc4.Cipher, *rc4.Cipher, error) {

	clientToServerKey, err := deriveKey(obfuscatorSeed, []byte(config.Keyword), []byte(OBFUSCATE_CLIENT_TO_SERVER_IV))
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	serverToClientKey, err := deriveKey(obfuscatorSeed, []byte(config.Keyword), []byte(OBFUSCATE_SERVER_TO_CLIENT_IV))
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	clientToServerCipher, err := rc4.NewCipher(clientToServerKey)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	serverToClientCipher, err := rc4.NewCipher(serverToClientKey)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	return clientToServerCipher, serverToClientCipher, nil
}

func deriveKey(obfuscatorSeed, keyword, iv []byte) ([]byte, error) {
	h := sha1.New()
	h.Write(obfuscatorSeed)
	h.Write(keyword)
	h.Write(iv)
	digest := h.Sum(nil)
	for i := 0; i < OBFUSCATE_HASH_ITERATIONS; i++ {
		h.Reset()
		h.Write(digest)
		digest = h.Sum(nil)
	}
	if len(digest) < OBFUSCATE_KEY_LENGTH {
		return nil, errors.TraceNew("insufficient bytes for obfuscation key")
	}
	return digest[0:OBFUSCATE_KEY_LENGTH], nil
}

// makeClientPreamble generates the preamble bytes for the Obfuscated SSH protocol.
//
// If a prefix is applied, preamble bytes refer to the prefix, prefix terminator,
// followed by the Obufscted SSH initial client message, followed by the
// prefix header.
//
// If a prefix is not applied, preamble bytes refer to the Obfuscated SSH
// initial client message (referred to as the "seed message" in the original spec):
// https://github.com/brl/obfuscated-openssh/blob/master/README.obfuscation
//
// Obfuscated SSH initial client message (no prefix):
//
//	[ 16 byte random seed ][ OSSH magic ][ padding length ][ padding ]
//	|_____________________||_________________________________________|
//
//	        |                                 |
//	     Plaintext             Encrypted with key derived from seed
//
// Prefix + Obfuscated SSH initial client message:
//
//	[ 24+ byte prefix ][ terminator ][ OSSH initial client message ][ prefix header ]
//	|_________________||____________________________________________________________|
//
//	        |                                 |
//	     Plaintext             Encrypted with key derived from first 24 bytes
//
// Returns the preamble, the prefix header if a prefix was generated,
// and the padding length.
func makeClientPreamble(
	keyword string,
	prefixSpec *OSSHPrefixSpec,
	paddingPRNG *prng.PRNG,
	minPadding, maxPadding int,
	obfuscatorSeed []byte,
	clientToServerCipher *rc4.Cipher) ([]byte, int, *OSSHPrefixHeader, int, error) {

	padding := paddingPRNG.Padding(minPadding, maxPadding)
	buffer := new(bytes.Buffer)
	magicValueStartIndex := len(obfuscatorSeed)

	prefixLen := 0

	if prefixSpec != nil {
		var b []byte
		var err error
		b, prefixLen, err = makeTerminatedPrefixWithPadding(prefixSpec, keyword, OBFUSCATE_CLIENT_TO_SERVER_IV)
		if err != nil {
			return nil, 0, nil, 0, errors.Trace(err)
		}

		_, err = buffer.Write(b)
		if err != nil {
			return nil, 0, nil, 0, errors.Trace(err)
		}

		magicValueStartIndex += len(b)
	}

	err := binary.Write(buffer, binary.BigEndian, obfuscatorSeed)
	if err != nil {
		return nil, 0, nil, 0, errors.Trace(err)
	}
	err = binary.Write(buffer, binary.BigEndian, uint32(OBFUSCATE_MAGIC_VALUE))
	if err != nil {
		return nil, 0, nil, 0, errors.Trace(err)
	}
	err = binary.Write(buffer, binary.BigEndian, uint32(len(padding)))
	if err != nil {
		return nil, 0, nil, 0, errors.Trace(err)
	}
	err = binary.Write(buffer, binary.BigEndian, padding)
	if err != nil {
		return nil, 0, nil, 0, errors.Trace(err)
	}

	var prefixHeader *OSSHPrefixHeader = nil
	if prefixSpec != nil {
		// Writes the prefix header after the padding.
		err := prefixSpec.writePrefixHeader(buffer)
		if err != nil {
			return nil, 0, nil, 0, errors.Trace(err)
		}

		prefixHeader = &OSSHPrefixHeader{
			SpecName: prefixSpec.Name,
		}
	}

	preamble := buffer.Bytes()

	// Encryptes what comes after the magic value.
	clientToServerCipher.XORKeyStream(
		preamble[magicValueStartIndex:],
		preamble[magicValueStartIndex:])

	return preamble, prefixLen, prefixHeader, len(padding), nil
}

// makeServerPreamble generates a server preamble (prefix or nil).
// If the header is nil, nil is returned. Otherwise, prefix is generated
// from serverSpecs matching the spec name in the header.
// If the spec name is not found in serverSpecs, random bytes
// of length PREAMBLE_HEADER_LENGTH are returned.
func makeServerPreamble(
	header *OSSHPrefixHeader,
	serverSpecs transforms.Specs,
	keyword string) ([]byte, int, error) {

	if header == nil {
		return nil, 0, nil
	}

	spec, ok := serverSpecs[header.SpecName]
	if !ok {
		// Generate a random prefix if the spec is not found.
		spec = transforms.Spec{{"", fmt.Sprintf(`[\x00-\xff]{%d}`, PREAMBLE_HEADER_LENGTH)}}
	}

	seed, err := prng.NewSeed()
	if err != nil {
		return nil, 0, errors.Trace(err)
	}

	prefixSpec := &OSSHPrefixSpec{
		Name: header.SpecName,
		Spec: spec,
		Seed: seed,
	}
	return makeTerminatedPrefixWithPadding(prefixSpec, keyword, OBFUSCATE_SERVER_TO_CLIENT_IV)
}

// readPreamble reads the preamble bytes from the client. If it does not detect
// valid magic value in the first 24 bytes, it assumes that a prefix is applied.
// If a prefix is applied, it first discard the prefix and the terminator, before
// looking for a valid Obfuscated SSH initial client message.
func readPreamble(
	config *ObfuscatorConfig,
	clientIP string,
	clientReader io.Reader) (*rc4.Cipher, *rc4.Cipher, *prng.Seed, *OSSHPrefixHeader, error) {
	return readPreambleHelper(config, clientIP, clientReader, false)
}

func readPreambleHelper(
	config *ObfuscatorConfig,
	clientIP string,
	clientReader io.Reader,
	removedPrefix bool) (*rc4.Cipher, *rc4.Cipher, *prng.Seed, *OSSHPrefixHeader, error) {

	// To distinguish different cases, irregular tunnel logs should indicate
	// which function called NewServerObfuscator.
	errBackTrace := "obfuscator.NewServerObfuscator"

	// Since the OSSH stream might be prefixed, the seed might not be the first
	// 16 bytes of the stream. The stream is read until valid magic value
	// is detected, PREFIX_MAX_LENGTH is reached, or until the stream is exhausted.
	// If the magic value is found, the seed is the 16 bytes before the magic value,
	// and is added to and checked against the seed history.

	preambleHeader := make([]byte, PREAMBLE_HEADER_LENGTH)
	_, err := io.ReadFull(clientReader, preambleHeader)
	if err != nil {
		return nil, nil, nil, nil, errors.Trace(err)
	}

	osshSeed := preambleHeader[:OBFUSCATE_SEED_LENGTH]

	clientToServerCipher, serverToClientCipher, err := initObfuscatorCiphers(
		config, osshSeed)
	if err != nil {
		return nil, nil, nil, nil, errors.Trace(err)
	}

	osshFixedLengthFields := make([]byte, 8) // 4 bytes each for magic value and padding length
	clientToServerCipher.XORKeyStream(osshFixedLengthFields, preambleHeader[OBFUSCATE_SEED_LENGTH:])

	// The magic value must be validated before acting on paddingLength as
	// paddingLength validation is vulnerable to a chosen ciphertext probing
	// attack: only a fixed number of any possible byte value for each
	// paddingLength is valid.

	buffer := bytes.NewReader(osshFixedLengthFields)
	var magicValue, paddingLength int32
	err = binary.Read(buffer, binary.BigEndian, &magicValue)
	if err != nil {
		return nil, nil, nil, nil, errors.Trace(err)
	}
	err = binary.Read(buffer, binary.BigEndian, &paddingLength)
	if err != nil {
		return nil, nil, nil, nil, errors.Trace(err)
	}

	if magicValue != OBFUSCATE_MAGIC_VALUE && removedPrefix {
		// Prefix terminator was found, but rest of the stream is not valid
		// Obfuscated SSH.
		errStr := "invalid magic value"
		if config.IrregularLogger != nil {
			config.IrregularLogger(
				clientIP,
				errors.BackTraceNew(errBackTrace, errStr),
				nil)
		}
		return nil, nil, nil, nil, errors.TraceNew(errStr)
	}

	if magicValue == OBFUSCATE_MAGIC_VALUE {

		if config.SeedHistory != nil {
			// Adds the seed to the seed history only if the magic value is valid.
			// This is to prevent malicious clients from filling up the history cache.
			ok, duplicateLogFields := config.SeedHistory.AddNew(
				config.StrictHistoryMode, clientIP, "obfuscator-seed", osshSeed)
			errStr := "duplicate obfuscation seed"
			if duplicateLogFields != nil {
				if config.IrregularLogger != nil {
					config.IrregularLogger(
						clientIP,
						errors.BackTraceNew(errBackTrace, errStr),
						*duplicateLogFields)
				}
			}
			if !ok {
				return nil, nil, nil, nil, errors.TraceNew(errStr)
			}
		}

		if paddingLength < 0 || paddingLength > OBFUSCATE_MAX_PADDING {
			errStr := "invalid padding length"
			if config.IrregularLogger != nil {
				config.IrregularLogger(
					clientIP,
					errors.BackTraceNew(errBackTrace, errStr),
					nil)
			}
			return nil, nil, nil, nil, errors.TraceNew(errStr)
		}

		padding := make([]byte, paddingLength)
		_, err = io.ReadFull(clientReader, padding)
		if err != nil {
			return nil, nil, nil, nil, errors.Trace(err)
		}
		clientToServerCipher.XORKeyStream(padding, padding)

		var prefixHeader *OSSHPrefixHeader = nil
		if removedPrefix {
			// This is a valid prefixed OSSH stream.
			prefixHeader, err = readPrefixHeader(clientReader, clientToServerCipher)
			if err != nil {
				if config.IrregularLogger != nil {
					config.IrregularLogger(
						clientIP,
						errors.BackTraceNew(errBackTrace, "invalid prefix header"),
						nil)
				}
				return nil, nil, nil, nil, errors.Trace(err)
			}
		}

		// Use the first prng.SEED_LENGTH bytes of padding as a PRNG seed for
		// subsequent operations. This allows the client to direct server-side
		// replay of certain protocol attributes.
		//
		// Since legacy clients may send < prng.SEED_LENGTH bytes of padding,
		// generate a new seed in that case.

		var paddingPRNGSeed *prng.Seed

		if len(padding) >= prng.SEED_LENGTH {
			paddingPRNGSeed = new(prng.Seed)
			copy(paddingPRNGSeed[:], padding[0:prng.SEED_LENGTH])
		} else {
			paddingPRNGSeed, err = prng.NewSeed()
			if err != nil {
				return nil, nil, nil, nil, errors.Trace(err)
			}
		}

		return clientToServerCipher, serverToClientCipher, paddingPRNGSeed, prefixHeader, nil
	}

	if !removedPrefix {
		// No magic value found, could be a prefixed OSSH stream.
		// Skips up to the prefix terminator, and looks for the magic value again.

		clientReader, ok := clientReader.(*SkipReader)
		if !ok {
			return nil, nil, nil, nil, errors.TraceNew("expected SkipReader")
		}

		terminator, err := makeTerminator(config.Keyword, preambleHeader, OBFUSCATE_CLIENT_TO_SERVER_IV)
		if err != nil {
			return nil, nil, nil, nil, errors.Trace(err)
		}

		err = clientReader.SkipUpToToken(terminator, PREFIX_TERM_SEARCH_BUF_SIZE, PREFIX_MAX_LENGTH)
		if err != nil {
			// No magic value or prefix terminator found,
			// log irregular tunnel and return error.
			errStr := "no prefix terminator or invalid magic value"
			if config.IrregularLogger != nil {
				config.IrregularLogger(
					clientIP,
					errors.BackTraceNew(errBackTrace, errStr),
					nil)
			}
			return nil, nil, nil, nil, errors.TraceNew(errStr)
		}

		// Reads OSSH initial client message followed by prefix header.
		return readPreambleHelper(config, clientIP, clientReader, true)
	}

	// Should never reach here.
	return nil, nil, nil, nil, errors.TraceNew("unexpected error")
}

// makeTerminator generates a prefix terminator used in finding end of prefix
// placed before OSSH stream.
// b should be at least PREAMBLE_HEADER_LENGTH bytes and contain enough entropy.
func makeTerminator(keyword string, b []byte, direction string) ([]byte, error) {

	// Bytes length is at least equal to obfuscator seed message.
	if len(b) < PREAMBLE_HEADER_LENGTH {
		return nil, errors.TraceNew("bytes too short")
	}

	if (direction != OBFUSCATE_CLIENT_TO_SERVER_IV) &&
		(direction != OBFUSCATE_SERVER_TO_CLIENT_IV) {
		return nil, errors.TraceNew("invalid direction")
	}

	hkdf := hkdf.New(sha256.New,
		[]byte(keyword),
		b[:PREAMBLE_HEADER_LENGTH],
		[]byte(direction))

	terminator := make([]byte, PREFIX_TERMINATOR_LENGTH)
	_, err := io.ReadFull(hkdf, terminator)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return terminator, nil
}

// makeTerminatedPrefixWithPadding generates bytes starting with the prefix bytes defiend
// by spec and ending with the generated terminator.
// If the generated prefix is shorter than PREAMBLE_HEADER_LENGTH, it is padded
// with random bytes.
// Returns the generated prefix with teminator, and the length of the prefix if no error.
func makeTerminatedPrefixWithPadding(spec *OSSHPrefixSpec, keyword, direction string) ([]byte, int, error) {

	prefix, prefixLen, err := spec.Spec.ApplyPrefix(spec.Seed, PREAMBLE_HEADER_LENGTH)
	if err != nil {
		return nil, 0, errors.Trace(err)
	}

	terminator, err := makeTerminator(keyword, prefix, direction)

	if err != nil {
		return nil, 0, errors.Trace(err)
	}
	terminatedPrefix := append(prefix, terminator...)

	return terminatedPrefix, prefixLen, nil
}

// writePrefixHeader writes the prefix header to the given writer.
// The prefix header is written in the following format:
//
// [ 2 byte version ][4 byte spec-length ][ .. prefix-spec-name ...]
func (spec *OSSHPrefixSpec) writePrefixHeader(w io.Writer) error {
	if len(spec.Name) > PREFIX_MAX_HEADER_LENGTH {
		return errors.TraceNew("prefix name too long")
	}
	err := binary.Write(w, binary.BigEndian, uint16(0x01))
	if err != nil {
		return errors.Trace(err)
	}
	err = binary.Write(w, binary.BigEndian, uint16(len(spec.Name)))
	if err != nil {
		return errors.Trace(err)
	}
	_, err = w.Write([]byte(spec.Name))
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func readPrefixHeader(
	clientReader io.Reader,
	cipher *rc4.Cipher) (*OSSHPrefixHeader, error) {

	fixedLengthFields := make([]byte, 4)
	_, err := io.ReadFull(clientReader, fixedLengthFields)
	if err != nil {
		return nil, errors.Trace(err)
	}

	cipher.XORKeyStream(fixedLengthFields, fixedLengthFields)

	buffer := bytes.NewBuffer(fixedLengthFields)
	var version uint16
	err = binary.Read(buffer, binary.BigEndian, &version)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if version != 0x01 {
		return nil, errors.TraceNew("invalid version")
	}

	var specLen uint16
	err = binary.Read(buffer, binary.BigEndian, &specLen)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if specLen > PREFIX_MAX_HEADER_LENGTH {
		return nil, errors.TraceNew("invalid header length")
	}

	// Read the spec name.
	specName := make([]byte, specLen)
	_, err = io.ReadFull(clientReader, specName)
	if err != nil {
		return nil, errors.Trace(err)
	}
	cipher.XORKeyStream(specName, specName)

	return &OSSHPrefixHeader{
		SpecName: string(specName),
	}, nil
}
