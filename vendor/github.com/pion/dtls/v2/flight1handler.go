// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"

	"github.com/pion/dtls/v2/pkg/crypto/elliptic"
	"github.com/pion/dtls/v2/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/alert"
	"github.com/pion/dtls/v2/pkg/protocol/extension"
	"github.com/pion/dtls/v2/pkg/protocol/handshake"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"

	inproxy_dtls "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy/dtls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

func flight1Parse(ctx context.Context, c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) (flightVal, *alert.Alert, error) {
	// HelloVerifyRequest can be skipped by the server,
	// so allow ServerHello during flight1 also
	seq, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence, state.cipherSuite,
		handshakeCachePullRule{handshake.TypeHelloVerifyRequest, cfg.initialEpoch, false, true},
		handshakeCachePullRule{handshake.TypeServerHello, cfg.initialEpoch, false, true},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	if _, ok := msgs[handshake.TypeServerHello]; ok {
		// Flight1 and flight2 were skipped.
		// Parse as flight3.
		return flight3Parse(ctx, c, state, cache, cfg)
	}

	if h, ok := msgs[handshake.TypeHelloVerifyRequest].(*handshake.MessageHelloVerifyRequest); ok {
		// DTLS 1.2 clients must not assume that the server will use the protocol version
		// specified in HelloVerifyRequest message. RFC 6347 Section 4.2.1
		if !h.Version.Equal(protocol.Version1_0) && !h.Version.Equal(protocol.Version1_2) {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, errUnsupportedProtocolVersion
		}
		state.cookie = append([]byte{}, h.Cookie...)
		state.handshakeRecvSequence = seq
		return flight3, nil, nil
	}

	return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
}

// [Psiphon]
// The API for this Psiphon fork is identical to upstream, apart from this
// symbol, which may be used to verify that the fork is used when compiling.
const IsPsiphon = true

func flight1Generate(ctx context.Context, c flightConn, state *State, _ *handshakeCache, cfg *handshakeConfig) ([]*packet, *alert.Alert, error) {
	var zeroEpoch uint16
	state.localEpoch.Store(zeroEpoch)
	state.remoteEpoch.Store(zeroEpoch)
	state.namedCurve = defaultNamedCurve
	state.cookie = nil

	if err := state.localRandom.Populate(); err != nil {
		return nil, nil, err
	}

	// [Psiphon]
	// Conjure DTLS support, from: https://github.com/mingyech/dtls/commit/a56eccc1
	if state.isClient && cfg.customClientHelloRandom != nil {
		state.localRandom.RandomBytes = cfg.customClientHelloRandom()
	}

	extensions := []extension.Extension{
		&extension.SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: cfg.localSignatureSchemes,
		},
		&extension.RenegotiationInfo{
			RenegotiatedConnection: 0,
		},
	}

	var setEllipticCurveCryptographyClientHelloExtensions bool
	for _, c := range cfg.localCipherSuites {
		if c.ECC() {
			setEllipticCurveCryptographyClientHelloExtensions = true
			break
		}
	}

	if setEllipticCurveCryptographyClientHelloExtensions {
		extensions = append(extensions, []extension.Extension{
			&extension.SupportedEllipticCurves{
				EllipticCurves: cfg.ellipticCurves,
			},
			&extension.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}...)
	}

	if len(cfg.localSRTPProtectionProfiles) > 0 {
		extensions = append(extensions, &extension.UseSRTP{
			ProtectionProfiles: cfg.localSRTPProtectionProfiles,
		})
	}

	if cfg.extendedMasterSecret == RequestExtendedMasterSecret ||
		cfg.extendedMasterSecret == RequireExtendedMasterSecret {
		extensions = append(extensions, &extension.UseExtendedMasterSecret{
			Supported: true,
		})
	}

	if len(cfg.serverName) > 0 {
		extensions = append(extensions, &extension.ServerName{ServerName: cfg.serverName})
	}

	if len(cfg.supportedProtocols) > 0 {
		extensions = append(extensions, &extension.ALPN{ProtocolNameList: cfg.supportedProtocols})
	}

	if cfg.sessionStore != nil {
		cfg.log.Tracef("[handshake] try to resume session")
		if s, err := cfg.sessionStore.Get(c.sessionKey()); err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		} else if s.ID != nil {
			cfg.log.Tracef("[handshake] get saved session: %x", s.ID)

			state.SessionID = s.ID
			state.masterSecret = s.Secret
		}
	}

	cipherSuites := cipherSuiteIDs(cfg.localCipherSuites)

	// [Psiphon]
	// Randomize ClientHello
	seed, err := inproxy_dtls.GetDTLSSeed(ctx)
	if err != nil {
		return nil, nil, err
	}
	if seed != nil {

		PRNG := prng.NewPRNGWithSeed(seed)

		cut := func(length int) int {
			n := length
			for ; n > 1; n-- {
				if !PRNG.FlipCoin() {
					break
				}
			}
			return n
		}

		PRNG.Shuffle(len(cipherSuites), func(i, j int) {
			cipherSuites[i], cipherSuites[j] = cipherSuites[j], cipherSuites[i]
		})
		cipherSuites = cipherSuites[:cut(len(cipherSuites))]

		// At least one ECC cipher suite needs to be retained for compatibilty
		// with the server's ECC certificate. Select from the ECC cipher suites
		// currently returned by defaultCipherSuites.

		eccCipherSuites := []uint16{
			uint16(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			uint16(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
			uint16(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
		}
		hasECC := false
	checkECCLoop:
		for _, cipherSuite := range cipherSuites {
			for _, eccCipherSuite := range eccCipherSuites {
				if cipherSuite == eccCipherSuite {
					hasECC = true
					break checkECCLoop
				}
			}
		}
		if !hasECC {
			eccCipherSuite := eccCipherSuites[PRNG.Intn(len(eccCipherSuites))]
			cipherSuites = append(cipherSuites, eccCipherSuite)
			PRNG.Shuffle(len(cipherSuites), func(i, j int) {
				cipherSuites[i], cipherSuites[j] = cipherSuites[j], cipherSuites[i]
			})
		}

		for _, ext := range extensions {
			switch e := ext.(type) {
			case *extension.SupportedSignatureAlgorithms:

				// Limitation: to ensure compatibility with the ECDSA P-256 certificates generated by pion/webrtc,
				// https://github.com/pion/webrtc/blob/1df634e1188e06c08fe87753c7bdd576a29e0c92/dtlstransport.go#L84-L92,
				// the corresponding signature/hash algorithm needs to remain in the first position.

				e.SignatureHashAlgorithms = append([]signaturehash.Algorithm(nil), e.SignatureHashAlgorithms...)
				PRNG.Shuffle(len(e.SignatureHashAlgorithms)-1, func(i, j int) {
					e.SignatureHashAlgorithms[i+1], e.SignatureHashAlgorithms[j+1] =
						e.SignatureHashAlgorithms[j+1], e.SignatureHashAlgorithms[i+1]
				})
				e.SignatureHashAlgorithms = e.SignatureHashAlgorithms[:cut(len(e.SignatureHashAlgorithms))]

			case *extension.SupportedEllipticCurves:

				e.EllipticCurves = append([]elliptic.Curve(nil), e.EllipticCurves...)
				PRNG.Shuffle(len(e.EllipticCurves), func(i, j int) {
					e.EllipticCurves[i], e.EllipticCurves[j] =
						e.EllipticCurves[j], e.EllipticCurves[i]
				})
				e.EllipticCurves = e.EllipticCurves[:cut(len(e.EllipticCurves))]

			case *extension.SupportedPointFormats:

				e.PointFormats = append([]elliptic.CurvePointFormat(nil), e.PointFormats...)
				PRNG.Shuffle(len(e.PointFormats), func(i, j int) {
					e.PointFormats[i], e.PointFormats[j] =
						e.PointFormats[j], e.PointFormats[i]
				})
				e.PointFormats = e.PointFormats[:cut(len(e.PointFormats))]

			case *extension.UseSRTP:

				e.ProtectionProfiles = append([]SRTPProtectionProfile(nil), e.ProtectionProfiles...)
				PRNG.Shuffle(len(e.ProtectionProfiles), func(i, j int) {
					e.ProtectionProfiles[i], e.ProtectionProfiles[j] =
						e.ProtectionProfiles[j], e.ProtectionProfiles[i]
				})
				e.ProtectionProfiles = e.ProtectionProfiles[:cut(len(e.ProtectionProfiles))]
			}
		}

		PRNG.Shuffle(len(extensions), func(i, j int) {
			extensions[i], extensions[j] = extensions[j], extensions[i]
		})
	}

	return []*packet{
		{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageClientHello{
						Version:            protocol.Version1_2,
						SessionID:          state.SessionID,
						Cookie:             state.cookie,
						Random:             state.localRandom,
						CipherSuiteIDs:     cipherSuites,
						CompressionMethods: defaultCompressionMethods(),
						Extensions:         extensions,
					},
				},
			},
		},
	}, nil, nil
}
