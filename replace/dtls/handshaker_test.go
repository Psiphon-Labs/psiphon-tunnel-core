// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/pion/dtls/v2/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v2/pkg/protocol/alert"
	"github.com/pion/dtls/v2/pkg/protocol/handshake"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
	"github.com/pion/logging"
	"github.com/pion/transport/v2/test"
)

const nonZeroRetransmitInterval = 100 * time.Millisecond

// Test that writes to the key log are in the correct format and only applies
// when a key log writer is given.
func TestWriteKeyLog(t *testing.T) {
	var buf bytes.Buffer
	cfg := handshakeConfig{
		keyLogWriter: &buf,
	}
	cfg.writeKeyLog("LABEL", []byte{0xAA, 0xBB, 0xCC}, []byte{0xDD, 0xEE, 0xFF})

	// Secrets follow the format <Label> <space> <ClientRandom> <space> <Secret>
	// https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
	want := "LABEL aabbcc ddeeff\n"
	if buf.String() != want {
		t.Fatalf("Got %s want %s", buf.String(), want)
	}

	// no key log writer = no writes
	cfg = handshakeConfig{}
	cfg.writeKeyLog("LABEL", []byte{0xAA, 0xBB, 0xCC}, []byte{0xDD, 0xEE, 0xFF})
}

func TestHandshaker(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	loggerFactory := logging.NewDefaultLoggerFactory()
	logger := loggerFactory.NewLogger("dtls")

	cipherSuites, err := parseCipherSuites(nil, nil, true, false)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	genFilters := map[string]func() (TestEndpoint, TestEndpoint, func(t *testing.T)){
		"PassThrough": func() (TestEndpoint, TestEndpoint, func(t *testing.T)) {
			return TestEndpoint{}, TestEndpoint{}, nil
		},

		"HelloVerifyRequestLost": func() (TestEndpoint, TestEndpoint, func(t *testing.T)) {
			var (
				cntHelloVerifyRequest  = 0
				cntClientHelloNoCookie = 0
			)
			const helloVerifyDrop = 5

			clientEndpoint := TestEndpoint{
				Filter: func(p *packet) bool {
					h, ok := p.record.Content.(*handshake.Handshake)
					if !ok {
						return true
					}
					if hmch, ok := h.Message.(*handshake.MessageClientHello); ok {
						if len(hmch.Cookie) == 0 {
							cntClientHelloNoCookie++
						}
					}
					return true
				},
			}

			serverEndpoint := TestEndpoint{
				Filter: func(p *packet) bool {
					h, ok := p.record.Content.(*handshake.Handshake)
					if !ok {
						return true
					}
					if _, ok := h.Message.(*handshake.MessageHelloVerifyRequest); ok {
						cntHelloVerifyRequest++
						return cntHelloVerifyRequest > helloVerifyDrop
					}
					return true
				},
			}

			report := func(t *testing.T) {
				if cntHelloVerifyRequest != helloVerifyDrop+1 {
					t.Errorf("Number of HelloVerifyRequest retransmit is wrong, expected: %d times, got: %d times", helloVerifyDrop+1, cntHelloVerifyRequest)
				}
				if cntClientHelloNoCookie != cntHelloVerifyRequest {
					t.Errorf(
						"HelloVerifyRequest must be triggered only by ClientHello, but HelloVerifyRequest was sent %d times and ClientHello was sent %d times",
						cntHelloVerifyRequest, cntClientHelloNoCookie,
					)
				}
			}

			return clientEndpoint, serverEndpoint, report
		},

		"NoLatencyTest": func() (TestEndpoint, TestEndpoint, func(t *testing.T)) {
			var (
				cntClientFinished = 0
				cntServerFinished = 0
			)

			clientEndpoint := TestEndpoint{
				Filter: func(p *packet) bool {
					h, ok := p.record.Content.(*handshake.Handshake)
					if !ok {
						return true
					}
					if _, ok := h.Message.(*handshake.MessageFinished); ok {
						cntClientFinished++
					}
					return true
				},
			}

			serverEndpoint := TestEndpoint{
				Filter: func(p *packet) bool {
					h, ok := p.record.Content.(*handshake.Handshake)
					if !ok {
						return true
					}
					if _, ok := h.Message.(*handshake.MessageFinished); ok {
						cntServerFinished++
					}
					return true
				},
			}

			report := func(t *testing.T) {
				if cntClientFinished != 1 {
					t.Errorf("Number of client finished is wrong, expected: %d times, got: %d times", 1, cntClientFinished)
				}
				if cntServerFinished != 1 {
					t.Errorf("Number of server finished is wrong, expected: %d times, got: %d times", 1, cntServerFinished)
				}
			}

			return clientEndpoint, serverEndpoint, report
		},

		"SlowServerTest": func() (TestEndpoint, TestEndpoint, func(t *testing.T)) {
			var (
				cntClientFinished               = 0
				isClientFinished                = false
				cntClientFinishedLastRetransmit = 0
				cntServerFinished               = 0
				isServerFinished                = false
				cntServerFinishedLastRetransmit = 0
			)

			clientEndpoint := TestEndpoint{
				Filter: func(p *packet) bool {
					h, ok := p.record.Content.(*handshake.Handshake)
					if !ok {
						return true
					}
					if _, ok := h.Message.(*handshake.MessageFinished); ok {
						if isClientFinished {
							cntClientFinishedLastRetransmit++
						} else {
							cntClientFinished++
						}
					}
					return true
				},
				Delay: 0,
				OnFinished: func() {
					isClientFinished = true
				},
				FinishWait: 2000 * time.Millisecond,
			}

			serverEndpoint := TestEndpoint{
				Filter: func(p *packet) bool {
					h, ok := p.record.Content.(*handshake.Handshake)
					if !ok {
						return true
					}
					if _, ok := h.Message.(*handshake.MessageFinished); ok {
						if isServerFinished {
							cntServerFinishedLastRetransmit++
						} else {
							cntServerFinished++
						}
					}
					return true
				},
				Delay: 1000 * time.Millisecond,
				OnFinished: func() {
					isServerFinished = true
				},
				FinishWait: 2000 * time.Millisecond,
			}

			report := func(t *testing.T) {
				// with one second server delay and 100 ms retransmit, there should be close to 10 `Finished` from client
				// using a range of 9 - 11 for checking
				if cntClientFinished < 8 || cntClientFinished > 11 {
					t.Errorf("Number of client finished is wrong, expected: %d - %d times, got: %d times", 9, 11, cntClientFinished)
				}
				if !isClientFinished {
					t.Errorf("Client is not finished")
				}
				// there should be no `Finished` last retransmit from client
				if cntClientFinishedLastRetransmit != 0 {
					t.Errorf("Number of client finished last retransmit is wrong, expected: %d times, got: %d times", 0, cntClientFinishedLastRetransmit)
				}
				if cntServerFinished < 1 {
					t.Errorf("Number of server finished is wrong, expected: at least %d times, got: %d times", 1, cntServerFinished)
				}
				if !isServerFinished {
					t.Errorf("Server is not finished")
				}
				// there should be `Finished` last retransmit from server. Because of slow server, client would have sent several `Finished`.
				if cntServerFinishedLastRetransmit < 1 {
					t.Errorf("Number of server finished last retransmit is wrong, expected: at least %d times, got: %d times", 1, cntServerFinishedLastRetransmit)
				}
			}

			return clientEndpoint, serverEndpoint, report
		},
	}

	for name, filters := range genFilters {
		clientEndpoint, serverEndpoint, report := filters()
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			if report != nil {
				defer report(t)
			}

			ca, cb := flightTestPipe(ctx, clientEndpoint, serverEndpoint)
			ca.state.isClient = true

			var wg sync.WaitGroup
			wg.Add(2)

			ctxCliFinished, cancelCli := context.WithCancel(ctx)
			ctxSrvFinished, cancelSrv := context.WithCancel(ctx)
			go func() {
				defer wg.Done()
				cfg := &handshakeConfig{
					localCipherSuites:     cipherSuites,
					localCertificates:     []tls.Certificate{clientCert},
					ellipticCurves:        defaultCurves,
					localSignatureSchemes: signaturehash.Algorithms(),
					insecureSkipVerify:    true,
					log:                   logger,
					onFlightState: func(f flightVal, s handshakeState) {
						if s == handshakeFinished {
							if clientEndpoint.OnFinished != nil {
								clientEndpoint.OnFinished()
							}
							time.AfterFunc(clientEndpoint.FinishWait, func() {
								cancelCli()
							})
						}
					},
					retransmitInterval: nonZeroRetransmitInterval,
				}

				fsm := newHandshakeFSM(&ca.state, ca.handshakeCache, cfg, flight1)
				err := fsm.Run(ctx, ca, handshakePreparing)
				switch {
				case errors.Is(err, context.Canceled):
				case errors.Is(err, context.DeadlineExceeded):
					t.Error("Timeout")
				default:
					t.Error(err)
				}
			}()

			go func() {
				defer wg.Done()
				cfg := &handshakeConfig{
					localCipherSuites:     cipherSuites,
					localCertificates:     []tls.Certificate{clientCert},
					ellipticCurves:        defaultCurves,
					localSignatureSchemes: signaturehash.Algorithms(),
					insecureSkipVerify:    true,
					log:                   logger,
					onFlightState: func(f flightVal, s handshakeState) {
						if s == handshakeFinished {
							if serverEndpoint.OnFinished != nil {
								serverEndpoint.OnFinished()
							}
							time.AfterFunc(serverEndpoint.FinishWait, func() {
								cancelSrv()
							})
						}
					},
					retransmitInterval: nonZeroRetransmitInterval,
				}

				fsm := newHandshakeFSM(&cb.state, cb.handshakeCache, cfg, flight0)
				err := fsm.Run(ctx, cb, handshakePreparing)
				switch {
				case errors.Is(err, context.Canceled):
				case errors.Is(err, context.DeadlineExceeded):
					t.Error("Timeout")
				default:
					t.Error(err)
				}
			}()

			<-ctxCliFinished.Done()
			<-ctxSrvFinished.Done()

			cancel()
			wg.Wait()
		})
	}
}

type packetFilter func(p *packet) bool

type TestEndpoint struct {
	Filter     packetFilter
	Delay      time.Duration
	OnFinished func()
	FinishWait time.Duration
}

func flightTestPipe(ctx context.Context, clientEndpoint TestEndpoint, serverEndpoint TestEndpoint) (*flightTestConn, *flightTestConn) {
	ca := newHandshakeCache()
	cb := newHandshakeCache()
	chA := make(chan chan struct{})
	chB := make(chan chan struct{})
	return &flightTestConn{
			handshakeCache: ca,
			otherEndCache:  cb,
			recv:           chA,
			otherEndRecv:   chB,
			done:           ctx.Done(),
			filter:         clientEndpoint.Filter,
			delay:          clientEndpoint.Delay,
		}, &flightTestConn{
			handshakeCache: cb,
			otherEndCache:  ca,
			recv:           chB,
			otherEndRecv:   chA,
			done:           ctx.Done(),
			filter:         serverEndpoint.Filter,
			delay:          serverEndpoint.Delay,
		}
}

type flightTestConn struct {
	state          State
	handshakeCache *handshakeCache
	recv           chan chan struct{}
	done           <-chan struct{}
	epoch          uint16

	filter packetFilter

	delay time.Duration

	otherEndCache *handshakeCache
	otherEndRecv  chan chan struct{}
}

func (c *flightTestConn) recvHandshake() <-chan chan struct{} {
	return c.recv
}

func (c *flightTestConn) setLocalEpoch(epoch uint16) {
	c.epoch = epoch
}

func (c *flightTestConn) notify(context.Context, alert.Level, alert.Description) error {
	return nil
}

func (c *flightTestConn) writePackets(_ context.Context, pkts []*packet) error {
	time.Sleep(c.delay)
	for _, p := range pkts {
		if c.filter != nil && !c.filter(p) {
			continue
		}
		if h, ok := p.record.Content.(*handshake.Handshake); ok {
			handshakeRaw, err := p.record.Marshal()
			if err != nil {
				return err
			}

			c.handshakeCache.push(handshakeRaw[recordlayer.HeaderSize:], p.record.Header.Epoch, h.Header.MessageSequence, h.Header.Type, c.state.isClient)

			content, err := h.Message.Marshal()
			if err != nil {
				return err
			}
			h.Header.Length = uint32(len(content))
			h.Header.FragmentLength = uint32(len(content))
			hdr, err := h.Header.Marshal()
			if err != nil {
				return err
			}
			c.otherEndCache.push(
				append(hdr, content...), p.record.Header.Epoch, h.Header.MessageSequence, h.Header.Type, c.state.isClient)
		}
	}
	go func() {
		select {
		case c.otherEndRecv <- make(chan struct{}):
		case <-c.done:
		}
	}()

	// Avoid deadlock on JS/WASM environment due to context switch problem.
	time.Sleep(10 * time.Millisecond)

	return nil
}

func (c *flightTestConn) handleQueuedPackets(context.Context) error {
	return nil
}

func (c *flightTestConn) sessionKey() []byte {
	return nil
}
