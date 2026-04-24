// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package nack

import (
	"math/rand"
	"slices"
	"sync"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/logging"
	"github.com/pion/rtcp"
)

// GeneratorInterceptorFactory is a interceptor.Factory for a GeneratorInterceptor.
type GeneratorInterceptorFactory struct {
	opts []GeneratorOption
}

// NewInterceptor constructs a new ReceiverInterceptor.
func (g *GeneratorInterceptorFactory) NewInterceptor(_ string) (interceptor.Interceptor, error) {
	generatorInterceptor := &GeneratorInterceptor{
		streamsFilter:     streamSupportNack,
		size:              512,
		skipLastN:         0,
		maxNacksPerPacket: 0,
		interval:          time.Millisecond * 100,
		receiveLogs:       map[uint32]*receiveLog{},
		nackCountLogs:     map[uint32]map[uint16]uint16{},
		close:             make(chan struct{}),
	}

	for _, opt := range g.opts {
		if err := opt(generatorInterceptor); err != nil {
			return nil, err
		}
	}

	if generatorInterceptor.loggerFactory == nil {
		generatorInterceptor.loggerFactory = logging.NewDefaultLoggerFactory()
	}
	if generatorInterceptor.log == nil {
		generatorInterceptor.log = generatorInterceptor.loggerFactory.NewLogger("nack_generator")
	}

	if _, err := newReceiveLog(generatorInterceptor.size); err != nil {
		return nil, err
	}

	return generatorInterceptor, nil
}

// GeneratorInterceptor interceptor generates nack feedback messages.
type GeneratorInterceptor struct {
	interceptor.NoOp
	streamsFilter     func(info *interceptor.StreamInfo) bool
	size              uint16
	skipLastN         uint16
	maxNacksPerPacket uint16
	interval          time.Duration
	m                 sync.Mutex
	wg                sync.WaitGroup
	close             chan struct{}
	log               logging.LeveledLogger
	loggerFactory     logging.LoggerFactory
	nackCountLogs     map[uint32]map[uint16]uint16

	receiveLogs   map[uint32]*receiveLog
	receiveLogsMu sync.Mutex
}

// NewGeneratorInterceptor returns a new GeneratorInterceptorFactory.
func NewGeneratorInterceptor(opts ...GeneratorOption) (*GeneratorInterceptorFactory, error) {
	return &GeneratorInterceptorFactory{opts}, nil
}

// BindRTCPWriter lets you modify any outgoing RTCP packets. It is called once per PeerConnection.
// The returned method will be called once per packet batch.
func (n *GeneratorInterceptor) BindRTCPWriter(writer interceptor.RTCPWriter) interceptor.RTCPWriter {
	n.m.Lock()
	defer n.m.Unlock()

	if n.isClosed() {
		return writer
	}

	n.wg.Add(1)

	go n.loop(writer)

	return writer
}

// BindRemoteStream lets you modify any incoming RTP packets. It is called once for per RemoteStream.
// The returned method will be called once per rtp packet.
func (n *GeneratorInterceptor) BindRemoteStream(
	info *interceptor.StreamInfo, reader interceptor.RTPReader,
) interceptor.RTPReader {
	if !n.streamsFilter(info) {
		return reader
	}

	// error is already checked in NewGeneratorInterceptor
	receiveLog, _ := newReceiveLog(n.size)
	n.receiveLogsMu.Lock()
	n.receiveLogs[info.SSRC] = receiveLog
	n.receiveLogsMu.Unlock()

	return interceptor.RTPReaderFunc(func(b []byte, a interceptor.Attributes) (int, interceptor.Attributes, error) {
		i, attr, err := reader.Read(b, a)
		if err != nil {
			return 0, nil, err
		}

		if attr == nil {
			attr = make(interceptor.Attributes)
		}
		header, err := attr.GetRTPHeader(b[:i])
		if err != nil {
			return 0, nil, err
		}
		receiveLog.add(header.SequenceNumber)

		return i, attr, nil
	})
}

// UnbindRemoteStream is called when the Stream is removed. It can be used to clean up any data related to that track.
func (n *GeneratorInterceptor) UnbindRemoteStream(info *interceptor.StreamInfo) {
	n.receiveLogsMu.Lock()
	delete(n.receiveLogs, info.SSRC)
	// the count logs must also be dropped for the specific SSRC.
	delete(n.nackCountLogs, info.SSRC)
	n.receiveLogsMu.Unlock()
}

// Close closes the interceptor.
func (n *GeneratorInterceptor) Close() error {
	defer n.wg.Wait()
	n.m.Lock()
	defer n.m.Unlock()

	if !n.isClosed() {
		close(n.close)
	}

	return nil
}

// nolint:gocognit,cyclop
func (n *GeneratorInterceptor) loop(rtcpWriter interceptor.RTCPWriter) {
	defer n.wg.Done()

	senderSSRC := rand.Uint32() // #nosec

	missingPacketSeqNums := make([]uint16, n.size)
	filteredMissingPacket := make([]uint16, n.size)

	ticker := time.NewTicker(n.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// save NACKs to send without holding the mutex during Write
			var toSend []rtcp.Packet

			n.receiveLogsMu.Lock()
			for ssrc, receiveLog := range n.receiveLogs {
				missing := receiveLog.missingSeqNumbers(n.skipLastN, missingPacketSeqNums)

				if len(missing) == 0 || n.nackCountLogs[ssrc] == nil {
					n.nackCountLogs[ssrc] = map[uint16]uint16{}
				}
				if len(missing) == 0 {
					continue
				}

				var nack *rtcp.TransportLayerNack

				count := 0
				if n.maxNacksPerPacket > 0 {
					for _, missingSeq := range missing {
						if n.nackCountLogs[ssrc][missingSeq] < n.maxNacksPerPacket {
							filteredMissingPacket[count] = missingSeq
							count++
						}
						n.nackCountLogs[ssrc][missingSeq]++
					}

					if count == 0 {
						continue
					}

					nack = &rtcp.TransportLayerNack{
						SenderSSRC: senderSSRC,
						MediaSSRC:  ssrc,
						Nacks:      rtcp.NackPairsFromSequenceNumbers(filteredMissingPacket[:count]),
					}
				} else {
					nack = &rtcp.TransportLayerNack{
						SenderSSRC: senderSSRC,
						MediaSSRC:  ssrc,
						Nacks:      rtcp.NackPairsFromSequenceNumbers(missing),
					}
				}

				for nackSeq := range n.nackCountLogs[ssrc] {
					if !slices.Contains(missing, nackSeq) {
						delete(n.nackCountLogs[ssrc], nackSeq)
					}
				}

				// clean up the count log for the ssrc if it's empty
				if len(n.nackCountLogs[ssrc]) == 0 {
					delete(n.nackCountLogs, ssrc)
				}

				toSend = append(toSend, nack)
			}
			n.receiveLogsMu.Unlock()

			// send RTCP without holding receiveLogsMu
			for _, pkt := range toSend {
				if _, err := rtcpWriter.Write([]rtcp.Packet{pkt}, interceptor.Attributes{}); err != nil {
					n.log.Warnf("failed sending nack: %+v", err)
				}
			}

		case <-n.close:
			return
		}
	}
}

func (n *GeneratorInterceptor) isClosed() bool {
	select {
	case <-n.close:
		return true
	default:
		return false
	}
}
