// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package stats provides an interceptor that records RTP/RTCP stream statistics
package stats

import (
	"sync"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/logging"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
)

// Option can be used to configure the stats interceptor.
type Option func(*Interceptor) error

// SetRecorderFactory sets the factory that is used to create new stats
// recorders for new streams.
func SetRecorderFactory(f RecorderFactory) Option {
	return func(i *Interceptor) error {
		i.RecorderFactory = f

		return nil
	}
}

// SetNowFunc sets the function the interceptor uses to get a current timestamp.
// This is mostly useful for testing.
func SetNowFunc(now func() time.Time) Option {
	return func(i *Interceptor) error {
		i.now = now

		return nil
	}
}

// WithLoggerFactory sets the logger factory for the interceptor.
func WithLoggerFactory(loggerFactory logging.LoggerFactory) Option {
	return func(i *Interceptor) error {
		i.loggerFactory = loggerFactory

		return nil
	}
}

// Getter returns the most recent stats of a stream.
type Getter interface {
	Get(ssrc uint32) *Stats
}

// NewPeerConnectionCallback receives a new StatsGetter for a newly created
// PeerConnection.
type NewPeerConnectionCallback func(string, Getter)

// InterceptorFactory is a interceptor.Factory for a stats Interceptor.
type InterceptorFactory struct {
	opts              []Option
	addPeerConnection NewPeerConnectionCallback
}

// NewInterceptor creates a new InterceptorFactory.
func NewInterceptor(opts ...Option) (*InterceptorFactory, error) {
	return &InterceptorFactory{
		opts:              opts,
		addPeerConnection: nil,
	}, nil
}

// OnNewPeerConnection sets the callback that is called when a new
// PeerConnection is created.
func (r *InterceptorFactory) OnNewPeerConnection(cb NewPeerConnectionCallback) {
	r.addPeerConnection = cb
}

// NewInterceptor creates a new Interceptor.
func (r *InterceptorFactory) NewInterceptor(id string) (interceptor.Interceptor, error) {
	interceptor := &Interceptor{
		NoOp:      interceptor.NoOp{},
		now:       time.Now,
		lock:      sync.Mutex{},
		recorders: map[uint32]Recorder{},
		wg:        sync.WaitGroup{},
	}
	for _, opt := range r.opts {
		if err := opt(interceptor); err != nil {
			return nil, err
		}
	}

	if interceptor.loggerFactory == nil {
		interceptor.loggerFactory = logging.NewDefaultLoggerFactory()
	}
	if interceptor.RecorderFactory == nil {
		interceptor.RecorderFactory = func(ssrc uint32, clockRate float64) Recorder {
			return newRecorder(ssrc, clockRate, interceptor.loggerFactory)
		}
	}

	if r.addPeerConnection != nil {
		r.addPeerConnection(id, interceptor)
	}

	return interceptor, nil
}

// Recorder is the interface of a statistics recorder.
type Recorder interface {
	QueueIncomingRTP(ts time.Time, buf []byte, attr interceptor.Attributes)
	QueueIncomingRTCP(ts time.Time, buf []byte, attr interceptor.Attributes)
	QueueOutgoingRTP(ts time.Time, header *rtp.Header, payload []byte, attr interceptor.Attributes)
	QueueOutgoingRTCP(ts time.Time, pkts []rtcp.Packet, attr interceptor.Attributes)
	GetStats() Stats
	Stop()
	Start()
}

// RecorderFactory creates new Recorders to be used by the interceptor.
type RecorderFactory func(ssrc uint32, clockRate float64) Recorder

// Interceptor is the interceptor that collects stream stats.
type Interceptor struct {
	interceptor.NoOp
	now             func() time.Time
	lock            sync.Mutex
	RecorderFactory RecorderFactory
	recorders       map[uint32]Recorder
	wg              sync.WaitGroup
	loggerFactory   logging.LoggerFactory
}

// Get returns the statistics for the stream with ssrc.
func (r *Interceptor) Get(ssrc uint32) *Stats {
	r.lock.Lock()
	defer r.lock.Unlock()
	if rec, ok := r.recorders[ssrc]; ok {
		stats := rec.GetStats()

		return &stats
	}

	return nil
}

func (r *Interceptor) getRecorder(ssrc uint32, clockRate float64) Recorder {
	r.lock.Lock()
	defer r.lock.Unlock()
	if rec, ok := r.recorders[ssrc]; ok {
		return rec
	}
	rec := r.RecorderFactory(ssrc, clockRate)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		rec.Start()
	}()
	r.recorders[ssrc] = rec

	return rec
}

// Close closes the interceptor and associated stats recorders.
func (r *Interceptor) Close() error {
	defer r.wg.Wait()

	r.lock.Lock()
	defer r.lock.Unlock()

	for _, r := range r.recorders {
		r.Stop()
	}

	return nil
}

// BindRTCPReader lets you modify any incoming RTCP packets. It is called once per sender/receiver, however this might
// change in the future. The returned method will be called once per packet batch.
func (r *Interceptor) BindRTCPReader(reader interceptor.RTCPReader) interceptor.RTCPReader {
	return interceptor.RTCPReaderFunc(
		func(bytes []byte, attributes interceptor.Attributes) (int, interceptor.Attributes, error) {
			n, attattributes, err := reader.Read(bytes, attributes)
			if err != nil {
				return 0, attattributes, err
			}
			r.lock.Lock()
			for _, recorder := range r.recorders {
				recorder.QueueIncomingRTCP(r.now(), bytes[:n], attributes)
			}
			r.lock.Unlock()

			return n, attattributes, err
		},
	)
}

// BindRTCPWriter lets you modify any outgoing RTCP packets. It is called once per PeerConnection. The returned method
// will be called once per packet batch.
func (r *Interceptor) BindRTCPWriter(writer interceptor.RTCPWriter) interceptor.RTCPWriter {
	return interceptor.RTCPWriterFunc(func(pkts []rtcp.Packet, attributes interceptor.Attributes) (int, error) {
		r.lock.Lock()
		for _, recorder := range r.recorders {
			recorder.QueueOutgoingRTCP(r.now(), pkts, attributes)
		}
		r.lock.Unlock()

		return writer.Write(pkts, attributes)
	})
}

// BindLocalStream lets you modify any outgoing RTP packets. It is called once for per LocalStream.
// The returned method will be called once per rtp packet.
func (r *Interceptor) BindLocalStream(
	info *interceptor.StreamInfo, writer interceptor.RTPWriter,
) interceptor.RTPWriter {
	recorder := r.getRecorder(info.SSRC, float64(info.ClockRate))

	return interceptor.RTPWriterFunc(
		func(header *rtp.Header, payload []byte, attributes interceptor.Attributes) (int, error) {
			recorder.QueueOutgoingRTP(r.now(), header, payload, attributes)

			return writer.Write(header, payload, attributes)
		},
	)
}

// BindRemoteStream lets you modify any incoming RTP packets. It is called once for per RemoteStream.
// The returned method will be called once per rtp packet.
func (r *Interceptor) BindRemoteStream(
	info *interceptor.StreamInfo, reader interceptor.RTPReader,
) interceptor.RTPReader {
	recorder := r.getRecorder(info.SSRC, float64(info.ClockRate))

	return interceptor.RTPReaderFunc(
		func(bytes []byte, attributes interceptor.Attributes) (int, interceptor.Attributes, error) {
			n, attributes, err := reader.Read(bytes, attributes)
			if err != nil {
				return 0, nil, err
			}
			recorder.QueueIncomingRTP(r.now(), bytes[:n], attributes)

			return n, attributes, nil
		},
	)
}
