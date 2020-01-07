package gquic

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic/gquic-go/internal/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic/gquic-go/internal/utils"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic/gquic-go/internal/wire"
)

// The packetHandlerMap stores packetHandlers, identified by connection ID.
// It is used:
// * by the server to store sessions
// * when multiplexing outgoing connections to store clients
type packetHandlerMap struct {
	mutex sync.RWMutex

	conn      net.PacketConn
	connIDLen int

	handlers map[string] /* string(ConnectionID)*/ packetHandler
	server   unknownPacketHandler
	closed   bool

	deleteClosedSessionsAfter time.Duration

	logger utils.Logger
}

var _ packetHandlerManager = &packetHandlerMap{}

func newPacketHandlerMap(conn net.PacketConn, connIDLen int, logger utils.Logger) packetHandlerManager {
	m := &packetHandlerMap{
		conn:                      conn,
		connIDLen:                 connIDLen,
		handlers:                  make(map[string]packetHandler),
		deleteClosedSessionsAfter: protocol.ClosedSessionDeleteTimeout,
		logger:                    logger,
	}
	go m.listen()
	return m
}

func (h *packetHandlerMap) Add(id protocol.ConnectionID, handler packetHandler) {
	h.mutex.Lock()
	h.handlers[string(id)] = handler
	h.mutex.Unlock()
}

func (h *packetHandlerMap) Remove(id protocol.ConnectionID) {
	h.removeByConnectionIDAsString(string(id))
}

func (h *packetHandlerMap) removeByConnectionIDAsString(id string) {
	h.mutex.Lock()
	h.handlers[id] = nil
	h.mutex.Unlock()

	time.AfterFunc(h.deleteClosedSessionsAfter, func() {
		h.mutex.Lock()
		delete(h.handlers, id)
		h.mutex.Unlock()
	})
}

func (h *packetHandlerMap) SetServer(s unknownPacketHandler) {
	h.mutex.Lock()
	h.server = s
	h.mutex.Unlock()
}

func (h *packetHandlerMap) CloseServer() {
	h.mutex.Lock()
	h.server = nil
	var wg sync.WaitGroup
	for id, handler := range h.handlers {
		if handler != nil && handler.GetPerspective() == protocol.PerspectiveServer {
			wg.Add(1)
			go func(id string, handler packetHandler) {
				// session.Close() blocks until the CONNECTION_CLOSE has been sent and the run-loop has stopped
				_ = handler.Close()
				h.removeByConnectionIDAsString(id)
				wg.Done()
			}(id, handler)
		}
	}
	h.mutex.Unlock()
	wg.Wait()
}

func (h *packetHandlerMap) close(e error) error {
	h.mutex.Lock()
	if h.closed {
		h.mutex.Unlock()
		return nil
	}
	h.closed = true

	var wg sync.WaitGroup
	for _, handler := range h.handlers {
		if handler != nil {
			wg.Add(1)
			go func(handler packetHandler) {
				handler.destroy(e)
				wg.Done()
			}(handler)
		}
	}

	// [Psiphon]
	// Call h.server.setCloseError(e) outside of mutex to prevent deadlock
	//
	//    sync.(*RWMutex).Lock
	//    [...]/lucas-clemente/quic-go.(*packetHandlerMap).CloseServer
	//    [...]/lucas-clemente/quic-go.(*server).closeWithMutex
	//    [...]/lucas-clemente/quic-go.(*server).closeWithError
	//    [...]/lucas-clemente/quic-go.(*packetHandlerMap).close
	//    [...]/lucas-clemente/quic-go.(*packetHandlerMap).listen
	//
	//    packetHandlerMap.CloseServer is attempting to lock the same mutex that
	//    is already locked in packetHandlerMap.close, which deadlocks. As
	//    packetHandlerMap and its mutex are used by all client sessions, this
	//    effectively hangs the entire server.

	var server unknownPacketHandler
	if h.server != nil {
		server = h.server
	}

	h.mutex.Unlock()

	if server != nil {
		server.closeWithError(e)
	}

	wg.Wait()
	return nil
}

func (h *packetHandlerMap) listen() {
	for {
		data := *getPacketBuffer()
		data = data[:protocol.MaxReceivePacketSize]
		// The packet size should not exceed protocol.MaxReceivePacketSize bytes
		// If it does, we only read a truncated packet, which will then end up undecryptable
		n, addr, err := h.conn.ReadFrom(data)
		if err != nil {

			// [Psiphon]
			// Do not unconditionally shutdown
			if netErr, ok := err.(net.Error); !ok || !netErr.Temporary() {
				h.close(err)
				return
			}

		}
		data = data[:n]

		if err := h.handlePacket(addr, data); err != nil {
			h.logger.Debugf("error handling packet from %s: %s", addr, err)
		}
	}
}

func (h *packetHandlerMap) handlePacket(addr net.Addr, data []byte) error {
	rcvTime := time.Now()

	r := bytes.NewReader(data)
	iHdr, err := wire.ParseInvariantHeader(r, h.connIDLen)
	// drop the packet if we can't parse the header
	if err != nil {
		return fmt.Errorf("error parsing invariant header: %s", err)
	}

	h.mutex.RLock()
	handler, ok := h.handlers[string(iHdr.DestConnectionID)]
	server := h.server
	h.mutex.RUnlock()

	var sentBy protocol.Perspective
	var version protocol.VersionNumber
	var handlePacket func(*receivedPacket)
	if ok && handler == nil {
		// Late packet for closed session
		return nil
	}
	if !ok {
		if server == nil { // no server set
			return fmt.Errorf("received a packet with an unexpected connection ID %s", iHdr.DestConnectionID)
		}
		handlePacket = server.handlePacket
		sentBy = protocol.PerspectiveClient
		version = iHdr.Version
	} else {
		sentBy = handler.GetPerspective().Opposite()
		version = handler.GetVersion()
		handlePacket = handler.handlePacket
	}

	hdr, err := iHdr.Parse(r, sentBy, version)
	if err != nil {
		return fmt.Errorf("error parsing header: %s", err)
	}
	hdr.Raw = data[:len(data)-r.Len()]
	packetData := data[len(data)-r.Len():]

	if hdr.IsLongHeader && hdr.Version.UsesLengthInHeader() {
		if protocol.ByteCount(len(packetData)) < hdr.PayloadLen {
			return fmt.Errorf("packet payload (%d bytes) is smaller than the expected payload length (%d bytes)", len(packetData), hdr.PayloadLen)
		}
		packetData = packetData[:int(hdr.PayloadLen)]
		// TODO(#1312): implement parsing of compound packets
	}

	handlePacket(&receivedPacket{
		remoteAddr: addr,
		header:     hdr,
		data:       packetData,
		rcvTime:    rcvTime,
	})
	return nil
}
