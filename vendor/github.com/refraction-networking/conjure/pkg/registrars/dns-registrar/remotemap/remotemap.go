package remotemap

import (
	"container/heap"
	"net"
	"sync"
	"time"
)

const QueueSize = 128

// remoteRecord is a record of a recently seen remote peer, with the time it was
// last seen and queues of outgoing packets.
type remoteRecord struct {
	Addr     net.Addr
	LastSeen time.Time
	Chan     chan []byte
}

// RemoteMap manages a mapping of live remote peers, keyed by address, to their
// respective send queues. Each peer has two queues: a send queue, and a
// receive queue.
// RemoteMap's functions are safe to call from multiple goroutines.
type RemoteMap struct {
	// We use an inner structure to avoid exposing public heap.Interface
	// functions to users of remoteMap.
	inner remoteMapInner
	// Synchronizes access to inner.
	lock sync.Mutex
}

// NewRemoteMap creates a RemoteMap that expires peers after a timeout.
//
// If the timeout is 0, peers never expire.
func NewRemoteMap(timeout time.Duration) *RemoteMap {
	m := &RemoteMap{
		inner: remoteMapInner{
			byAge:  make([]*remoteRecord, 0),
			byAddr: make(map[string]int),
		},
	}
	if timeout > 0 {
		go func() {
			for {
				time.Sleep(timeout / 2)
				now := time.Now()
				m.lock.Lock()
				m.inner.removeExpired(now, timeout)
				m.lock.Unlock()
			}
		}()
	}
	return m
}

// Returns the send channel corresponding to addr and indicates whether it is a new channel
func (m *RemoteMap) GetChan(addr net.Addr) (chan []byte, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	record, isNewAddr := m.inner.Lookup(addr, time.Now())
	return record.Chan, isNewAddr
}

// Get Channel corresponding to addr
func (m *RemoteMap) Chan(addr net.Addr) chan []byte {
	rv, _ := m.GetChan(addr)
	return rv
}

// remoteMapInner is the inner type of RemoteMap, implementing heap.Interface.
// byAge is the backing store, a heap ordered by LastSeen time, to facilitate
// expiring old records. byAddr is a map from addresses to heap indices, to
// allow looking up by address. Unlike RemoteMap, remoteMapInner requires
// external synchonization.
type remoteMapInner struct {
	byAge  []*remoteRecord
	byAddr map[string]int
}

// removeExpired removes all records whose LastSeen timestamp is more than
// timeout in the past.
func (inner *remoteMapInner) removeExpired(now time.Time, timeout time.Duration) {
	for len(inner.byAge) > 0 && now.Sub(inner.byAge[0].LastSeen) >= timeout {
		record := heap.Pop(inner).(*remoteRecord)
		close(record.Chan)
	}
}

// Lookup finds the existing record corresponding to addr, or creates a new
// one if none exists yet. It updates the record's LastSeen time and returns the
// record.
func (inner *remoteMapInner) Lookup(addr net.Addr, now time.Time) (*remoteRecord, bool) {
	var record *remoteRecord
	i, ok := inner.byAddr[addr.String()]
	if ok {
		// Found one, update its LastSeen.
		record = inner.byAge[i]
		record.LastSeen = now
		heap.Fix(inner, i)
	} else {
		// Not found, create a new one.
		record = &remoteRecord{
			Addr:     addr,
			LastSeen: now,
			Chan:     make(chan []byte, QueueSize),
		}
		heap.Push(inner, record)
		return record, true
	}
	return record, false
}

// heap.Interface for remoteMapInner.

func (inner *remoteMapInner) Len() int {
	if len(inner.byAge) != len(inner.byAddr) {
		panic("inconsistent remoteMap")
	}
	return len(inner.byAge)
}

func (inner *remoteMapInner) Less(i, j int) bool {
	return inner.byAge[i].LastSeen.Before(inner.byAge[j].LastSeen)
}

func (inner *remoteMapInner) Swap(i, j int) {
	inner.byAge[i], inner.byAge[j] = inner.byAge[j], inner.byAge[i]
	inner.byAddr[inner.byAge[i].Addr.String()] = i
	inner.byAddr[inner.byAge[j].Addr.String()] = j
}

func (inner *remoteMapInner) Push(x interface{}) {
	record := x.(*remoteRecord)
	if _, ok := inner.byAddr[record.Addr.String()]; ok {
		panic("duplicate address in remoteMap")
	}
	// Insert into byAddr map.
	inner.byAddr[record.Addr.String()] = len(inner.byAge)
	// Insert into byAge slice.
	inner.byAge = append(inner.byAge, record)
}

func (inner *remoteMapInner) Pop() interface{} {
	n := len(inner.byAddr)
	// Remove from byAge slice.
	record := inner.byAge[n-1]
	inner.byAge[n-1] = nil
	inner.byAge = inner.byAge[:n-1]
	// Remove from byAddr map.
	delete(inner.byAddr, record.Addr.String())
	return record
}
