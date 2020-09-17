//+build !go1.12

package nfqueue

import (
	"context"
	"encoding/binary"
	"log"
	"sync"

	"github.com/florianl/go-nfqueue/internal/unix"

	"github.com/mdlayher/netlink"
)

type verdict struct {
	sync.Mutex
	data []netlink.Message
}

// Nfqueue represents a netfilter queue handler
type Nfqueue struct {
	// Con is the pure representation of a netlink socket
	Con *netlink.Conn

	logger *log.Logger

	flags        []byte // uint32
	maxPacketLen []byte // uint32
	family       uint8
	queue        uint16
	maxQueueLen  []byte // uint32
	copymode     uint8

	verdicts verdict
}

// Open a connection to the netfilter queue subsystem
func Open(config *Config) (*Nfqueue, error) {
	var nfqueue Nfqueue

	if config.Flags >= nfQaCfgFlagMax {
		return nil, ErrInvFlag
	}

	con, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: config.NetNS})
	if err != nil {
		return nil, err
	}
	nfqueue.Con = con
	// default size of copied packages to userspace
	nfqueue.maxPacketLen = []byte{0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint32(nfqueue.maxPacketLen, config.MaxPacketLen)
	nfqueue.flags = []byte{0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint32(nfqueue.flags, config.Flags)
	nfqueue.queue = config.NfQueue
	nfqueue.family = config.AfFamily
	nfqueue.maxQueueLen = []byte{0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint32(nfqueue.maxQueueLen, config.MaxQueueLen)
	if config.Logger == nil {
		nfqueue.logger = log.New(new(devNull), "", 0)
	} else {
		nfqueue.logger = config.Logger
	}
	nfqueue.copymode = config.Copymode

	return &nfqueue, nil
}

func (nfqueue *Nfqueue) setVerdict(id uint32, verdict int, batch bool, attributes []byte) error {
	/*
		struct nfqnl_msg_verdict_hdr {
			__be32 verdict;
			__be32 id;
		};
	*/

	if verdict != NfDrop && verdict != NfAccept && verdict != NfStolen && verdict != NfQeueue && verdict != NfRepeat {
		return ErrInvalidVerdict
	}

	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(id))
	verdictData := append([]byte{0x0, 0x0, 0x0, byte(verdict)}, buf...)
	cmd, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nfQaVerdictHdr, Data: verdictData},
	})
	if err != nil {
		return err
	}
	data := putExtraHeader(nfqueue.family, unix.NFNETLINK_V0, nfqueue.queue)
	data = append(data, cmd...)
	data = append(data, attributes...)
	req := netlink.Message{
		Header: netlink.Header{
			Flags:    netlink.Request,
			Sequence: 0,
		},
		Data: data,
	}
	if batch {
		req.Header.Type = netlink.HeaderType((nfnlSubSysQueue << 8) | nfQnlMsgVerdictBatch)
	} else {
		req.Header.Type = netlink.HeaderType((nfnlSubSysQueue << 8) | nfQnlMsgVerdict)
	}

	nfqueue.verdicts.Lock()
	nfqueue.verdicts.data = append(nfqueue.verdicts.data, req)
	nfqueue.verdicts.Unlock()

	return nil

}

func (nfqueue *Nfqueue) sendVerdicts() error {
	nfqueue.verdicts.Lock()
	defer nfqueue.verdicts.Unlock()
	if len(nfqueue.verdicts.data) == 0 {
		return nil
	}
	_, err := nfqueue.Con.SendMessages(nfqueue.verdicts.data)
	if err != nil {
		nfqueue.logger.Printf("Could not send verdict: %v\n", err)
		return err
	}
	nfqueue.verdicts.data = []netlink.Message{}

	return nil
}

func (nfqueue *Nfqueue) socketCallback(ctx context.Context, fn HookFunc, errfn ErrorFunc, seq uint32) {
	defer func() {
		// unbinding from queue
		_, err := nfqueue.setConfig(uint8(unix.AF_UNSPEC), seq, nfqueue.queue, []netlink.Attribute{
			{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdUnbind, 0x0, 0x0, byte(nfqueue.family)}},
		})
		if err != nil {
			nfqueue.logger.Printf("Could not unbind from queue: %v\n", err)
			return
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			nfqueue.logger.Printf("Stop receiving nfqueue messages: %v\n", err)
			return
		}
		if err := nfqueue.sendVerdicts(); err != nil {
			nfqueue.logger.Printf("Could not send verdict(s): %v\n", err)
		}
		replys, err := nfqueue.Con.Receive()
		if err != nil {
			if ret := errfn(err); ret != 0 {
				return
			}
			continue
		}
		for _, msg := range replys {
			if msg.Header.Type == netlink.Done {
				// this is the last message of a batch
				// continue to receive messages
				break
			}
			m, err := parseMsg(nfqueue.logger, msg)
			if err != nil {
				nfqueue.logger.Printf("Could not parse message: %v\n", err)
				continue
			}
			if ret := fn(m); ret != 0 {
				return
			}
		}
	}
}
