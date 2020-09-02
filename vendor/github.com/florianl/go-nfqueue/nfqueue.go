package nfqueue

import (
	"context"
	"encoding/binary"
	"log"

	"github.com/florianl/go-nfqueue/internal/unix"

	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
)

// devNull satisfies io.Writer, in case *log.Logger is not provided
type devNull struct{}

func (devNull) Write(p []byte) (int, error) {
	return 0, nil
}

// Close the connection to the netfilter queue subsystem
func (nfqueue *Nfqueue) Close() error {
	return nfqueue.Con.Close()
}

// SetVerdictWithMark signals the kernel the next action and the mark for a specified package id
func (nfqueue *Nfqueue) SetVerdictWithMark(id uint32, verdict, mark int) error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(mark))
	attributes, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: nfQaMark,
		Data: buf,
	}})
	if err != nil {
		return err
	}
	return nfqueue.setVerdict(id, verdict, false, attributes)
}

// SetVerdictModPacket signals the kernel the next action for an altered packet
func (nfqueue *Nfqueue) SetVerdictModPacket(id uint32, verdict int, packet []byte) error {
	data, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: nfQaPayload,
		Data: packet,
	}})
	if err != nil {
		return err
	}
	return nfqueue.setVerdict(id, verdict, false, data)
}

// SetVerdictModPacketWithMark signals the kernel the next action and mark for an altered packet
func (nfqueue *Nfqueue) SetVerdictModPacketWithMark(id uint32, verdict, mark int, packet []byte) error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(mark))
	data, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: nfQaPayload,
		Data: packet,
	},
		{Type: nfQaMark,
			Data: buf}})
	if err != nil {
		return err
	}
	return nfqueue.setVerdict(id, verdict, false, data)
}

// SetVerdict signals the kernel the next action for a specified package id
func (nfqueue *Nfqueue) SetVerdict(id uint32, verdict int) error {
	return nfqueue.setVerdict(id, verdict, false, []byte{})
}

// SetVerdictBatch signals the kernel the next action for a batch of packages till id
func (nfqueue *Nfqueue) SetVerdictBatch(id uint32, verdict int) error {
	return nfqueue.setVerdict(id, verdict, true, []byte{})
}

// Register your own function as callback for a netfilter queue
func (nfqueue *Nfqueue) Register(ctx context.Context, fn HookFunc) error {
	return nfqueue.RegisterWithErrorFunc(ctx, fn, func(err error) int {
		if opError, ok := err.(*netlink.OpError); ok {
			if opError.Timeout() || opError.Temporary() {
				return 0
			}
		}
		nfqueue.logger.Printf("Could not receive message: %v\n", err)
		return 1
	})
}

// RegisterWithErrorFunc is like Register but allows custom error handling
// for errors encountered when reading from the underlying netlink socket.
func (nfqueue *Nfqueue) RegisterWithErrorFunc(ctx context.Context, fn HookFunc, errfn ErrorFunc) error {
	// unbinding existing handler (if any)
	seq, err := nfqueue.setConfig(unix.AF_UNSPEC, 0, 0, []netlink.Attribute{
		{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdPfUnbind, 0x0, 0x0, byte(nfqueue.family)}},
	})
	if err != nil {
		return errors.Wrapf(err, "Could not unbind existing handlers (if any)")
	}

	// binding to family
	_, err = nfqueue.setConfig(unix.AF_UNSPEC, seq, 0, []netlink.Attribute{
		{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdPfBind, 0x0, 0x0, byte(nfqueue.family)}},
	})
	if err != nil {
		return errors.Wrapf(err, "Could not bind to family %d", nfqueue.family)
	}

	// binding to the requested queue
	_, err = nfqueue.setConfig(uint8(unix.AF_UNSPEC), seq, nfqueue.queue, []netlink.Attribute{
		{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdBind, 0x0, 0x0, byte(nfqueue.family)}},
	})
	if err != nil {
		return errors.Wrapf(err, "Could not bind to requested queue %d", nfqueue.queue)
	}

	// set copy mode and buffer size
	data := append(nfqueue.maxPacketLen, nfqueue.copymode)
	_, err = nfqueue.setConfig(uint8(unix.AF_UNSPEC), seq, nfqueue.queue, []netlink.Attribute{
		{Type: nfQaCfgParams, Data: data},
	})
	if err != nil {
		return err
	}

	var attrs []netlink.Attribute
	if nfqueue.flags[0] != 0 || nfqueue.flags[1] != 0 || nfqueue.flags[2] != 0 || nfqueue.flags[3] != 0 {
		// set flags
		attrs = append(attrs, netlink.Attribute{Type: nfQaCfgFlags, Data: nfqueue.flags})
		attrs = append(attrs, netlink.Attribute{Type: nfQaCfgMask, Data: nfqueue.flags})
	}
	attrs = append(attrs, netlink.Attribute{Type: nfQaCfgQueueMaxLen, Data: nfqueue.maxQueueLen})

	_, err = nfqueue.setConfig(uint8(unix.AF_UNSPEC), seq, nfqueue.queue, attrs)
	if err != nil {
		return err
	}

	go nfqueue.socketCallback(ctx, fn, errfn, seq)

	return nil
}

// /include/uapi/linux/netfilter/nfnetlink.h:struct nfgenmsg{} res_id is Big Endian
func putExtraHeader(familiy, version uint8, resid uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, resid)
	return append([]byte{familiy, version}, buf...)
}

func (nfqueue *Nfqueue) setConfig(afFamily uint8, oseq uint32, resid uint16, attrs []netlink.Attribute) (uint32, error) {
	cmd, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return 0, err
	}
	data := putExtraHeader(afFamily, unix.NFNETLINK_V0, resid)
	data = append(data, cmd...)
	req := netlink.Message{
		Header: netlink.Header{
			Type:     netlink.HeaderType((nfnlSubSysQueue << 8) | nfQnlMsgConfig),
			Flags:    netlink.Request | netlink.Acknowledge,
			Sequence: oseq,
		},
		Data: data,
	}
	return nfqueue.execute(req)
}

func (nfqueue *Nfqueue) execute(req netlink.Message) (uint32, error) {
	var seq uint32

	reply, e := nfqueue.Con.Execute(req)
	if e != nil {
		return 0, e
	}

	if e := netlink.Validate(req, reply); e != nil {
		return 0, e
	}
	for _, msg := range reply {
		if seq != 0 {
			return 0, errors.Wrapf(ErrUnexpMsg, "Number of received messages: %d", len(reply))
		}
		seq = msg.Header.Sequence
	}

	return seq, nil
}

func parseMsg(log *log.Logger, msg netlink.Message) (Attribute, error) {
	a, err := extractAttributes(log, msg.Data)
	if err != nil {
		return a, err
	}
	return a, nil
}
