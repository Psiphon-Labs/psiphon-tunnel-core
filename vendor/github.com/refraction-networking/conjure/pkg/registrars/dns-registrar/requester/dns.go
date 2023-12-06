package requester

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"log"
	"net"

	"github.com/refraction-networking/conjure/pkg/registrars/dns-registrar/dns"
	"github.com/refraction-networking/conjure/pkg/registrars/dns-registrar/queuepacketconn"
)

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// DNSPacketConn provides a packet-sending and -receiving interface over various
// forms of DNS. It handles the details of how packets and padding are encoded
// as a DNS name in the Question section of an upstream query, and as a TXT RR
// in downstream responses.
//
// DNSPacketConn does not handle the mechanics of actually sending and receiving
// encoded DNS messages. That is rather the responsibility of some other
// net.PacketConn such as net.UDPConn, HTTPPacketConn, or TLSPacketConn, one of
// which must be provided to NewDNSPacketConn.
type DNSPacketConn struct {
	domain dns.Name
	// QueuePacketConn is the direct receiver of ReadFrom and WriteTo calls.
	// recvLoop and sendLoop take the messages out of the receive and send
	// queues and actually put them on the network.
	*queuepacketconn.QueuePacketConn
}

// NewDNSPacketConn creates a new DNSPacketConn. transport, through its WriteTo
// and ReadFrom methods, handles the actual sending and receiving the DNS
// messages encoded by DNSPacketConn. addr is the address to be passed to
// transport.WriteTo whenever a message needs to be sent.
func NewDNSPacketConn(transport net.Conn, addr net.Addr, domain dns.Name) *DNSPacketConn {
	// Generate a new random ClientID.
	c := &DNSPacketConn{
		domain:          domain,
		QueuePacketConn: queuepacketconn.NewQueuePacketConn(queuepacketconn.DummyAddr{}, 0),
	}
	go func() {
		err := c.recvLoop(transport)
		if err != nil {
			log.Printf("recvLoop: %v", err)
		}
	}()
	go func() {
		err := c.sendLoop(transport, addr)
		if err != nil {
			log.Printf("sendLoop: %v", err)
		}
	}()
	return c
}

// dnsResponsePayload extracts the downstream payload of a DNS response, encoded
// into the RDATA of a TXT RR. It returns nil if the message doesn't pass format
// checks, or if the name in its Question entry is not a subdomain of domain.
func dnsResponsePayload(resp *dns.Message, domain dns.Name) []byte {
	if resp.Flags&0x8000 != 0x8000 {
		// QR != 1, this is not a response.
		return nil
	}
	if resp.Flags&0x000f != dns.RcodeNoError {
		return nil
	}

	if len(resp.Answer) != 1 {
		return nil
	}
	answer := resp.Answer[0]

	_, ok := answer.Name.TrimSuffix(domain)
	if !ok {
		// Not the name we are expecting.
		return nil
	}

	if answer.Type != dns.RRTypeTXT {
		// We only support TYPE == TXT.
		return nil
	}
	payload, err := dns.DecodeRDataTXT(answer.Data)
	if err != nil {
		return nil
	}

	return payload
}

// recvLoop repeatedly calls transport.ReadFrom to receive a DNS message,
// extracts its payload and breaks it into packets, and stores the packets in a
// queue to be returned from a future call to c.ReadFrom.
func (c *DNSPacketConn) recvLoop(transport net.Conn) error {
	for {
		var buf [4096]byte
		n, err := transport.Read(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok {
				log.Printf("ReadFrom error: %v", err)
				continue
			}
			return err
		}

		// Got a response. Try to parse it as a DNS message.
		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Printf("MessageFromWireFormat: %v", err)
			continue
		}

		payload := dnsResponsePayload(&resp, c.domain)

		c.QueuePacketConn.QueueIncoming(payload, transport.RemoteAddr())
	}
}

// chunks breaks p into non-empty subslices of at most n bytes, greedily so that
// only final subslice has length < n.
func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

// send sends p as a single packet encoded into a DNS query, using
// transport.WriteTo(query, addr). The length of p must be less than 224 bytes.
//
//  0. Start with the raw packet contents.
//     supercalifragilisticexpialidocious
//  1. Base32-encode, without padding and in lower case.
//     ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3djmrxwg2lpovzq
//  2. Break into labels of at most 63 octets.
//     ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3d.jmrxwg2lpovzq
//  3. Append the domain.
//     ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3d.jmrxwg2lpovzq.t.example.com
func (c *DNSPacketConn) send(transport net.Conn, p []byte) error {
	encoded := make([]byte, base32Encoding.EncodedLen(len(p)))
	base32Encoding.Encode(encoded, p)
	encoded = bytes.ToLower(encoded)
	labels := chunks(encoded, 63)
	labels = append(labels, c.domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}

	var id uint16
	err = binary.Read(rand.Reader, binary.BigEndian, &id)
	if err != nil {
		return err
	}

	query := &dns.Message{
		ID:    id,
		Flags: 0x0100, // QR = 0, RD = 1
		Question: []dns.Question{
			{
				Name:  name,
				Type:  dns.RRTypeTXT,
				Class: dns.ClassIN,
			},
		},
		// EDNS(0)
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: 4096, // requester's UDP payload size
				TTL:   0,    // extended RCODE and flags
				Data:  []byte{},
			},
		},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return err
	}

	_, err = transport.Write(buf)
	return err
}

// sendLoop takes packets that have been written using c.WriteTo, and sends them
// on the network using send. It also does polling with empty packets when
// requested by pollChan or after a timeout.
func (c *DNSPacketConn) sendLoop(transport net.Conn, addr net.Addr) error {
	for {
		var p []byte
		outgoing := c.QueuePacketConn.OutgoingQueue(addr)
		// Prioritize sending an actual data packet from outgoing. Only
		// consider a poll when outgoing is empty.
		p = <-outgoing

		// Unlike in the server, in the client we assume that because
		// the data capacity of queries is so limited, it's not worth
		// trying to send more than one packet per query.
		err := c.send(transport, p)
		if err != nil {
			log.Printf("send: %v", err)
			continue
		}
	}
}
