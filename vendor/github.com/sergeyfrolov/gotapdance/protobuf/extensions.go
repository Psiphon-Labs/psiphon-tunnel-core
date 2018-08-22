package tdproto

// Package tdproto, in addition to generated functions, has some manual extensions.

import (
	"encoding/binary"
	"net"
)

// InitTLSDecoySpec creates TLSDecoySpec from ip address and server name.
// Other feilds, such as Pubkey, Timeout and Tcpwin are left unset.
func InitTLSDecoySpec(ip string, sni string) *TLSDecoySpec {
	ip4 := net.ParseIP(ip)
	var ipUint32 uint32
	if ip4 != nil {
		ipUint32 = binary.BigEndian.Uint32(net.ParseIP(ip).To4())
	} else {
		ipUint32 = 0
	}
	tlsDecoy := TLSDecoySpec{Hostname: &sni, Ipv4Addr: &ipUint32}
	return &tlsDecoy
}

// GetIpv4AddrStr returns IP address of TLSDecoySpec as a string.
func (ds *TLSDecoySpec) GetIpv4AddrStr() string {
	if ds.Ipv4Addr != nil {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, ds.GetIpv4Addr())
		// TODO: what checks need to be done, and what's guaranteed?
		ipv4Str := ip.To4().String() + ":443"
		return ipv4Str
	}
	return ""
}
