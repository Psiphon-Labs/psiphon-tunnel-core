package tdproto

// Package tdproto, in addition to generated functions, has some manual extensions.

import (
	"encoding/binary"
	"net"
)

// InitTLSDecoySpec creates TLSDecoySpec from ip address and server name.
// Other feilds, such as Pubkey, Timeout and Tcpwin are left unset.

// InitTLSDecoySpec creates TLSDecoySpec from ip address and server name.
// Other feilds, such as Pubkey, Timeout and Tcpwin are left unset.
func InitTLSDecoySpec(ip string, sni string) *TLSDecoySpec {
	_ip := net.ParseIP(ip)
	var ipUint32 *uint32
	var ipv6Bytes []byte
	if _ip.To4() != nil {
		ipUint32 = new(uint32)
		*ipUint32 = binary.BigEndian.Uint32(net.ParseIP(ip).To4())
	} else if _ip.To16() != nil  {
		ipv6Bytes = _ip
	}
	tlsDecoy := TLSDecoySpec{Hostname: &sni, Ipv4Addr: ipUint32, Ipv6Addr: ipv6Bytes}
	return &tlsDecoy
}

// GetIpAddrStr returns IP address of TLSDecoySpec as a string.
func (ds *TLSDecoySpec) GetIpAddrStr() string {
	if ds.Ipv4Addr != nil {
		_ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(_ip, ds.GetIpv4Addr())
		return net.JoinHostPort(_ip.To4().String(), "443")
	}
	if ds.Ipv6Addr != nil {
		return net.JoinHostPort(net.IP(ds.Ipv6Addr).String(), "443")
	}
	return ""
}
