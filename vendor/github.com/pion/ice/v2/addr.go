package ice

import "net"

func parseMulticastAnswerAddr(in net.Addr) (net.IP, bool) {
	switch addr := in.(type) {
	case *net.IPAddr:
		return addr.IP, true
	case *net.UDPAddr:
		return addr.IP, true
	case *net.TCPAddr:
		return addr.IP, true
	}
	return nil, false
}

func parseAddr(in net.Addr) (net.IP, int, NetworkType, bool) {
	switch addr := in.(type) {
	case *net.UDPAddr:
		return addr.IP, addr.Port, NetworkTypeUDP4, true
	case *net.TCPAddr:
		return addr.IP, addr.Port, NetworkTypeTCP4, true
	}
	return nil, 0, 0, false
}

func createAddr(network NetworkType, ip net.IP, port int) net.Addr {
	switch {
	case network.IsTCP():
		return &net.TCPAddr{IP: ip, Port: port}
	default:
		return &net.UDPAddr{IP: ip, Port: port}
	}
}

func addrEqual(a, b net.Addr) bool {
	aIP, aPort, aType, aOk := parseAddr(a)
	if !aOk {
		return false
	}

	bIP, bPort, bType, bOk := parseAddr(b)
	if !bOk {
		return false
	}

	return aType == bType && aIP.Equal(bIP) && aPort == bPort
}
