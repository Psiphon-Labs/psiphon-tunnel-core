package requester

import (
	"fmt"
	"net"
)

type Config struct {
	// TransportMethod is the transport method to be used
	TransportMethod TransportMethodType

	// Target is the target addr/url for the recursive DNS server used
	Target string

	// Domain is the base domain for the DNS request that the responder is authoritative for
	BaseDomain string

	// Pubkey is the public key for the listening responder
	Pubkey []byte

	// UtlsDistribution allows utls distribution to be specified for the utls connection used during DoH and DoT
	UtlsDistribution string

	// DialTransport allows for a custom dialer to be used for the underlying TCP/UDP transport
	DialTransport dialFunc
}

// TransportMethodType declares the transport method to be used
type TransportMethodType int

const (
	DoH TransportMethodType = iota
	DoT
	UDP
)

func defaultDialTransport() dialFunc {
	dialer := net.Dialer{}
	return dialer.DialContext
}

func (c *Config) dialTransport() dialFunc {
	if c.DialTransport == nil {
		return defaultDialTransport()
	}
	return c.DialTransport
}

func validateConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("no config provided")
	}

	if config.Target == "" {
		return fmt.Errorf("no target configured")
	}

	if config.BaseDomain == "" {
		return fmt.Errorf("no base domain configured")
	}

	return nil
}
