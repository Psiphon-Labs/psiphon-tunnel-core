package registration

import (
	"fmt"
	"net/http"
	"time"

	"github.com/refraction-networking/gotapdance/tapdance"
)

type Config struct {
	// DNSTransportMethod is the transport method to be used in the DNS registrar
	DNSTransportMethod DNSTransportMethodType

	// Target is the target registration addr/url
	Target string

	// BaseDomain is the base domain for the DNS request that the responder is authoritative for in the DNS registrar
	BaseDomain string

	// Pubkey is the public key for the listening DNS registration server
	Pubkey []byte

	// UTLSDistribution allows utls distribution to be specified for the utls connection used during DoH and DoT in the DNS registrar
	UTLSDistribution string

	// MaxRetries is the max number of retries a registrar will attempt
	MaxRetries int

	// Delay is the delay duration between retries
	//
	// Deprecated: Use tapdance.Dialer.RegDelay instead.
	Delay time.Duration

	// STUNAddr is the address of STUN server used to determine the client's IPv4 address for the DNS registrar
	STUNAddr string

	// Bidirectional sets wether the registrar should be bidirectional or unidirectional
	Bidirectional bool

	// SecondaryRegistrar is the secondary registrar to use when the main one fails
	SecondaryRegistrar tapdance.Registrar

	// HTTPClient is the HTTP client to use for the API registrar
	HTTPClient *http.Client
}

// DNSTransportMethodType declares the DNS transport method to be used
type DNSTransportMethodType int

const (
	DoH DNSTransportMethodType = iota
	DoT
	UDP
)

//nolint:unused
func validateConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("no config provided")
	}

	if config.Target == "" {
		return fmt.Errorf("no target configured")
	}

	return nil
}
