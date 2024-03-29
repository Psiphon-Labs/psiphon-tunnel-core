package crypto

import (
	"errors"
	"strings"

	tls "github.com/Psiphon-Labs/psiphon-tls"
)

// A CertChain holds a certificate and a private key
type CertChain interface {
	SignServerProof(sni string, chlo []byte, serverConfigData []byte) ([]byte, error)
	GetCertsCompressed(sni string, commonSetHashes, cachedHashes []byte) ([]byte, error)
	GetLeafCert(sni string) ([]byte, error)
}

// proofSource stores a key and a certificate for the server proof
type certChain struct {
	config *tls.Config
}

var _ CertChain = &certChain{}

var errNoMatchingCertificate = errors.New("no matching certificate found")

// NewCertChain loads the key and cert from files
func NewCertChain(tlsConfig *tls.Config) CertChain {
	return &certChain{config: tlsConfig}
}

// SignServerProof signs CHLO and server config for use in the server proof
func (c *certChain) SignServerProof(sni string, chlo []byte, serverConfigData []byte) ([]byte, error) {
	cert, err := c.getCertForSNI(sni)
	if err != nil {
		return nil, err
	}

	return signServerProof(cert, chlo, serverConfigData)
}

// GetCertsCompressed gets the certificate in the format described by the QUIC crypto doc
func (c *certChain) GetCertsCompressed(sni string, pCommonSetHashes, pCachedHashes []byte) ([]byte, error) {
	cert, err := c.getCertForSNI(sni)
	if err != nil {
		return nil, err
	}
	return getCompressedCert(cert.Certificate, pCommonSetHashes, pCachedHashes)
}

// GetLeafCert gets the leaf certificate
func (c *certChain) GetLeafCert(sni string) ([]byte, error) {
	cert, err := c.getCertForSNI(sni)
	if err != nil {
		return nil, err
	}
	return cert.Certificate[0], nil
}

func (c *certChain) getCertForSNI(sni string) (*tls.Certificate, error) {
	conf, err := maybeGetConfigForClient(c.config, sni)
	if err != nil {
		return nil, err
	}
	// The rest of this function is mostly copied from crypto/tls.getCertificate

	if conf.GetCertificate != nil {
		cert, err := conf.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		if cert != nil || err != nil {
			return cert, err
		}
	}

	if len(conf.Certificates) == 0 {
		return nil, errNoMatchingCertificate
	}

	if len(conf.Certificates) == 1 || conf.NameToCertificate == nil {
		// There's only one choice, so no point doing any work.
		return &conf.Certificates[0], nil
	}

	name := strings.ToLower(sni)
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	if cert, ok := conf.NameToCertificate[name]; ok {
		return cert, nil
	}

	// try replacing labels in the name with wildcards until we get a
	// match.
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if cert, ok := conf.NameToCertificate[candidate]; ok {
			return cert, nil
		}
	}

	// If nothing matches, return the first certificate.
	return &conf.Certificates[0], nil
}

func maybeGetConfigForClient(c *tls.Config, sni string) (*tls.Config, error) {
	if c.GetConfigForClient == nil {
		return c, nil
	}
	confForClient, err := c.GetConfigForClient(&tls.ClientHelloInfo{ServerName: sni})
	if err != nil {
		return nil, err
	}
	// if GetConfigForClient returns nil, use the original config
	if confForClient == nil {
		return c, nil
	}
	return confForClient, nil
}
