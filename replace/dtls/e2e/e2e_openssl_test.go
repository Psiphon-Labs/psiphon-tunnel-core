// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build openssl && !js
// +build openssl,!js

package e2e

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v2"
)

func serverOpenSSL(c *comm) {
	go func() {
		c.serverMutex.Lock()
		defer c.serverMutex.Unlock()

		cfg := c.serverConfig

		// create openssl arguments
		args := []string{
			"s_server",
			"-dtls1_2",
			"-quiet",
			"-verify_quiet",
			"-verify_return_error",
			fmt.Sprintf("-accept=%d", c.serverPort),
		}
		ciphers := ciphersOpenSSL(cfg)
		if ciphers != "" {
			args = append(args, fmt.Sprintf("-cipher=%s", ciphers))
		}

		// psk arguments
		if cfg.PSK != nil {
			psk, err := cfg.PSK(nil)
			if err != nil {
				c.errChan <- err
				return
			}
			args = append(args, fmt.Sprintf("-psk=%X", psk))
			if len(cfg.PSKIdentityHint) > 0 {
				args = append(args, fmt.Sprintf("-psk_hint=%s", cfg.PSKIdentityHint))
			}
		}

		// certs arguments
		if len(cfg.Certificates) > 0 {
			// create temporary cert files
			certPEM, keyPEM, err := writeTempPEM(cfg)
			if err != nil {
				c.errChan <- err
				return
			}
			args = append(args,
				fmt.Sprintf("-cert=%s", certPEM),
				fmt.Sprintf("-key=%s", keyPEM))
			defer func() {
				_ = os.Remove(certPEM)
				_ = os.Remove(keyPEM)
			}()
		} else {
			args = append(args, "-nocert")
		}

		// launch command
		// #nosec G204
		cmd := exec.CommandContext(c.ctx, "openssl", args...)
		var inner net.Conn
		inner, c.serverConn = net.Pipe()
		cmd.Stdin = inner
		cmd.Stdout = inner
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			c.errChan <- err
			_ = inner.Close()
			return
		}

		// Ensure that server has started
		time.Sleep(500 * time.Millisecond)

		c.serverReady <- struct{}{}
		simpleReadWrite(c.errChan, c.serverChan, c.serverConn, c.messageRecvCount)
	}()
}

func clientOpenSSL(c *comm) {
	select {
	case <-c.serverReady:
		// OK
	case <-time.After(time.Second):
		c.errChan <- errors.New("waiting on serverReady err: timeout")
	}

	c.clientMutex.Lock()
	defer c.clientMutex.Unlock()

	cfg := c.clientConfig

	// create openssl arguments
	args := []string{
		"s_client",
		"-dtls1_2",
		"-quiet",
		"-verify_quiet",
		"-servername=localhost",
		fmt.Sprintf("-connect=127.0.0.1:%d", c.serverPort),
	}
	ciphers := ciphersOpenSSL(cfg)
	if ciphers != "" {
		args = append(args, fmt.Sprintf("-cipher=%s", ciphers))
	}

	// psk arguments
	if cfg.PSK != nil {
		psk, err := cfg.PSK(nil)
		if err != nil {
			c.errChan <- err
			return
		}
		args = append(args, fmt.Sprintf("-psk=%X", psk))
	}

	// certificate arguments
	if len(cfg.Certificates) > 0 {
		// create temporary cert files
		certPEM, keyPEM, err := writeTempPEM(cfg)
		if err != nil {
			c.errChan <- err
			return
		}
		args = append(args, fmt.Sprintf("-CAfile=%s", certPEM), fmt.Sprintf("-cert=%s", certPEM), fmt.Sprintf("-key=%s", keyPEM))
		defer func() {
			_ = os.Remove(certPEM)
			_ = os.Remove(keyPEM)
		}()
	}
	if !cfg.InsecureSkipVerify {
		args = append(args, "-verify_return_error")
	}

	// launch command
	// #nosec G204
	cmd := exec.CommandContext(c.ctx, "openssl", args...)
	var inner net.Conn
	inner, c.clientConn = net.Pipe()
	cmd.Stdin = inner
	cmd.Stdout = inner
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		c.errChan <- err
		_ = inner.Close()
		return
	}

	simpleReadWrite(c.errChan, c.clientChan, c.clientConn, c.messageRecvCount)
}

func ciphersOpenSSL(cfg *dtls.Config) string {
	// See https://tls.mbed.org/supported-ssl-ciphersuites
	translate := map[dtls.CipherSuiteID]string{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:   "ECDHE-ECDSA-AES128-CCM",
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: "ECDHE-ECDSA-AES128-CCM8",

		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "ECDHE-ECDSA-AES128-GCM-SHA256",
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "ECDHE-ECDSA-AES256-GCM-SHA384",

		dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: "ECDHE-RSA-AES128-GCM-SHA256",
		dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: "ECDHE-RSA-AES256-GCM-SHA384",

		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: "ECDHE-ECDSA-AES256-SHA",
		dtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:   "ECDHE-RSA-AES256-SHA",

		dtls.TLS_PSK_WITH_AES_128_CCM:   "PSK-AES128-CCM",
		dtls.TLS_PSK_WITH_AES_128_CCM_8: "PSK-AES128-CCM8",
		dtls.TLS_PSK_WITH_AES_256_CCM_8: "PSK-AES256-CCM8",

		dtls.TLS_PSK_WITH_AES_128_GCM_SHA256: "PSK-AES128-GCM-SHA256",

		dtls.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256: "ECDHE-PSK-AES128-CBC-SHA256",
	}

	var ciphers []string
	for _, c := range cfg.CipherSuites {
		if text, ok := translate[c]; ok {
			ciphers = append(ciphers, text)
		}
	}
	return strings.Join(ciphers, ";")
}

func writeTempPEM(cfg *dtls.Config) (string, string, error) {
	certOut, err := ioutil.TempFile("", "cert.pem")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temporary file: %w", err)
	}
	keyOut, err := ioutil.TempFile("", "key.pem")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temporary file: %w", err)
	}

	cert := cfg.Certificates[0]
	derBytes := cert.Certificate[0]
	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return "", "", fmt.Errorf("failed to write data to cert.pem: %w", err)
	}
	if err = certOut.Close(); err != nil {
		return "", "", fmt.Errorf("error closing cert.pem: %w", err)
	}

	priv := cert.PrivateKey
	var privBytes []byte
	privBytes, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("unable to marshal private key: %w", err)
	}
	if err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return "", "", fmt.Errorf("failed to write data to key.pem: %w", err)
	}
	if err = keyOut.Close(); err != nil {
		return "", "", fmt.Errorf("error closing key.pem: %w", err)
	}
	return certOut.Name(), keyOut.Name(), nil
}

func minimumOpenSSLVersion(t *testing.T) bool {
	t.Helper()

	cmd := exec.Command("openssl", "version")
	allOut, err := cmd.CombinedOutput()
	if err != nil {
		t.Log("Cannot determine OpenSSL version: ", err)
		return false
	}
	verMatch := regexp.MustCompile(`(?i)^OpenSSL\s(?P<version>(\d+\.)?(\d+\.)?(\*|\d+)(\w)?).+$`)
	match := verMatch.FindStringSubmatch(strings.TrimSpace(string(allOut)))
	params := map[string]string{}
	for i, name := range verMatch.SubexpNames() {
		if i > 0 && i <= len(match) {
			params[name] = match[i]
		}
	}
	var ver string
	if val, ok := params["version"]; !ok {
		t.Log("Could not extract OpenSSL version")
		return false
	} else {
		ver = val
	}

	cmp := strings.Compare(ver, "3.0.0")
	if cmp == -1 {
		return false
	}
	return true
}

func TestPionOpenSSLE2ESimple(t *testing.T) {
	t.Run("OpenSSLServer", func(t *testing.T) {
		testPionE2ESimple(t, serverOpenSSL, clientPion)
	})
	t.Run("OpenSSLClient", func(t *testing.T) {
		testPionE2ESimple(t, serverPion, clientOpenSSL)
	})
}

func TestPionOpenSSLE2ESimplePSK(t *testing.T) {
	t.Run("OpenSSLServer", func(t *testing.T) {
		testPionE2ESimplePSK(t, serverOpenSSL, clientPion)
	})
	t.Run("OpenSSLClient", func(t *testing.T) {
		testPionE2ESimplePSK(t, serverPion, clientOpenSSL)
	})
}

func TestPionOpenSSLE2EMTUs(t *testing.T) {
	t.Run("OpenSSLServer", func(t *testing.T) {
		testPionE2EMTUs(t, serverOpenSSL, clientPion)
	})
	t.Run("OpenSSLClient", func(t *testing.T) {
		testPionE2EMTUs(t, serverPion, clientOpenSSL)
	})
}

func TestPionOpenSSLE2ESimpleED25519(t *testing.T) {
	t.Run("OpenSSLServer", func(t *testing.T) {
		if !minimumOpenSSLVersion(t) {
			t.Skip("Cannot use OpenSSL < 3.0 as a DTLS server with ED25519 keys")
		}
		testPionE2ESimpleED25519(t, serverOpenSSL, clientPion)
	})
	t.Run("OpenSSLClient", func(t *testing.T) {
		testPionE2ESimpleED25519(t, serverPion, clientOpenSSL)
	})
}

func TestPionOpenSSLE2ESimpleED25519ClientCert(t *testing.T) {
	t.Run("OpenSSLServer", func(t *testing.T) {
		if !minimumOpenSSLVersion(t) {
			t.Skip("Cannot use OpenSSL < 3.0 as a DTLS server with ED25519 keys")
		}
		testPionE2ESimpleED25519ClientCert(t, serverOpenSSL, clientPion)
	})
	t.Run("OpenSSLClient", func(t *testing.T) {
		testPionE2ESimpleED25519ClientCert(t, serverPion, clientOpenSSL)
	})
}

func TestPionOpenSSLE2ESimpleECDSAClientCert(t *testing.T) {
	t.Run("OpenSSLServer", func(t *testing.T) {
		testPionE2ESimpleECDSAClientCert(t, serverOpenSSL, clientPion)
	})
	t.Run("OpenSSLClient", func(t *testing.T) {
		testPionE2ESimpleECDSAClientCert(t, serverPion, clientOpenSSL)
	})
}
