/*
* Copyright (c) 2016, Psiphon Inc.
* All rights reserved.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
 */

package psiphon

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

// Conforms to the format expected by the feedback decryptor.
// https://bitbucket.org/psiphon/psiphon-circumvention-system/src/default/EmailResponder/FeedbackDecryptor/decryptor.py
type secureFeedback struct {
	IV                   string `json:"iv"`
	ContentCipherText    string `json:"contentCiphertext"`
	WrappedEncryptionKey string `json:"wrappedEncryptionKey"`
	ContentMac           string `json:"contentMac"`
	WrappedMacKey        string `json:"wrappedMacKey"`
}

// Encrypt and marshal feedback into secure json structure utilizing the
// Encrypt-then-MAC paradigm (https://tools.ietf.org/html/rfc7366#section-3).
func encryptFeedback(diagnosticsJson, b64EncodedPublicKey string) ([]byte, error) {
	publicKey, err := base64.StdEncoding.DecodeString(b64EncodedPublicKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	iv, encryptionKey, diagnosticsCiphertext, err := encryptAESCBC([]byte(diagnosticsJson))
	if err != nil {
		return nil, err
	}
	digest, macKey, err := generateHMAC(iv, diagnosticsCiphertext)
	if err != nil {
		return nil, err
	}

	wrappedMacKey, err := encryptWithPublicKey(macKey, publicKey)
	if err != nil {
		return nil, err
	}
	wrappedEncryptionKey, err := encryptWithPublicKey(encryptionKey, publicKey)
	if err != nil {
		return nil, err
	}

	var securedFeedback = secureFeedback{
		IV:                   base64.StdEncoding.EncodeToString(iv),
		ContentCipherText:    base64.StdEncoding.EncodeToString(diagnosticsCiphertext),
		WrappedEncryptionKey: base64.StdEncoding.EncodeToString(wrappedEncryptionKey),
		ContentMac:           base64.StdEncoding.EncodeToString(digest),
		WrappedMacKey:        base64.StdEncoding.EncodeToString(wrappedMacKey),
	}

	encryptedFeedback, err := json.Marshal(securedFeedback)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return encryptedFeedback, nil
}

// Encrypt feedback and upload to server. If upload fails
// the routine will sleep and retry multiple times.
func SendFeedback(ctx context.Context, configJson, diagnosticsJson, uploadPath string) error {

	config, err := LoadConfig([]byte(configJson))
	if err != nil {
		return errors.Trace(err)
	}
	err = config.Commit(true)
	if err != nil {
		return errors.Trace(err)
	}

	// Get tactics, may update client parameters
	p := config.GetClientParameters().Get()
	timeout := p.Duration(parameters.FeedbackTacticsWaitPeriod)
	p.Close()
	getTacticsCtx, cancelFunc := context.WithTimeout(ctx, timeout)
	defer cancelFunc()
	// Note: GetTactics will fail silently if the datastore used for retrieving
	// and storing tactics is opened by another process.
	GetTactics(getTacticsCtx, config)

	// Get the latest client parameters
	p = config.GetClientParameters().Get()
	feedbackUploadMinRetryDelay := p.Duration(parameters.FeedbackUploadRetryMinDelaySeconds)
	feedbackUploadMaxRetryDelay := p.Duration(parameters.FeedbackUploadRetryMaxDelaySeconds)
	feedbackUploadTimeout := p.Duration(parameters.FeedbackUploadTimeoutSeconds)
	feedbackUploadMaxAttempts := p.Int(parameters.FeedbackUploadMaxAttempts)
	transferURLs := p.TransferURLs(parameters.FeedbackUploadURLs)
	p.Close()

	untunneledDialConfig := &DialConfig{
		UpstreamProxyURL:              config.UpstreamProxyURL,
		CustomHeaders:                 config.CustomHeaders,
		DeviceBinder:                  nil,
		IPv6Synthesizer:               nil,
		DnsServerGetter:               nil,
		TrustedCACertificatesFilename: config.TrustedCACertificatesFilename,
	}

	uploadId := prng.HexString(8)

	for i := 0; i < feedbackUploadMaxAttempts; i++ {

		uploadURL := transferURLs.Select(i)
		if uploadURL == nil {
			return errors.TraceNew("error no feedback upload URL selected")
		}

		b64PublicKey := uploadURL.B64EncodedPublicKey
		if b64PublicKey == "" {
			if config.FeedbackEncryptionPublicKey == "" {
				return errors.TraceNew("error no default encryption key")
			}
			b64PublicKey = config.FeedbackEncryptionPublicKey
		}

		secureFeedback, err := encryptFeedback(diagnosticsJson, b64PublicKey)
		if err != nil {
			return errors.Trace(err)
		}

		feedbackUploadCtx, cancelFunc := context.WithTimeout(
			ctx,
			feedbackUploadTimeout)
		defer cancelFunc()

		client, err := MakeUntunneledHTTPClient(
			feedbackUploadCtx,
			config,
			untunneledDialConfig,
			nil,
			uploadURL.SkipVerify)
		if err != nil {
			return errors.Trace(err)
		}

		parsedURL, err := url.Parse(uploadURL.URL)
		if err != nil {
			return errors.TraceMsg(err, "failed to parse feedback upload URL")
		}

		parsedURL.Path = path.Join(parsedURL.Path, uploadPath, uploadId)

		request, err := http.NewRequestWithContext(feedbackUploadCtx, "PUT", parsedURL.String(), bytes.NewBuffer(secureFeedback))
		if err != nil {
			return errors.Trace(err)
		}

		for k, v := range uploadURL.RequestHeaders {
			request.Header.Set(k, v)
		}
		request.Header.Set("User-Agent", MakePsiphonUserAgent(config))

		err = uploadFeedback(client, request)
		cancelFunc()
		if err != nil {
			if ctx.Err() != nil {
				// Input context has completed
				return errors.TraceMsg(err,
					fmt.Sprintf("feedback upload attempt %d/%d cancelled", i+1, feedbackUploadMaxAttempts))
			}
			// Do not sleep after the last attempt
			if i+1 < feedbackUploadMaxAttempts {
				// Log error, sleep and then retry
				timeUntilRetry := prng.Period(feedbackUploadMinRetryDelay, feedbackUploadMaxRetryDelay)
				NoticeWarning(
					"feedback upload attempt %d/%d failed (retry in %.0fs): %s",
					i+1, feedbackUploadMaxAttempts, timeUntilRetry.Seconds(), errors.Trace(err))
				select {
				case <-ctx.Done():
					return errors.TraceNew(
						fmt.Sprintf("feedback upload attempt %d/%d cancelled before attempt",
							i+2, feedbackUploadMaxAttempts))
				case <-time.After(timeUntilRetry):
				}
				continue
			}
			return errors.TraceMsg(err,
				fmt.Sprintf("feedback upload failed after %d attempts", i+1))
		}
		return nil
	}

	return nil
}

// Attempt to upload feedback data to server.
func uploadFeedback(
	client *http.Client, req *http.Request) error {

	resp, err := client.Do(req)
	if err != nil {
		return errors.Trace(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.TraceNew("unexpected HTTP status: " + resp.Status)
	}

	return nil
}

// Pad src to the next block boundary with PKCS7 padding
// (https://tools.ietf.org/html/rfc5652#section-6.3).
func addPKCS7Padding(src []byte, blockSize int) []byte {
	paddingLen := blockSize - (len(src) % blockSize)
	padding := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	return append(src, padding...)
}

// Encrypt plaintext with AES in CBC mode.
func encryptAESCBC(plaintext []byte) ([]byte, []byte, []byte, error) {
	// CBC mode works on blocks so plaintexts need to be padded to the
	// next whole block (https://tools.ietf.org/html/rfc5246#section-6.2.3.2).
	plaintext = addPKCS7Padding(plaintext, aes.BlockSize)

	ciphertext := make([]byte, len(plaintext))
	iv, err := common.MakeSecureRandomBytes(aes.BlockSize)
	if err != nil {
		return nil, nil, nil, err
	}

	key, err := common.MakeSecureRandomBytes(aes.BlockSize)
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return iv, key, ciphertext, nil
}

// Encrypt plaintext with RSA public key.
func encryptWithPublicKey(plaintext, publicKey []byte) ([]byte, error) {
	parsedKey, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if rsaPubKey, ok := parsedKey.(*rsa.PublicKey); ok {
		rsaEncryptOutput, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaPubKey, plaintext, nil)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return rsaEncryptOutput, nil
	}
	return nil, errors.TraceNew("feedback key is not an RSA public key")
}

// Generate HMAC for Encrypt-then-MAC paradigm.
func generateHMAC(iv, plaintext []byte) ([]byte, []byte, error) {
	key, err := common.MakeSecureRandomBytes(16)
	if err != nil {
		return nil, nil, err
	}

	mac := hmac.New(sha256.New, key)

	mac.Write(iv)
	mac.Write(plaintext)

	digest := mac.Sum(nil)

	return digest, key, nil
}
