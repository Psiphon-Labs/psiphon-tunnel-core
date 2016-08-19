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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

const (
	FEEDBACK_UPLOAD_MAX_RETRIES         = 5
	FEEDBACK_UPLOAD_RETRY_DELAY_SECONDS = 300
	FEEDBACK_UPLOAD_TIMEOUT_SECONDS     = 30
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
		return nil, common.ContextError(err)
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
		return nil, common.ContextError(err)
	}

	return encryptedFeedback, nil
}

// Encrypt feedback and upload to server. If upload fails
// the feedback thread will sleep and retry multiple times.
func SendFeedback(configJson, diagnosticsJson, b64EncodedPublicKey, uploadServer, uploadPath, uploadServerHeaders string) error {

	config, err := LoadConfig([]byte(configJson))
	if err != nil {
		return common.ContextError(err)
	}

	untunneledDialConfig := &DialConfig{
		UpstreamProxyUrl:              config.UpstreamProxyUrl,
		UpstreamProxyCustomHeaders:    config.UpstreamProxyCustomHeaders,
		PendingConns:                  nil,
		DeviceBinder:                  nil,
		DnsServerGetter:               nil,
		UseIndistinguishableTLS:       config.UseIndistinguishableTLS,
		TrustedCACertificatesFilename: config.TrustedCACertificatesFilename,
		DeviceRegion:                  config.DeviceRegion,
	}

	secureFeedback, err := encryptFeedback(diagnosticsJson, b64EncodedPublicKey)
	if err != nil {
		return err
	}

	randBytes, err := common.MakeSecureRandomBytes(8)
	if err != nil {
		return err
	}
	uploadId := hex.EncodeToString(randBytes)

	url := "https://" + uploadServer + uploadPath + uploadId
	headerPieces := strings.Split(uploadServerHeaders, ": ")
	// Only a single header is expected.
	if len(headerPieces) != 2 {
		return common.ContextError(errors.New("expected 2 header pieces, got: " + strconv.Itoa(len(headerPieces))))
	}

	for i := 0; i < FEEDBACK_UPLOAD_MAX_RETRIES; i++ {
		err := uploadFeedback(untunneledDialConfig, secureFeedback, url, headerPieces)
		if err != nil {
			NoticeAlert("failed to upload feedback: %s", err)
			time.Sleep(FEEDBACK_UPLOAD_RETRY_DELAY_SECONDS * time.Second)
		} else {
			break
		}
	}
	return nil
}

// Attempt to upload feedback data to server.
func uploadFeedback(config *DialConfig, feedbackData []byte, url string, headerPieces []string) error {
	client, parsedUrl, err := MakeUntunneledHttpsClient(config, nil, url, time.Duration(FEEDBACK_UPLOAD_TIMEOUT_SECONDS*time.Second))
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", parsedUrl, bytes.NewBuffer(feedbackData))
	if err != nil {
		return common.ContextError(err)
	}
	req.Header.Set(headerPieces[0], headerPieces[1])

	resp, err := client.Do(req)
	if err != nil {
		return common.ContextError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return common.ContextError(errors.New("received HTTP status: " + resp.Status))
	}

	return nil
}

// Pad src to the next block boundary with PKCS7 padding
// (https://tools.ietf.org/html/rfc5652#section-6.3).
func AddPKCS7Padding(src []byte, blockSize int) []byte {
	paddingLen := blockSize - (len(src) % blockSize)
	padding := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	return append(src, padding...)
}

// Encrypt plaintext with AES in CBC mode.
func encryptAESCBC(plaintext []byte) ([]byte, []byte, []byte, error) {
	// CBC mode works on blocks so plaintexts need to be padded to the
	// next whole block (https://tools.ietf.org/html/rfc5246#section-6.2.3.2).
	plaintext = AddPKCS7Padding(plaintext, aes.BlockSize)

	ciphertext := make([]byte, len(plaintext))
	iv, err := common.MakeSecureRandomBytes(aes.BlockSize)
	if err != nil {
		return nil, nil, nil, err
	}

	key, err := common.MakeSecureRandomBytes(aes.BlockSize)
	if err != nil {
		return nil, nil, nil, common.ContextError(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, common.ContextError(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return iv, key, ciphertext, nil
}

// Encrypt plaintext with RSA public key.
func encryptWithPublicKey(plaintext, publicKey []byte) ([]byte, error) {
	parsedKey, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return nil, common.ContextError(err)
	}
	if rsaPubKey, ok := parsedKey.(*rsa.PublicKey); ok {
		rsaEncryptOutput, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaPubKey, plaintext, nil)
		if err != nil {
			return nil, common.ContextError(err)
		}
		return rsaEncryptOutput, nil
	}
	return nil, common.ContextError(errors.New("feedback key is not an RSA public key"))
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
