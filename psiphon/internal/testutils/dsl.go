/*
 * Copyright (c) 2025, Psiphon Inc.
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

package testutils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

type DSLBackendTestShim interface {
	ClientIPHeaderName() string
	ClientGeoIPDataHeaderName() string
	ClientTunneledHeaderName() string
	HostIDHeaderName() string
	DiscoverServerEntriesRequestPath() string
	GetServerEntriesRequestPath() string
	GetActiveOSLsRequestPath() string
	GetOSLFileSpecsRequestPath() string

	UnmarshalDiscoverServerEntriesRequest(
		cborRequest []byte) (
		apiParams protocol.PackedAPIParameters,
		oslKeys [][]byte,
		discoverCount int32,
		retErr error)

	MarshalDiscoverServerEntriesResponse(
		versionedServerEntryTags []*struct {
			Tag     []byte
			Version int32
		}) (
		cborResponse []byte,
		retErr error)

	UnmarshalGetServerEntriesRequest(
		cborRequest []byte) (
		apiParams protocol.PackedAPIParameters,
		serverEntryTags [][]byte,
		retErr error)

	MarshalGetServerEntriesResponse(
		sourcedServerEntries []*struct {
			ServerEntryFields protocol.PackedServerEntryFields
			Source            string
		}) (
		cborResponse []byte,
		retErr error)

	UnmarshalGetActiveOSLsRequest(
		cborRequest []byte) (
		apiParams protocol.PackedAPIParameters,
		retErr error)

	MarshalGetActiveOSLsResponse(
		activeOSLIDs [][]byte) (
		cborResponse []byte,
		retErr error)

	UnmarshalGetOSLFileSpecsRequest(
		cborRequest []byte) (
		apiParams protocol.PackedAPIParameters,
		oslIDs [][]byte,
		retErr error)

	MarshalGetOSLFileSpecsResponse(
		oslFileSpecs [][]byte) (
		cborResponse []byte,
		retErr error)
}

// TestDSLBackend is a mock DSL backend intended only for testing.
type TestDSLBackend struct {
	shim                    DSLBackendTestShim
	tlsConfig               *TestDSLRelayTLSConfig
	expectedClientIP        string
	expectedClientGeoIPData *common.GeoIPData
	expectedHostID          string
	oslPaveData             atomic.Value
	untunneledServerEntries map[string]*dslSourcedServerEntry
	tunneledServerEntries   map[string]*dslSourcedServerEntry
	listener                net.Listener
}

type dslSourcedServerEntry struct {
	ServerEntryFields protocol.PackedServerEntryFields
	Source            string
}

func NewTestDSLBackend(
	shim DSLBackendTestShim,
	tlsConfig *TestDSLRelayTLSConfig,
	expectedClientIP string,
	expectedClientGeoIPData *common.GeoIPData,
	expectedHostID string,
	oslPaveData []*osl.PaveData,
	untunneledServerEntries []protocol.ServerEntryFields,
	tunneledServerEntries []protocol.ServerEntryFields) (*TestDSLBackend, error) {

	b := &TestDSLBackend{
		shim:                    shim,
		tlsConfig:               tlsConfig,
		expectedClientIP:        expectedClientIP,
		expectedClientGeoIPData: expectedClientGeoIPData,
		expectedHostID:          expectedHostID,
	}
	b.oslPaveData.Store(oslPaveData)

	prepareServerEntries := func(
		serverEntries []protocol.ServerEntryFields,
		source string) map[string]*dslSourcedServerEntry {

		sourcedServerEntries := make(map[string]*dslSourcedServerEntry)
		for _, serverEntryFields := range untunneledServerEntries {
			packedServerEntryFields, _ := protocol.EncodePackedServerEntryFields(serverEntryFields)
			b.untunneledServerEntries[serverEntryFields.GetTag()] = &dslSourcedServerEntry{
				ServerEntryFields: packedServerEntryFields,
				Source:            source,
			}
		}
		return sourcedServerEntries
	}

	if len(untunneledServerEntries) > 0 {
		b.untunneledServerEntries = prepareServerEntries(
			untunneledServerEntries, "DSL-untunneled")
	}

	if len(tunneledServerEntries) > 0 {
		b.tunneledServerEntries = prepareServerEntries(
			tunneledServerEntries, "DSL-tunneled")
	}

	if b.untunneledServerEntries != nil ||
		b.tunneledServerEntries != nil {
		return b, nil
	}

	// Generate mock server entries if none are specified.

	// Run GenerateConfig concurrently to try to take advantage of multiple
	// CPU cores.
	//
	// Update: no longer using server.GenerateConfig due to import cycle.

	var initMutex sync.Mutex
	var initGroup sync.WaitGroup
	var initErr error

	serverEntries := make(map[string]*dslSourcedServerEntry)

	for i := 1; i <= 128; i++ {

		initGroup.Add(1)
		go func(i int) (retErr error) {
			defer initGroup.Done()
			defer func() {
				if retErr != nil {
					initMutex.Lock()
					initErr = retErr
					initMutex.Unlock()
				}
			}()

			serverEntry := &protocol.ServerEntry{
				Tag:                  prng.Base64String(32),
				IpAddress:            fmt.Sprintf("192.0.2.%d", i),
				SshUsername:          prng.HexString(8),
				SshPassword:          prng.HexString(32),
				SshHostKey:           prng.Base64String(280),
				SshObfuscatedPort:    prng.Range(1, 65535),
				SshObfuscatedKey:     prng.HexString(32),
				Capabilities:         []string{"OSSH"},
				Region:               prng.HexString(1),
				ProviderID:           strings.ToUpper(prng.HexString(8)),
				ConfigurationVersion: 0,
				Signature:            prng.Base64String(80),
			}

			serverEntryFields, err := serverEntry.GetServerEntryFields()
			if err != nil {
				return errors.Trace(err)
			}

			packed, err := protocol.EncodePackedServerEntryFields(serverEntryFields)
			if err != nil {
				return errors.Trace(err)
			}

			source := fmt.Sprintf("DSL-compartment-%d", i)

			initMutex.Lock()

			if serverEntries[serverEntry.Tag] != nil {
				initMutex.Unlock()
				return errors.TraceNew("duplicate tag")
			}

			serverEntries[serverEntry.Tag] = &dslSourcedServerEntry{
				ServerEntryFields: packed,
				Source:            source,
			}

			initMutex.Unlock()

			return nil
		}(i)
	}
	initGroup.Wait()

	if initErr != nil {
		return nil, errors.Trace(initErr)
	}

	b.untunneledServerEntries = serverEntries
	b.tunneledServerEntries = serverEntries

	return b, nil
}

func (b *TestDSLBackend) Start() error {

	logger := NewTestLoggerWithComponent("backend")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.Trace(err)
	}

	certificatePool := x509.NewCertPool()
	certificatePool.AddCert(b.tlsConfig.CACertificate)

	listener = tls.NewListener(
		listener,
		&tls.Config{
			Certificates: []tls.Certificate{*b.tlsConfig.BackendCertificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certificatePool,
		})

	mux := http.NewServeMux()

	handlerAdapter := func(
		w http.ResponseWriter,
		r *http.Request,
		handler func(bool, []byte) ([]byte, error)) (retErr error) {

		defer func() {
			if retErr != nil {
				logger.WithTrace().Warning(fmt.Sprintf("handler failed: %s\n", retErr))
				http.Error(w, retErr.Error(), http.StatusInternalServerError)
			}
		}()

		headerName := b.shim.ClientIPHeaderName()
		clientIPHeader, ok := r.Header[headerName]
		if !ok {
			return errors.Tracef("missing header: %s", headerName)
		}
		if len(clientIPHeader) != 1 ||
			(b.expectedClientIP != "" && clientIPHeader[0] != b.expectedClientIP) {
			return errors.Tracef("invalid header: %s", headerName)
		}

		headerName = b.shim.ClientGeoIPDataHeaderName()
		clientGeoIPDataHeader, ok := r.Header[headerName]
		if !ok {
			return errors.Tracef("missing header: %s", headerName)
		}
		var geoIPData common.GeoIPData
		if len(clientGeoIPDataHeader) != 1 ||
			json.Unmarshal([]byte(clientGeoIPDataHeader[0]), &geoIPData) != nil ||
			(b.expectedClientGeoIPData != nil && geoIPData != *b.expectedClientGeoIPData) {
			return errors.Tracef("invalid header: %s", headerName)
		}

		headerName = b.shim.ClientTunneledHeaderName()
		clientTunneledHeader, ok := r.Header[headerName]
		if !ok {
			return errors.Tracef("missing header: %s", headerName)
		}
		if len(clientTunneledHeader) != 1 ||
			!common.Contains([]string{"true", "false"}, clientTunneledHeader[0]) {
			return errors.Tracef("invalid header: %s", headerName)
		}
		tunneled := clientTunneledHeader[0] == "true"

		headerName = b.shim.HostIDHeaderName()
		hostIDHeader, ok := r.Header[headerName]
		if !ok {
			return errors.Tracef("missing header: %s", headerName)
		}
		if len(hostIDHeader) != 1 ||
			(b.expectedHostID != "" && hostIDHeader[0] != b.expectedHostID) {
			return errors.Tracef("invalid header: %s", headerName)
		}

		request, err := io.ReadAll(r.Body)
		if err != nil {
			return errors.Trace(err)
		}
		r.Body.Close()

		response, err := handler(tunneled, request)
		if err != nil {
			return errors.Trace(err)
		}

		_, err = w.Write(response)
		if err != nil {
			return errors.Trace(err)
		}

		return nil
	}

	mux.HandleFunc(b.shim.DiscoverServerEntriesRequestPath(),
		func(w http.ResponseWriter, r *http.Request) {
			_ = handlerAdapter(w, r, b.handleDiscoverServerEntries)
		})
	mux.HandleFunc(b.shim.GetServerEntriesRequestPath(),
		func(w http.ResponseWriter, r *http.Request) {
			_ = handlerAdapter(w, r, b.handleGetServerEntries)
		})
	mux.HandleFunc(b.shim.GetActiveOSLsRequestPath(),
		func(w http.ResponseWriter, r *http.Request) {
			_ = handlerAdapter(w, r, b.handleGetActiveOSLs)
		})
	mux.HandleFunc(b.shim.GetOSLFileSpecsRequestPath(),
		func(w http.ResponseWriter, r *http.Request) {
			_ = handlerAdapter(w, r, b.handleGetOSLFileSpecs)
		})

	server := &http.Server{
		Handler: mux,
	}

	go func() {
		_ = server.Serve(listener)
	}()

	b.listener = listener

	return nil
}

func (b *TestDSLBackend) Stop() {
	if b.listener == nil {
		return
	}
	_ = b.listener.Close()
}

func (b *TestDSLBackend) GetAddress() string {
	if b.listener == nil {
		return ""
	}
	return b.listener.Addr().String()
}

func (b *TestDSLBackend) GetServerEntryCount(isTunneled bool) int {
	if isTunneled {
		return len(b.tunneledServerEntries)
	}
	return len(b.untunneledServerEntries)
}

func (b *TestDSLBackend) SetOSLPaveData(oslPaveData []*osl.PaveData) {
	b.oslPaveData.Store(oslPaveData)
}

func (b *TestDSLBackend) handleDiscoverServerEntries(
	tunneled bool,
	cborRequest []byte) ([]byte, error) {

	serverEntries := b.untunneledServerEntries
	if tunneled {
		serverEntries = b.tunneledServerEntries
	}

	_, oslKeys, discoverCount, err :=
		b.shim.UnmarshalDiscoverServerEntriesRequest(cborRequest)
	if err != nil {
		return nil, errors.Trace(err)
	}

	missingOSLs := false
	oslPaveDataValue := b.oslPaveData.Load()
	if oslPaveDataValue != nil {

		oslPaveData := oslPaveDataValue.([]*osl.PaveData)

		// When b.oslPaveData is set, the client must provide the expected OSL
		// keys in order to discover any server entries.

		for _, oslPaveData := range oslPaveData {
			found := false
			for _, key := range oslKeys {
				if bytes.Equal(key, oslPaveData.FileKey) {
					found = true
					break
				}

			}
			if !found {
				missingOSLs = true
				break
			}
		}
	}

	var versionedServerEntryTags []*struct {
		Tag     []byte
		Version int32
	}

	if !missingOSLs {

		count := 0
		for tag := range serverEntries {
			if count >= int(discoverCount) {
				break
			}
			count += 1

			// Test server entry tags are base64-encoded random byte strings.
			serverEntryTag, err := base64.StdEncoding.DecodeString(tag)
			if err != nil {
				return nil, errors.Trace(err)
			}

			versionedServerEntryTags = append(
				versionedServerEntryTags,
				&struct {
					Tag     []byte
					Version int32
				}{serverEntryTag, 0})
		}
	}

	cborResponse, err := b.shim.MarshalDiscoverServerEntriesResponse(
		versionedServerEntryTags)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return cborResponse, nil
}

func (b *TestDSLBackend) handleGetServerEntries(
	tunneled bool,
	cborRequest []byte) ([]byte, error) {

	serverEntries := b.untunneledServerEntries
	if tunneled {
		serverEntries = b.tunneledServerEntries
	}

	_, serverEntryTags, err :=
		b.shim.UnmarshalGetServerEntriesRequest(cborRequest)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var sourcedServerEntryTags []*struct {
		ServerEntryFields protocol.PackedServerEntryFields
		Source            string
	}

	for _, serverEntryTag := range serverEntryTags {

		tag := base64.StdEncoding.EncodeToString(serverEntryTag)

		sourcedServerEntry, ok := serverEntries[tag]
		if !ok {

			// An actual DSL backend must return empty slot in this case, as
			// the requested server entry could be pruned or unavailable. For
			// this test, this case is unexpected.

			return nil, errors.TraceNew("unknown server entry tag")
		}

		sourcedServerEntryTags = append(
			sourcedServerEntryTags, &struct {
				ServerEntryFields protocol.PackedServerEntryFields
				Source            string
			}{sourcedServerEntry.ServerEntryFields, sourcedServerEntry.Source})
	}

	cborResponse, err := b.shim.MarshalGetServerEntriesResponse(
		sourcedServerEntryTags)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return cborResponse, nil
}

func (b *TestDSLBackend) handleGetActiveOSLs(
	_ bool,
	cborRequest []byte) ([]byte, error) {

	_, err := b.shim.UnmarshalGetActiveOSLsRequest(cborRequest)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var activeOSLIDs [][]byte

	oslPaveData := b.oslPaveData.Load().([]*osl.PaveData)
	for _, oslPaveData := range oslPaveData {
		activeOSLIDs = append(activeOSLIDs, oslPaveData.FileSpec.ID)
	}

	cborResponse, err := b.shim.MarshalGetActiveOSLsResponse(activeOSLIDs)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return cborResponse, nil
}

func (b *TestDSLBackend) handleGetOSLFileSpecs(
	_ bool,
	cborRequest []byte) ([]byte, error) {

	_, oslIDs, err := b.shim.UnmarshalGetOSLFileSpecsRequest(cborRequest)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var oslFileSpecs [][]byte

	oslPaveData := b.oslPaveData.Load().([]*osl.PaveData)
	for _, oslID := range oslIDs {

		var matchingPaveData *osl.PaveData
		for _, oslPaveData := range oslPaveData {
			if bytes.Equal(oslID, oslPaveData.FileSpec.ID) {
				matchingPaveData = oslPaveData
				break
			}

		}
		if matchingPaveData == nil {

			// An actual DSL backend must return empty slot in this case, as
			// the requested OSL may no longer be active. For this test, this
			// case is unexpected.

			return nil, errors.TraceNew("unknown OSL ID")
		}

		cborOSLFileSpec, err := protocol.CBOREncoding.Marshal(matchingPaveData.FileSpec)
		if err != nil {
			return nil, errors.Trace(err)
		}

		oslFileSpecs = append(oslFileSpecs, cborOSLFileSpec)
	}

	cborResponse, err := b.shim.MarshalGetOSLFileSpecsResponse(oslFileSpecs)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return cborResponse, nil
}

func InitializeTestOSLPaveData() ([]*osl.PaveData, []*osl.PaveData, []*osl.SLOK, error) {

	// Adapted from testObfuscatedRemoteServerLists in psiphon/remoteServerList_test.go

	oslConfigJSONTemplate := `
    {
      "Schemes" : [
        {
          "Epoch" : "%s",
          "PaveDataOSLCount" : 2,
          "Regions" : [],
          "PropagationChannelIDs" : ["%s"],
          "MasterKey" : "vwab2WY3eNyMBpyFVPtsivMxF4MOpNHM/T7rHJIXctg=",
          "SeedSpecs" : [
            {
              "ID" : "KuP2V6gLcROIFzb/27fUVu4SxtEfm2omUoISlrWv1mA=",
              "UpstreamSubnets" : ["0.0.0.0/0"],
              "Targets" :
              {
                  "BytesRead" : 1,
                  "BytesWritten" : 1,
                  "PortForwardDurationNanoseconds" : 1
              }
            }
          ],
          "SeedSpecThreshold" : 1,
          "SeedPeriodNanoseconds" : %d,
          "SeedPeriodKeySplits": [
            {
              "Total": 1,
              "Threshold": 1
            }
          ]
        }
      ]
    }`

	now := time.Now().UTC()
	seedPeriod := 1 * time.Second
	epoch := now.Truncate(seedPeriod)
	epochStr := epoch.Format(time.RFC3339Nano)

	propagationChannelID := prng.HexString(8)

	oslConfigJSON := fmt.Sprintf(
		oslConfigJSONTemplate,
		epochStr,
		propagationChannelID,
		seedPeriod)

	oslConfig, err := osl.LoadConfig([]byte(oslConfigJSON))
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
	}

	oslPaveData, err := oslConfig.GetPaveData(0)
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
	}

	backendPaveData1, ok := oslPaveData[propagationChannelID]
	if !ok {
		return nil, nil, nil, errors.TraceNew("unexpected missing OSL file data")
	}

	// Mock seeding SLOKs
	//
	// Normally, clients supplying the specified propagation channel ID would
	// receive SLOKs via the psiphond tunnel connection

	seedState := oslConfig.NewClientSeedState("", propagationChannelID, nil)
	seedPortForward := seedState.NewClientSeedPortForward(net.ParseIP("0.0.0.0"), nil)
	seedPortForward.UpdateProgress(1, 1, 1)
	payload := seedState.GetSeedPayload()
	if len(payload.SLOKs) != 1 {
		return nil, nil, nil, errors.Tracef("unexpected SLOK count %d", len(payload.SLOKs))
	}
	clientSLOKs := payload.SLOKs

	// Rollover to the next OSL time period and generate a new set of active
	// OSLs and SLOKs.

	time.Sleep(2 * seedPeriod)

	oslPaveData, err = oslConfig.GetPaveData(0)
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
	}

	backendPaveData2, ok := oslPaveData[propagationChannelID]
	if !ok {
		return nil, nil, nil, errors.TraceNew("unexpected missing OSL file data")
	}

	seedState = oslConfig.NewClientSeedState("", propagationChannelID, nil)
	seedPortForward = seedState.NewClientSeedPortForward(net.ParseIP("0.0.0.0"), nil)
	seedPortForward.UpdateProgress(1, 1, 1)
	payload = seedState.GetSeedPayload()
	if len(payload.SLOKs) != 1 {
		return nil, nil, nil, errors.Tracef("unexpected SLOK count %d", len(payload.SLOKs))
	}
	clientSLOKs = append(clientSLOKs, payload.SLOKs...)

	// Double check that PaveData periods don't overlap.
	for _, paveData1 := range backendPaveData1 {
		for _, paveData2 := range backendPaveData2 {
			if bytes.Equal(paveData1.FileSpec.ID, paveData2.FileSpec.ID) {
				return nil, nil, nil, errors.TraceNew("unexpected pave data overlap")
			}
		}
	}

	return backendPaveData1, backendPaveData2, clientSLOKs, nil
}

type TestDSLRelayTLSConfig struct {
	CACertificate      *x509.Certificate
	BackendCertificate *tls.Certificate
	RelayCertificate   *tls.Certificate
}

func NewTestDSLRelayTLSConfiguration() (*TestDSLRelayTLSConfig, error) {

	CAPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Trace(err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"test root CA"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 1),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	CACertificateDER, err := x509.CreateCertificate(
		rand.Reader, template, template, &CAPrivateKey.PublicKey, CAPrivateKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	CACertificate, err := x509.ParseCertificate(CACertificateDER)
	if err != nil {
		return nil, errors.Trace(err)
	}

	issueCertificate := func(
		name string, isServer bool) (*tls.Certificate, error) {

		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, errors.Trace(err)
		}

		now := time.Now()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject: pkix.Name{
				CommonName: name,
			},
			NotBefore: now,
			NotAfter:  now.AddDate(0, 0, 1),
			KeyUsage:  x509.KeyUsageDigitalSignature,
		}
		if isServer {
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}

		certificateDER, err := x509.CreateCertificate(
			rand.Reader, template, CACertificate, &privateKey.PublicKey, CAPrivateKey)
		if err != nil {
			return nil, errors.Trace(err)
		}

		keyPEM := pem.EncodeToMemory(
			&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

		certPEM := pem.EncodeToMemory(
			&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})

		tlsCertificate, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, errors.Trace(err)
		}

		return &tlsCertificate, nil
	}

	backendCertificate, err := issueCertificate("backend", true)
	if err != nil {
		return nil, errors.Trace(err)
	}

	relayCertificate, err := issueCertificate("relay", false)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &TestDSLRelayTLSConfig{
		CACertificate:      CACertificate,
		BackendCertificate: backendCertificate,
		RelayCertificate:   relayCertificate,
	}, nil
}
