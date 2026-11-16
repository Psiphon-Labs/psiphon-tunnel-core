/*
 * Copyright (c) 2014, Psiphon Inc.
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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/deviceregion"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/resolver"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
	"github.com/stretchr/testify/suite"
)

type ConfigTestSuite struct {
	suite.Suite
	confStubBlob      []byte
	requiredFields    []string
	nonRequiredFields []string
	testDirectory     string
}

func (suite *ConfigTestSuite) SetupSuite() {
	suite.confStubBlob = []byte(`
	{
	    "PropagationChannelId" : "<placeholder>",
	    "SponsorId" : "<placeholder>",
	    "LocalHttpProxyPort" : 8080,
	    "LocalSocksProxyPort" : 1080
	}
	`)

	var obj map[string]interface{}
	json.Unmarshal(suite.confStubBlob, &obj)

	// Use a temporary directory for the data root directory so any artifacts
	// created by config.Commit() can be cleaned up.

	testDirectory, err := ioutil.TempDir("", "psiphon-config-test")
	if err != nil {
		suite.T().Fatalf("TempDir failed: %s\n", err)
	}
	suite.testDirectory = testDirectory
	obj["DataRootDirectory"] = testDirectory

	suite.confStubBlob, err = json.Marshal(obj)
	if err != nil {
		suite.T().Fatalf("Marshal failed: %s\n", err)
	}

	for k, v := range obj {
		if k == "DataRootDirectory" {
			// skip
		} else if v == "<placeholder>" {
			suite.requiredFields = append(suite.requiredFields, k)
		} else {
			suite.nonRequiredFields = append(suite.nonRequiredFields, k)
		}
	}
}

func (suite *ConfigTestSuite) TearDownSuite() {
	if common.FileExists(suite.testDirectory) {
		err := os.RemoveAll(suite.testDirectory)
		if err != nil {
			suite.T().Fatalf("Failed to remove test directory %s: %s", suite.testDirectory, err.Error())
		}
	} else {
		suite.T().Fatalf("Test directory not found: %s", suite.testDirectory)
	}
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(ConfigTestSuite))
}

// Tests good config
func (suite *ConfigTestSuite) Test_LoadConfig_BasicGood() {
	config, err := LoadConfig(suite.confStubBlob)
	if err == nil {
		err = config.Commit(false)
	}
	suite.Nil(err, "a basic config should succeed")
}

func (suite *ConfigTestSuite) Test_LoadConfig_DSLAccessTokenRegistration() {
	var obj map[string]any
	suite.Require().NoError(json.Unmarshal(suite.confStubBlob, &obj))
	obj["EnableDSLAccessTokenRegistration"] = true

	configJSON, err := json.Marshal(obj)
	suite.Require().NoError(err)
	config, err := LoadConfig(configJSON)
	suite.Require().NoError(err)
	suite.True(config.EnableDSLAccessTokenRegistration)
}

type configTestNetworkIDGetter string

func (g configTestNetworkIDGetter) GetNetworkID() string {
	return string(g)
}

func (suite *ConfigTestSuite) Test_NetworkIDPrecedence() {
	config, err := LoadConfig(suite.confStubBlob)
	suite.Require().NoError(err)

	config.NetworkID = "WIFI-test"
	suite.Require().NoError(config.Commit(false))
	suite.Equal("WIFI-test", config.GetNetworkID())

	config, err = LoadConfig(suite.confStubBlob)
	suite.Require().NoError(err)

	config.NetworkID = "WIFI-test"
	config.NetworkIDGetter = configTestNetworkIDGetter("MOBILE-getter")
	suite.Require().NoError(config.Commit(false))
	suite.Equal("MOBILE-getter", config.GetNetworkID())
}

// Tests non-JSON file contents
func (suite *ConfigTestSuite) Test_LoadConfig_BadFileContents() {
	_, err := LoadConfig([]byte(`this is not JSON`))
	suite.NotNil(err, "bytes that are not JSON at all should give an error")
}

// Tests config file with JSON contents that don't match our structure
func (suite *ConfigTestSuite) Test_LoadConfig_BadJson() {
	var testObj map[string]interface{}
	var testObjJSON []byte

	// JSON with none of our fields
	//
	// DataRootDirectory must be set to avoid creating data files in the
	// current working directory.
	config, err := LoadConfig([]byte(
		fmt.Sprintf(
			`{"f1": 11, "f2": "two", "DataRootDirectory" : %s}`,
			suite.testDirectory)))
	if err == nil {
		err = config.Commit(false)
	}
	suite.NotNil(err, "JSON with none of our fields should fail")

	// Test all required fields
	for _, field := range suite.requiredFields {
		// Missing a required field
		json.Unmarshal(suite.confStubBlob, &testObj)
		delete(testObj, field)
		testObjJSON, _ = json.Marshal(testObj)
		config, err = LoadConfig(testObjJSON)
		if err == nil {
			err = config.Commit(false)
		}
		suite.NotNil(err, "JSON with one of our required fields missing should fail: %s", field)

		// Bad type for required field
		json.Unmarshal(suite.confStubBlob, &testObj)
		testObj[field] = false // basically guessing a wrong type
		testObjJSON, _ = json.Marshal(testObj)
		config, err = LoadConfig(testObjJSON)
		if err == nil {
			err = config.Commit(false)
		}
		suite.NotNil(err, "JSON with one of our required fields with the wrong type should fail: %s", field)

		// One of our required fields is null
		json.Unmarshal(suite.confStubBlob, &testObj)
		testObj[field] = nil
		testObjJSON, _ = json.Marshal(testObj)
		config, err = LoadConfig(testObjJSON)
		if err == nil {
			err = config.Commit(false)
		}
		suite.NotNil(err, "JSON with one of our required fields set to null should fail: %s", field)

		// One of our required fields is an empty string
		json.Unmarshal(suite.confStubBlob, &testObj)
		testObj[field] = ""
		testObjJSON, _ = json.Marshal(testObj)
		config, err = LoadConfig(testObjJSON)
		if err == nil {
			err = config.Commit(false)
		}
		suite.NotNil(err, "JSON with one of our required fields set to an empty string should fail: %s", field)
	}

	// Test optional fields
	for _, field := range suite.nonRequiredFields {
		// Has incorrect type for optional field
		json.Unmarshal(suite.confStubBlob, &testObj)
		testObj[field] = false // basically guessing a wrong type
		testObjJSON, _ = json.Marshal(testObj)
		config, err = LoadConfig(testObjJSON)
		if err == nil {
			err = config.Commit(false)
		}
		suite.NotNil(err, "JSON with one of our optional fields with the wrong type should fail: %s", field)
	}
}

// Tests config file with JSON contents that don't match our structure
func (suite *ConfigTestSuite) Test_LoadConfig_GoodJson() {
	var testObj map[string]interface{}
	var testObjJSON []byte

	// TODO: Test that the config actually gets the values we expect?

	// Has all of our required fields, but no optional fields
	json.Unmarshal(suite.confStubBlob, &testObj)
	for i := range suite.nonRequiredFields {
		delete(testObj, suite.nonRequiredFields[i])
	}
	testObjJSON, _ = json.Marshal(testObj)
	config, err := LoadConfig(testObjJSON)
	if err == nil {
		err = config.Commit(false)
	}
	suite.Nil(err, "JSON with good values for our required fields but no optional fields should succeed")

	// Has all of our required fields, and all optional fields
	config, err = LoadConfig(suite.confStubBlob)
	if err == nil {
		err = config.Commit(false)
	}
	suite.Nil(err, "JSON with all good values for required and optional fields should succeed")

	// Has null for optional fields
	json.Unmarshal(suite.confStubBlob, &testObj)
	for i := range suite.nonRequiredFields {
		testObj[suite.nonRequiredFields[i]] = nil
	}
	testObjJSON, _ = json.Marshal(testObj)
	config, err = LoadConfig(testObjJSON)
	if err == nil {
		err = config.Commit(false)
	}
	suite.Nil(err, "JSON with null for optional values should succeed")
}

// stubDeviceBinder is a DeviceBinder that records the device name it would
// bind to and returns it as the device info.
type stubDeviceBinder struct{ name string }

func (b *stubDeviceBinder) BindToDevice(int) (string, error) { return b.name, nil }

func TestConfigDeviceBinderGetters(t *testing.T) {

	host := &stubDeviceBinder{name: "host"}
	upstream := &stubDeviceBinder{name: "upstream"}
	downstream := &stubDeviceBinder{name: "downstream"}

	// No split, no host binder: both getters return nil.
	c := &Config{}
	if c.deviceBinder() != nil {
		t.Fatalf("deviceBinder: expected nil")
	}
	if c.splitDeviceBinder() != nil {
		t.Fatalf("splitDeviceBinder: expected nil")
	}

	// No split, host binder set: both getters return the host binder.
	c = &Config{hostDeviceBinder: host}
	if c.deviceBinder() != host {
		t.Fatalf("deviceBinder: expected host binder")
	}
	if c.splitDeviceBinder() != host {
		t.Fatalf("splitDeviceBinder: expected fallback to host binder")
	}

	// Split mode: deviceBinder() returns upstream, splitDeviceBinder()
	// returns downstream. hostDeviceBinder must be nil under the Commit
	// validation in this mode, but the getter logic doesn't depend on
	// that.
	c = &Config{
		splitInterface: &splitInterfaceState{
			upstreamDeviceBinder:   upstream,
			downstreamDeviceBinder: downstream,
			upstreamInterfaceName:  "iface-up",
		},
	}
	if c.deviceBinder() != upstream {
		t.Fatalf("deviceBinder: expected upstream binder in split mode")
	}
	if c.splitDeviceBinder() != downstream {
		t.Fatalf("splitDeviceBinder: expected downstream binder in split mode")
	}
	if c.splitInterfaceUpstreamInterfaceName() != "iface-up" {
		t.Fatalf("splitInterfaceUpstreamInterfaceName: unexpected value %q",
			c.splitInterfaceUpstreamInterfaceName())
	}
}

func TestConfigGetSplitResolverFallback(t *testing.T) {

	c := &Config{}

	// Both nil to start.
	if c.GetResolver() != nil {
		t.Fatalf("GetResolver: expected nil before SetResolver")
	}
	if c.GetSplitResolver() != nil {
		t.Fatalf("GetSplitResolver: expected nil before SetResolver/SetSplitResolver")
	}

	// Main set, split unset: GetSplitResolver falls back to the main one.
	main := &resolver.Resolver{}
	c.SetResolver(main)
	if got := c.GetSplitResolver(); got != main {
		t.Fatalf("GetSplitResolver: expected fallback to main resolver, got %p", got)
	}

	// Both set: GetSplitResolver returns the split one.
	split := &resolver.Resolver{}
	c.SetSplitResolver(split)
	if got := c.GetSplitResolver(); got != split {
		t.Fatalf("GetSplitResolver: expected split resolver, got %p", got)
	}
	if got := c.GetResolver(); got != main {
		t.Fatalf("GetResolver: expected main resolver, got %p", got)
	}
}

// TestInproxySplitInterfaceCommonClients checks that split-interface mode
// rejects common client capacity while still serving personal clients.
func TestInproxySplitInterfaceCommonClients(t *testing.T) {

	if !tun.IsBindToDeviceSupported() {
		t.Skip("split interface mode is not supported on this platform")
	}

	newConfig := func(t *testing.T) *Config {
		dataRootDirectory, err := ioutil.TempDir("", "psiphon-split-config-test")
		if err != nil {
			t.Fatalf("TempDir failed: %s", err)
		}
		t.Cleanup(func() { os.RemoveAll(dataRootDirectory) })

		return &Config{
			DataRootDirectory:                        dataRootDirectory,
			PropagationChannelId:                     "ABCDEFGH",
			SponsorId:                                "12345678",
			ClientVersion:                            "1",
			DisableTunnels:                           true,
			InproxyEnableProxy:                       true,
			InproxyProxySplitUpstreamInterfaceName:   "upstream0",
			InproxyProxySplitDownstreamInterfaceName: "downstream0",
			InproxyMaxPersonalClients:                1,
		}
	}

	t.Run("personal only", func(t *testing.T) {
		config := newConfig(t)
		if err := config.Commit(false); err != nil {
			t.Fatalf("expected success, got: %s", err)
		}
	})

	t.Run("common clients rejected", func(t *testing.T) {
		config := newConfig(t)
		config.InproxyMaxCommonClients = 1
		if err := config.Commit(false); err == nil {
			t.Fatalf("expected error for InproxyMaxCommonClients in split interface mode")
		}
	})

	t.Run("common clients via proxy limits rejected", func(t *testing.T) {
		config := newConfig(t)
		limits, err := common.NewProxyLimits(&common.ProxyLimitsConfig{
			MaxCommonClients:   1,
			MaxPersonalClients: 1,
		})
		if err != nil {
			t.Fatalf("NewProxyLimits failed: %s", err)
		}
		config.InproxyProxyLimits = limits
		if err := config.Commit(false); err == nil {
			t.Fatalf("expected error for common clients in shared proxy limits in split interface mode")
		}
	})

	t.Run("personal only via proxy limits", func(t *testing.T) {
		config := newConfig(t)
		limits, err := common.NewProxyLimits(&common.ProxyLimitsConfig{
			MaxPersonalClients: 1,
		})
		if err != nil {
			t.Fatalf("NewProxyLimits failed: %s", err)
		}
		config.InproxyProxyLimits = limits
		if err := config.Commit(false); err != nil {
			t.Fatalf("expected success, got: %s", err)
		}
	})
}

// newUnixSocketTestConfig returns a minimal committable Config configured to
// use Unix domain sockets, for validation testing.
func newUnixSocketTestConfig(t *testing.T) *Config {
	dataRootDirectory, err := ioutil.TempDir("", "psiphon-uds-config-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	t.Cleanup(func() { os.RemoveAll(dataRootDirectory) })

	return &Config{
		DataRootDirectory:       dataRootDirectory,
		PropagationChannelId:    "ABCDEFGH",
		SponsorId:               "12345678",
		ClientVersion:           "1",
		UseUnixDomainSockets:    true,
		LocalSocksProxyUnixPath: filepath.Join(dataRootDirectory, "socks.sock"),
		LocalHttpProxyUnixPath:  filepath.Join(dataRootDirectory, "http.sock"),
	}
}

func TestUseUnixDomainSocketsValidation(t *testing.T) {

	supported := runtime.GOOS == "darwin" || runtime.GOOS == "android" || runtime.GOOS == "linux"

	t.Run("both paths set and valid", func(t *testing.T) {
		config := newUnixSocketTestConfig(t)
		err := config.Commit(false)
		if supported {
			if err != nil {
				t.Fatalf("expected success, got: %s", err)
			}
		} else {
			if err == nil {
				t.Fatalf("expected error on unsupported platform")
			}
		}
	})

	if !supported {
		// The remaining cases assert path-specific validation behavior that
		// is only reached on supported platforms.
		return
	}

	t.Run("missing socks path with socks enabled", func(t *testing.T) {
		config := newUnixSocketTestConfig(t)
		config.LocalSocksProxyUnixPath = ""
		err := config.Commit(false)
		if err == nil {
			t.Fatalf("expected error for missing LocalSocksProxyUnixPath")
		}
	})

	t.Run("missing http path with http enabled", func(t *testing.T) {
		config := newUnixSocketTestConfig(t)
		config.LocalHttpProxyUnixPath = ""
		err := config.Commit(false)
		if err == nil {
			t.Fatalf("expected error for missing LocalHttpProxyUnixPath")
		}
	})

	t.Run("missing socks path but socks disabled", func(t *testing.T) {
		config := newUnixSocketTestConfig(t)
		config.LocalSocksProxyUnixPath = ""
		config.DisableLocalSocksProxy = true
		err := config.Commit(false)
		if err != nil {
			t.Fatalf("expected success when SOCKS proxy is disabled, got: %s", err)
		}
	})

	t.Run("path too long", func(t *testing.T) {
		config := newUnixSocketTestConfig(t)
		config.LocalSocksProxyUnixPath = "/" + strings.Repeat("a", 200)
		err := config.Commit(false)
		if err == nil {
			t.Fatalf("expected error for over-length path")
		}
	})

	t.Run("relative path rejected", func(t *testing.T) {
		config := newUnixSocketTestConfig(t)
		config.LocalSocksProxyUnixPath = "socks.sock"
		err := config.Commit(false)
		if err == nil {
			t.Fatalf("expected error for relative path")
		}
	})

	t.Run("abstract namespace path", func(t *testing.T) {
		config := newUnixSocketTestConfig(t)
		config.LocalSocksProxyUnixPath = "@psiphon-socks"
		config.LocalHttpProxyUnixPath = "@psiphon-http"
		err := config.Commit(false)
		if runtime.GOOS == "darwin" {
			if err == nil {
				t.Fatalf("expected error for abstract namespace socket on Darwin")
			}
		} else {
			if err != nil {
				t.Fatalf("expected success for abstract namespace socket, got: %s", err)
			}
		}
	})

	t.Run("disabled flag ignores paths", func(t *testing.T) {
		config := newUnixSocketTestConfig(t)
		config.UseUnixDomainSockets = false
		config.LocalSocksProxyUnixPath = ""
		config.LocalHttpProxyUnixPath = ""
		err := config.Commit(false)
		if err != nil {
			t.Fatalf("expected success when UseUnixDomainSockets is off, got: %s", err)
		}
	})

	t.Run("identical paths with both proxies enabled", func(t *testing.T) {
		config := newUnixSocketTestConfig(t)
		config.LocalHttpProxyUnixPath = config.LocalSocksProxyUnixPath
		err := config.Commit(false)
		if err == nil {
			t.Fatalf("expected error for identical enabled proxy paths")
		}
	})

	t.Run("identical paths but one proxy disabled", func(t *testing.T) {
		config := newUnixSocketTestConfig(t)
		config.LocalHttpProxyUnixPath = config.LocalSocksProxyUnixPath
		config.DisableLocalHTTPProxy = true
		err := config.Commit(false)
		if err != nil {
			t.Fatalf("expected success when only one proxy is enabled, got: %s", err)
		}
	})
}

// newDeviceRegionTestConfig returns a minimal committable Config.
func newDeviceRegionTestConfig(t *testing.T) *Config {
	dataRootDirectory, err := ioutil.TempDir("", "psiphon-device-region-config-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	t.Cleanup(func() { os.RemoveAll(dataRootDirectory) })

	return &Config{
		DataRootDirectory:    dataRootDirectory,
		PropagationChannelId: "ABCDEFGH",
		SponsorId:            "12345678",
		ClientVersion:        "1",
	}
}

func TestConfigDeviceRegion(t *testing.T) {

	// A host application that supplies the region, as the mobile libraries do,
	// keeps its value.
	t.Run("supplied region is retained", func(t *testing.T) {
		config := newDeviceRegionTestConfig(t)
		config.DeviceRegion = "CA"
		err := config.Commit(false)
		if err != nil {
			t.Fatalf("Commit failed: %s", err)
		}
		if config.DeviceRegion != "CA" {
			t.Fatalf("expected DeviceRegion CA, got %q", config.DeviceRegion)
		}
	})

	// Otherwise the region is approximated from operating system settings. The
	// expected value depends on how the machine running this test is
	// configured, and is empty when no setting yields a region.
	t.Run("blank region is approximated", func(t *testing.T) {
		config := newDeviceRegionTestConfig(t)
		err := config.Commit(false)
		if err != nil {
			t.Fatalf("Commit failed: %s", err)
		}
		if config.DeviceRegion != deviceregion.Get() {
			t.Fatalf("expected DeviceRegion %q, got %q",
				deviceregion.Get(), config.DeviceRegion)
		}
	})
}
