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
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/resolver"
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
	// DataRootDirectory must to be set to avoid a migration in the current
	// working directory.
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

func (suite *ConfigTestSuite) Test_LoadConfig_Migrate() {
	oslFiles := []FileTree{
		{
			Name: "osl-registry",
		},
		{
			Name: "osl-registry.cached",
		},
		{
			Name: "osl-1",
		},
		{
			Name: "osl-1.part",
		}}

	nonOSLFile := FileTree{
		Name: "should_not_be_deleted",
		Children: []FileTree{
			{
				Name: "should_not_be_deleted",
			},
		},
	}

	// Test where OSL directory is not deleted after migration because
	// it contains non-OSL files.
	LoadConfigMigrateTest(append(oslFiles, nonOSLFile), &nonOSLFile, suite)

	// Test where OSL directory is deleted after migration because it only
	// contained OSL files.
	LoadConfigMigrateTest(oslFiles, nil, suite)
}

// Test when migrating from old config fields results in filesystem changes.
func LoadConfigMigrateTest(oslDirChildrenPreMigration []FileTree, oslDirChildrenPostMigration *FileTree, suite *ConfigTestSuite) {
	// This test needs its own temporary directory because a previous test may
	// have paved the file which signals that migration has already been
	// completed.
	testDirectory, err := ioutil.TempDir("", "psiphon-config-migration-test")
	if err != nil {
		suite.T().Fatalf("TempDir failed: %s\n", err)
	}

	defer func() {
		if common.FileExists(testDirectory) {
			err := os.RemoveAll(testDirectory)
			if err != nil {
				suite.T().Fatalf("Failed to remove test directory %s: %s", testDirectory, err.Error())
			}
		}
	}()

	// Pre migration files and directories
	oldDataStoreDirectory := filepath.Join(testDirectory, "datastore_old")
	oldRemoteServerListname := "rsl"
	oldObfuscatedServerListDirectoryName := "obfuscated_server_list"
	oldObfuscatedServerListDirectory := filepath.Join(testDirectory, oldObfuscatedServerListDirectoryName)
	oldUpgradeDownloadFilename := "upgrade"
	oldRotatingNoticesFilename := "rotating_notices"
	oldHomepageNoticeFilename := "homepage"

	// Post migration data root directory
	testDataRootDirectory := filepath.Join(testDirectory, "data_root_directory")

	oldFileTree := FileTree{
		Name: testDirectory,
		Children: []FileTree{
			{
				Name: "datastore_old",
				Children: []FileTree{
					{
						Name: "psiphon.boltdb",
					},
					{
						Name: "psiphon.boltdb.lock",
					},
					{
						Name: "non_tunnel_core_file_should_not_be_migrated",
					},
				},
			},
			{
				Name: oldRemoteServerListname,
			},
			{
				Name: oldRemoteServerListname + ".part",
			},
			{
				Name: oldRemoteServerListname + ".part.etag",
			},
			{
				Name:     oldObfuscatedServerListDirectoryName,
				Children: oslDirChildrenPreMigration,
			},
			{
				Name: oldRotatingNoticesFilename,
			},
			{
				Name: oldRotatingNoticesFilename + ".1",
			},
			{
				Name: oldHomepageNoticeFilename,
			},
			{
				Name: oldUpgradeDownloadFilename,
			},
			{
				Name: oldUpgradeDownloadFilename + ".1234",
			},
			{
				Name: oldUpgradeDownloadFilename + ".1234.part",
			},
			{
				Name: oldUpgradeDownloadFilename + ".1234.part.etag",
			},
			{
				Name: "data_root_directory",
				Children: []FileTree{
					{
						Name: "non_tunnel_core_file_should_not_be_clobbered",
					},
				},
			},
		},
	}

	// Write test files
	traverseFileTree(func(tree FileTree, path string) {
		if tree.Children == nil || len(tree.Children) == 0 {
			if !common.FileExists(path) {
				f, err := os.Create(path)
				if err != nil {
					suite.T().Fatalf("Failed to create test file %s with error: %s", path, err.Error())
				}
				f.Close()
			}
		} else {
			if !common.FileExists(path) {
				err := os.Mkdir(path, os.ModePerm)
				if err != nil {
					suite.T().Fatalf("Failed to create test directory %s with error: %s", path, err.Error())
				}
			}
		}
	}, "", oldFileTree)

	// Create config with legacy config values
	config := &Config{
		DataRootDirectory:                            testDataRootDirectory,
		MigrateRotatingNoticesFilename:               filepath.Join(testDirectory, oldRotatingNoticesFilename),
		MigrateHomepageNoticesFilename:               filepath.Join(testDirectory, oldHomepageNoticeFilename),
		MigrateDataStoreDirectory:                    oldDataStoreDirectory,
		PropagationChannelId:                         "ABCDEFGH",
		SponsorId:                                    "12345678",
		LocalSocksProxyPort:                          0,
		LocalHttpProxyPort:                           0,
		MigrateRemoteServerListDownloadFilename:      filepath.Join(testDirectory, oldRemoteServerListname),
		MigrateObfuscatedServerListDownloadDirectory: oldObfuscatedServerListDirectory,
		MigrateUpgradeDownloadFilename:               filepath.Join(testDirectory, oldUpgradeDownloadFilename),
	}

	// Commit config, this is where file migration happens
	err = config.Commit(true)
	if err != nil {
		suite.T().Fatal("Error committing config:", err)
		return
	}

	expectedNewTree := FileTree{
		Name: testDirectory,
		Children: []FileTree{
			{
				Name: "data_root_directory",
				Children: []FileTree{
					{
						Name: "non_tunnel_core_file_should_not_be_clobbered",
					},
					{
						Name: "ca.psiphon.PsiphonTunnel.tunnel-core",
						Children: []FileTree{
							{
								Name: "migration_complete",
							},
							{
								Name: "remote_server_list",
							},
							{
								Name: "remote_server_list.part",
							},
							{
								Name: "remote_server_list.part.etag",
							},
							{
								Name: "datastore",
								Children: []FileTree{
									{
										Name: "psiphon.boltdb",
									},
									{
										Name: "psiphon.boltdb.lock",
									},
								},
							},
							{
								Name: "osl",
								Children: []FileTree{
									{
										Name: "osl-registry",
									},
									{
										Name: "osl-registry.cached",
									},
									{
										Name: "osl-1",
									},
									{
										Name: "osl-1.part",
									},
								},
							},
							{
								Name: "upgrade",
							},
							{
								Name: "upgrade.1234",
							},
							{
								Name: "upgrade.1234.part",
							},
							{
								Name: "upgrade.1234.part.etag",
							},
							{
								Name: "notices",
							},
							{
								Name: "notices.1",
							},
							{
								Name: "homepage",
							},
						},
					},
				},
			},
			{
				Name: "datastore_old",
				Children: []FileTree{
					{
						Name: "non_tunnel_core_file_should_not_be_migrated",
					},
				},
			},
		},
	}

	// The OSL directory will have been deleted if it has no children after
	// migration.
	if oslDirChildrenPostMigration != nil {
		oslDir := FileTree{
			Name:     oldObfuscatedServerListDirectoryName,
			Children: []FileTree{*oslDirChildrenPostMigration},
		}
		expectedNewTree.Children = append(expectedNewTree.Children, oslDir)
	}

	// Read the test directory into a file tree
	testDirectoryTree, err := buildDirectoryTree("", testDirectory)
	if err != nil {
		suite.T().Fatal("Failed to build directory tree:", err)
	}

	// Enumerate the file paths, relative to the test directory,
	// of each file in the test directory after migration.
	testDirectoryFilePaths := make(map[string]int)
	traverseFileTree(func(tree FileTree, path string) {
		if val, ok := testDirectoryFilePaths[path]; ok {
			testDirectoryFilePaths[path] = val + 1
		} else {
			testDirectoryFilePaths[path] = 1
		}
	}, "", *testDirectoryTree)

	// Enumerate the file paths, relative to the test directory,
	// of each file we expect to exist in the test directory tree
	// after migration.
	expectedTestDirectoryFilePaths := make(map[string]int)
	traverseFileTree(func(tree FileTree, path string) {
		if val, ok := expectedTestDirectoryFilePaths[path]; ok {
			expectedTestDirectoryFilePaths[path] = val + 1
		} else {
			expectedTestDirectoryFilePaths[path] = 1
		}
	}, "", expectedNewTree)

	// The set of expected file paths and set of actual  file paths should be
	// identical.

	for k := range expectedTestDirectoryFilePaths {
		_, ok := testDirectoryFilePaths[k]
		if ok {
			// Prevent redundant checks
			delete(testDirectoryFilePaths, k)
		} else {
			suite.T().Errorf("Expected %s to exist in directory", k)
		}
	}

	for k := range testDirectoryFilePaths {
		if _, ok := expectedTestDirectoryFilePaths[k]; !ok {
			suite.T().Errorf("%s in directory but not expected", k)
		}
	}
}

// FileTree represents a file or directory in a file tree.
// There is no need to distinguish between the two in our tests.
type FileTree struct {
	Name     string
	Children []FileTree
}

// traverseFileTree traverses a file tree and emits the filepath of each node.
//
// For example:
//
//	a
//	├── b
//	│   ├── 1
//	│   └── 2
//	└── c
//	    └── 3
//
// Will result in: ["a", "a/b", "a/b/1", "a/b/2", "a/c", "a/c/3"].
func traverseFileTree(f func(node FileTree, nodePath string), basePath string, tree FileTree) {
	filePath := filepath.Join(basePath, tree.Name)
	f(tree, filePath)
	if tree.Children == nil || len(tree.Children) == 0 {
		return
	}
	for _, childTree := range tree.Children {
		traverseFileTree(f, filePath, childTree)
	}
}

// buildDirectoryTree creates a file tree, with the given directory as its root,
// representing the directory structure that exists relative to the given directory.
func buildDirectoryTree(basePath, directoryName string) (*FileTree, error) {

	tree := &FileTree{
		Name:     directoryName,
		Children: nil,
	}

	dirPath := filepath.Join(basePath, directoryName)
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return nil, errors.Tracef("Failed to read directory %s with error: %s", dirPath, err.Error())
	}

	if len(files) > 0 {
		for _, file := range files {
			if file.IsDir() {
				filePath := filepath.Join(basePath, directoryName)
				childTree, err := buildDirectoryTree(filePath, file.Name())
				if err != nil {
					return nil, err
				}
				tree.Children = append(tree.Children, *childTree)
			} else {
				tree.Children = append(tree.Children, FileTree{
					Name:     file.Name(),
					Children: nil,
				})
			}
		}
	}

	return tree, nil
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
