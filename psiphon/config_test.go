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

/*
NOTE: This test suite is probably overkill for such a simple file. It also
probably shouldn't be doing error type checking, and especially not checking
for particular JSON package errors. This is our first test file and mostly
intended to be something to learn from and derive other test sets.
*/

import (
	"encoding/json"
	"errors"
	"github.com/stretchr/testify/suite"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const (
	_TEST_DIR = "./testfiles"
)

type ConfigTestSuite struct {
	suite.Suite
}

func (suite *ConfigTestSuite) SetupTest() {
	os.Mkdir(_TEST_DIR, 0777)
}

func (suite *ConfigTestSuite) TearDownTest() {
	os.RemoveAll(_TEST_DIR)
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(ConfigTestSuite))
}

func writeConfigFile(filename string, contents string) {
	configFile, _ := os.Create(filename)
	configFile.WriteString(contents)
	configFile.Close()
}

// Tests bad config file path
func (suite *ConfigTestSuite) Test_LoadConfig_BadPath() {
	_, err := LoadConfig("BAADPATH")
	suite.NotNil(err, "error should be set")
}

// Tests good config file path
func (suite *ConfigTestSuite) Test_LoadConfig_GoodPath() {
	filename := filepath.Join(_TEST_DIR, "good.json")
	writeConfigFile(filename, `{"PropagationChannelId": "xyz", "SponsorId": "xyz", "RemoteServerListUrl": "xyz", "RemoteServerListSignaturePublicKey": "xyz"}`)

	// Use absolute path
	abspath, _ := filepath.Abs(filename)
	_, err := LoadConfig(abspath)
	suite.Nil(err, "error should not be set")

	// Use relative path
	suite.False(filepath.IsAbs(filename))
	_, err = LoadConfig(filename)
	suite.Nil(err, "error should not be set")
}

// Tests non-JSON file contents
func (suite *ConfigTestSuite) Test_LoadConfig_BadFileContents() {
	filename := filepath.Join(_TEST_DIR, "junk.json")
	writeConfigFile(filename, "**ohhi**")
	_, err := LoadConfig(filename)
	suite.NotNil(err, "error should be set")
	// TODO: Is it worthwhile to test error types?
	suite.Equal(reflect.TypeOf(json.SyntaxError{}).Name(), reflect.TypeOf(err).Elem().Name())
}

// Tests config file with JSON contents that don't match our structure
func (suite *ConfigTestSuite) Test_LoadConfig_BadJson() {
	filename := filepath.Join(_TEST_DIR, "other.json")

	// Has none of our fields
	writeConfigFile(filename, `{"f1": 11, "f2": "two"}`)
	_, err := LoadConfig(filename)
	suite.NotNil(err, "error should be set")
	suite.Equal(reflect.TypeOf(errors.New("")).Elem().Name(), reflect.TypeOf(err).Elem().Name())

	// Has one of our required fields, but wrong type
	writeConfigFile(filename, `{"PropagationChannelId": 11, "f2": "two"}`)
	_, err = LoadConfig(filename)
	suite.NotNil(err, "error should be set")
	suite.Equal(reflect.TypeOf(json.UnmarshalTypeError{}).Name(), reflect.TypeOf(err).Elem().Name())

	// Has one of our required fields, but null
	writeConfigFile(filename, `{"PropagationChannelId": null, "f2": "two"}`)
	_, err = LoadConfig(filename)
	suite.NotNil(err, "error should be set")
	suite.Equal(reflect.TypeOf(errors.New("")).Elem().Name(), reflect.TypeOf(err).Elem().Name())

	// Has one of our required fields, but empty string
	writeConfigFile(filename, `{"PropagationChannelId": "", "f2": "two"}`)
	_, err = LoadConfig(filename)
	suite.NotNil(err, "error should be set")
	suite.Equal(reflect.TypeOf(errors.New("")).Elem().Name(), reflect.TypeOf(err).Elem().Name())

	// Has all of our required fields, but no optional fields
	writeConfigFile(filename, `{"PropagationChannelId": "xyz", "SponsorId": "xyz", "RemoteServerListUrl": "xyz", "RemoteServerListSignaturePublicKey": "xyz"}`)
	config, err := LoadConfig(filename)
	suite.Nil(err, "should be no error")
	suite.Equal("xyz", config.PropagationChannelId)

	// Has incorrect type for optional field
	writeConfigFile(filename, `{"ClientVersion": "string, not int", "PropagationChannelId": "xyz", "SponsorId": "xyz", "RemoteServerListUrl": "xyz", "RemoteServerListSignaturePublicKey": "xyz"}`)
	_, err = LoadConfig(filename)
	suite.NotNil(err, "error should be set")
	suite.Equal(reflect.TypeOf(json.UnmarshalTypeError{}).Name(), reflect.TypeOf(err).Elem().Name())

	// Has null for optional field
	writeConfigFile(filename, `{"ClientVersion": null, "PropagationChannelId": "xyz", "SponsorId": "xyz", "RemoteServerListUrl": "xyz", "RemoteServerListSignaturePublicKey": "xyz"}`)
	config, err = LoadConfig(filename)
	suite.Nil(err, "should be no error")
	suite.Equal(0, config.ClientVersion)
}

// Tests config file with JSON contents that don't match our structure
func (suite *ConfigTestSuite) Test_LoadConfig_GoodJson() {
	filename := filepath.Join(_TEST_DIR, "good.json")

	// Has all of our required fields, but no optional fields
	writeConfigFile(filename, `{"PropagationChannelId": "pci", "SponsorId": "si", "RemoteServerListUrl": "rslu", "RemoteServerListSignaturePublicKey": "rslspk"}`)
	config, err := LoadConfig(filename)
	suite.Nil(err, "should be no error")
	suite.Equal("pci", config.PropagationChannelId)
	suite.Equal("si", config.SponsorId)
	suite.Equal("rslu", config.RemoteServerListUrl)
	suite.Equal("rslspk", config.RemoteServerListSignaturePublicKey)

	// Has all of our required fields, and all optional fields
	writeConfigFile(filename, `{"PropagationChannelId": "pci", "SponsorId": "si", "RemoteServerListUrl": "rslu", "RemoteServerListSignaturePublicKey": "rslspk", "LogFilename": "lf", "ClientVersion": 12, "ClientPlatform": "cp", "TunnelWholeDevice": 34, "EgressRegion": "er", "LocalSocksProxyPort": 56, "LocalHttpProxyPort": 78}`)
	config, err = LoadConfig(filename)
	suite.Nil(err, "should be no error")
	suite.Equal("pci", config.PropagationChannelId)
	suite.Equal("si", config.SponsorId)
	suite.Equal("rslu", config.RemoteServerListUrl)
	suite.Equal("rslspk", config.RemoteServerListSignaturePublicKey)
	suite.Equal("lf", config.LogFilename)
	suite.Equal(12, config.ClientVersion)
	suite.Equal("cp", config.ClientPlatform)
	suite.Equal(34, config.TunnelWholeDevice)
	suite.Equal("er", config.EgressRegion)
	suite.Equal(56, config.LocalSocksProxyPort)
	suite.Equal(78, config.LocalHttpProxyPort)
}
