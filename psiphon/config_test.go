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
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

const (
	_README              = "../README.md"
	_README_CONFIG_BEGIN = "<!--BEGIN-SAMPLE-CONFIG-->"
	_README_CONFIG_END   = "<!--END-SAMPLE-CONFIG-->"
)

type ConfigTestSuite struct {
	suite.Suite
	confStubBlob      []byte
	requiredFields    []string
	nonRequiredFields []string
}

func (suite *ConfigTestSuite) SetupSuite() {
	readmeBlob, _ := ioutil.ReadFile(_README)
	readmeString := string(readmeBlob)
	readmeString = readmeString[strings.Index(readmeString, _README_CONFIG_BEGIN)+len(_README_CONFIG_BEGIN) : strings.Index(readmeString, _README_CONFIG_END)]
	readmeString = strings.TrimSpace(readmeString)
	readmeString = strings.Trim(readmeString, "`")

	suite.confStubBlob = []byte(readmeString)

	var obj map[string]interface{}
	json.Unmarshal(suite.confStubBlob, &obj)
	for k, v := range obj {
		if v == "<placeholder>" {
			suite.requiredFields = append(suite.requiredFields, k)
		} else {
			suite.nonRequiredFields = append(suite.nonRequiredFields, k)
		}
	}
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(ConfigTestSuite))
}

// Tests good config
func (suite *ConfigTestSuite) Test_LoadConfig_BasicGood() {
	_, err := LoadConfig(suite.confStubBlob)
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
	_, err := LoadConfig([]byte(`{"f1": 11, "f2": "two"}`))
	suite.NotNil(err, "JSON with none of our fields should fail")

	// Test all required fields
	for _, field := range suite.requiredFields {
		// Missing a required field
		json.Unmarshal(suite.confStubBlob, &testObj)
		delete(testObj, field)
		testObjJSON, _ = json.Marshal(testObj)
		_, err = LoadConfig(testObjJSON)
		suite.NotNil(err, "JSON with one of our required fields missing should fail: %s", field)

		// Bad type for required field
		json.Unmarshal(suite.confStubBlob, &testObj)
		testObj[field] = false // basically guessing a wrong type
		testObjJSON, _ = json.Marshal(testObj)
		_, err = LoadConfig(testObjJSON)
		suite.NotNil(err, "JSON with one of our required fields with the wrong type should fail: %s", field)

		// One of our required fields is null
		json.Unmarshal(suite.confStubBlob, &testObj)
		testObj[field] = nil
		testObjJSON, _ = json.Marshal(testObj)
		_, err = LoadConfig(testObjJSON)
		suite.NotNil(err, "JSON with one of our required fields set to null should fail: %s", field)

		// One of our required fields is an empty string
		json.Unmarshal(suite.confStubBlob, &testObj)
		testObj[field] = ""
		testObjJSON, _ = json.Marshal(testObj)
		_, err = LoadConfig(testObjJSON)
		suite.NotNil(err, "JSON with one of our required fields set to an empty string should fail: %s", field)
	}

	// Test optional fields
	for _, field := range suite.nonRequiredFields {
		// Has incorrect type for optional field
		json.Unmarshal(suite.confStubBlob, &testObj)
		testObj[field] = false // basically guessing a wrong type
		testObjJSON, _ = json.Marshal(testObj)
		_, err = LoadConfig(testObjJSON)
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
	_, err := LoadConfig(testObjJSON)
	suite.Nil(err, "JSON with good values for our required fields but no optional fields should succeed")

	// Has all of our required fields, and all optional fields
	_, err = LoadConfig(suite.confStubBlob)
	suite.Nil(err, "JSON with all good values for required and optional fields should succeed")

	// Has null for optional fields
	json.Unmarshal(suite.confStubBlob, &testObj)
	for i := range suite.nonRequiredFields {
		testObj[suite.nonRequiredFields[i]] = nil
	}
	testObjJSON, _ = json.Marshal(testObj)
	_, err = LoadConfig(testObjJSON)
	suite.Nil(err, "JSON with null for optional values should succeed")
}

func TestDownloadURLs(t *testing.T) {

	decodedA := "a.example.com"
	encodedA := base64.StdEncoding.EncodeToString([]byte(decodedA))
	encodedB := base64.StdEncoding.EncodeToString([]byte("b.example.com"))
	encodedC := base64.StdEncoding.EncodeToString([]byte("c.example.com"))

	testCases := []struct {
		description                string
		downloadURLs               []*DownloadURL
		attempts                   int
		expectedValid              bool
		expectedCanonicalURL       string
		expectedDistinctSelections int
	}{
		{
			"missing OnlyAfterAttempts = 0",
			[]*DownloadURL{
				&DownloadURL{
					URL:               encodedA,
					OnlyAfterAttempts: 1,
				},
			},
			1,
			false,
			decodedA,
			0,
		},
		{
			"single URL, multiple attempts",
			[]*DownloadURL{
				&DownloadURL{
					URL:               encodedA,
					OnlyAfterAttempts: 0,
				},
			},
			2,
			true,
			decodedA,
			1,
		},
		{
			"multiple URLs, single attempt",
			[]*DownloadURL{
				&DownloadURL{
					URL:               encodedA,
					OnlyAfterAttempts: 0,
				},
				&DownloadURL{
					URL:               encodedB,
					OnlyAfterAttempts: 1,
				},
				&DownloadURL{
					URL:               encodedC,
					OnlyAfterAttempts: 1,
				},
			},
			1,
			true,
			decodedA,
			1,
		},
		{
			"multiple URLs, multiple attempts",
			[]*DownloadURL{
				&DownloadURL{
					URL:               encodedA,
					OnlyAfterAttempts: 0,
				},
				&DownloadURL{
					URL:               encodedB,
					OnlyAfterAttempts: 1,
				},
				&DownloadURL{
					URL:               encodedC,
					OnlyAfterAttempts: 1,
				},
			},
			2,
			true,
			decodedA,
			3,
		},
		{
			"multiple URLs, multiple attempts",
			[]*DownloadURL{
				&DownloadURL{
					URL:               encodedA,
					OnlyAfterAttempts: 0,
				},
				&DownloadURL{
					URL:               encodedB,
					OnlyAfterAttempts: 1,
				},
				&DownloadURL{
					URL:               encodedC,
					OnlyAfterAttempts: 3,
				},
			},
			4,
			true,
			decodedA,
			3,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {

			err := decodeAndValidateDownloadURLs(
				testCase.description,
				testCase.downloadURLs)

			if testCase.expectedValid {
				if err != nil {
					t.Fatalf("unexpected validation error: %s", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected validation error")
				}
				return
			}

			// Track distinct selections for each attempt; the
			// expected number of distinct should be for at least
			// one particular attempt.
			attemptDistinctSelections := make(map[int]map[string]int)
			for i := 0; i < testCase.attempts; i++ {
				attemptDistinctSelections[i] = make(map[string]int)
			}

			// Perform enough runs to account for random selection.
			runs := 1000

			attempt := 0
			for i := 0; i < runs; i++ {
				url, canonicalURL, skipVerify := selectDownloadURL(attempt, testCase.downloadURLs)
				if canonicalURL != testCase.expectedCanonicalURL {
					t.Fatalf("unexpected canonical URL: %s", canonicalURL)
				}
				if skipVerify {
					t.Fatalf("expected skipVerify")
				}
				attemptDistinctSelections[attempt][url] += 1
				attempt = (attempt + 1) % testCase.attempts
			}

			maxDistinctSelections := 0
			for _, m := range attemptDistinctSelections {
				if len(m) > maxDistinctSelections {
					maxDistinctSelections = len(m)
				}
			}

			if maxDistinctSelections != testCase.expectedDistinctSelections {
				t.Fatalf("got %d distinct selections, expected %d",
					maxDistinctSelections,
					testCase.expectedDistinctSelections)
			}
		})
	}

}
