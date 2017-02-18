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
	"encoding/json"
	"io/ioutil"
	"testing"
)

type Diagnostics struct {
	Feedback struct {
		Message struct {
			Text string `json:"text"`
		}
		Email string `json:"email"`
	}
	Metadata struct {
		Id       string `json:"id"`
		Platform string `json:"platform"`
		Version  int    `json:"version"`
	}
}

func TestFeedbackUpload(t *testing.T) {
	configFileContents, err := ioutil.ReadFile("feedback_test.config")
	if err != nil {
		// Skip, don't fail, if config file is not present
		t.Skipf("error loading configuration file: %s", err)
	}

	shortRevHash, err := ioutil.ReadFile("git_rev")
	if err != nil {
		// Skip, don't fail, if git rev file is not present
		t.Skipf("error loading git revision file: %s", err)
	}

	var config map[string]interface{}

	err = json.Unmarshal(configFileContents, &config)
	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}

	// Form dummy feedback data which can be verified later
	diagnostics := Diagnostics{}
	diagnostics.Feedback.Message.Text = "Travis test feedback. Revision " + string(shortRevHash)
	diagnostics.Metadata.Id = "0000000000000000"
	diagnostics.Metadata.Platform = "android"
	diagnostics.Metadata.Version = 4

	diagnosticData, err := json.Marshal(diagnostics)
	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}

	err = SendFeedback(string(configFileContents), string(diagnosticData), config["ENCRYPTION_PUBLIC_KEY"].(string), config["UPLOAD_SERVER"].(string), config["UPLOAD_PATH"].(string), config["UPLOAD_SERVER_HEADERS"].(string))
	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
}
