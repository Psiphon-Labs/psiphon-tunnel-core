/*
 * Copyright (c) 2018, Psiphon Inc.
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

package common

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"time"
)

// profileManifestName is the completion marker WriteRuntimeProfiles writes
// last, atomically, into the output directory: a collector watching the
// directory (a host agent that ships the profiles elsewhere) takes a
// manifest newer than its trigger as "the collection is complete" and its
// files list as exactly what to ship, instead of guessing from timestamps.
const profileManifestName = "manifest.json"

// profileManifest is the manifest's content: when the collection completed
// and the base names of the profile files it wrote.
type profileManifest struct {
	CompletedAt time.Time `json:"completed_at"`
	Files       []string  `json:"files"`
}

// WriteRuntimeProfiles writes Go runtime profile information to a set of
// files in the specified output directory, creating the directory when it
// does not exist. The profiles include "heap", "goroutine", and other
// selected profiles from: https://golang.org/pkg/runtime/pprof/#Profile.
//
// The SampleDurationSeconds inputs determine how long to wait and sample
// profiles that require active sampling. When set to 0, these profiles are
// skipped.
func WriteRuntimeProfiles(
	logger Logger,
	outputDirectory string,
	filenameSuffix string,
	blockSampleDurationSeconds int,
	cpuSampleDurationSeconds int) {

	if err := os.MkdirAll(outputDirectory, 0755); err != nil {
		logger.WithTraceFields(
			LogFields{
				"error":     err,
				"directory": outputDirectory}).Error("create profile directory failed")
		return
	}

	// written collects the base names of the profile files written in full,
	// for the manifest.
	var written []string

	openProfileFile := func(profileName string) *os.File {
		filename := filepath.Join(outputDirectory, profileName+".profile")
		if filenameSuffix != "" {
			filename += "." + filenameSuffix
		}
		file, err := os.OpenFile(
			filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
		if err != nil {
			logger.WithTraceFields(
				LogFields{
					"error":    err,
					"fileName": filename}).Error("open profile file failed")
			return nil
		}
		return file
	}

	writeProfile := func(profileName string) {

		file := openProfileFile(profileName)
		if file == nil {
			return
		}
		err := pprof.Lookup(profileName).WriteTo(file, 1)
		file.Close()
		if err != nil {
			logger.WithTraceFields(
				LogFields{
					"error":       err,
					"profileName": profileName}).Error("write profile failed")
			return
		}
		written = append(written, filepath.Base(file.Name()))
	}

	// TODO: capture https://golang.org/pkg/runtime/debug/#WriteHeapDump?
	// May not be useful in its current state, as per:
	// https://groups.google.com/forum/#!topic/golang-dev/cYAkuU45Qyw

	// Write goroutine, heap, and threadcreate profiles
	// https://golang.org/pkg/runtime/pprof/#Profile
	writeProfile("goroutine")
	writeProfile("heap")
	writeProfile("threadcreate")

	// Write CPU profile (after sampling)
	// https://golang.org/pkg/runtime/pprof/#StartCPUProfile

	if cpuSampleDurationSeconds > 0 {
		file := openProfileFile("cpu")
		if file != nil {
			logger.WithTrace().Info("start cpu profiling")
			err := pprof.StartCPUProfile(file)
			if err != nil {
				logger.WithTraceFields(
					LogFields{"error": err}).Error("StartCPUProfile failed")
			} else {
				time.Sleep(time.Duration(cpuSampleDurationSeconds) * time.Second)
				pprof.StopCPUProfile()
				logger.WithTrace().Info("end cpu profiling")
				written = append(written, filepath.Base(file.Name()))
			}
			file.Close()
		}
	}

	// Write block profile (after sampling)
	// https://golang.org/pkg/runtime/pprof/#Profile

	if blockSampleDurationSeconds > 0 {
		logger.WithTrace().Info("start block/mutex profiling")
		runtime.SetBlockProfileRate(1)
		runtime.SetMutexProfileFraction(1)
		time.Sleep(time.Duration(blockSampleDurationSeconds) * time.Second)
		runtime.SetBlockProfileRate(0)
		runtime.SetMutexProfileFraction(0)
		logger.WithTrace().Info("end block/mutex profiling")
		writeProfile("block")
		writeProfile("mutex")
	}

	writeProfileManifest(logger, outputDirectory, written)
}

// writeProfileManifest writes the completion manifest last and atomically
// (a temporary file renamed into place), so a collector can never observe
// a manifest describing a half-finished collection. A collection that wrote
// no profile gets no manifest: there is nothing to collect, and the write
// failures were already logged.
func writeProfileManifest(logger Logger, outputDirectory string, files []string) {
	if len(files) == 0 {
		return
	}
	content, err := json.Marshal(profileManifest{CompletedAt: time.Now(), Files: files})
	if err != nil {
		logger.WithTraceFields(
			LogFields{"error": err}).Error("marshal profile manifest failed")
		return
	}
	manifest := filepath.Join(outputDirectory, profileManifestName)
	tmp := manifest + ".tmp"
	if err := os.WriteFile(tmp, content, 0666); err != nil {
		logger.WithTraceFields(
			LogFields{"error": err, "fileName": tmp}).Error("write profile manifest failed")
		return
	}
	if err := os.Rename(tmp, manifest); err != nil {
		logger.WithTraceFields(
			LogFields{"error": err, "fileName": manifest}).Error("commit profile manifest failed")
		return
	}
	logger.WithTraceFields(
		LogFields{"fileName": manifest, "files": len(files)}).Info("wrote profile manifest")
}
