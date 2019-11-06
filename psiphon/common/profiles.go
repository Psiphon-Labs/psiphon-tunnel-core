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
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"time"
)

// WriteRuntimeProfiles writes Go runtime profile information to a set of
// files in the specified output directory. The profiles include "heap",
// "goroutine", and other selected profiles from:
// https://golang.org/pkg/runtime/pprof/#Profile.
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
		}
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
}
