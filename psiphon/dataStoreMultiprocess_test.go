//go:build PSIPHON_USE_SQLITE_DB
// +build PSIPHON_USE_SQLITE_DB

/*
 * Copyright (c) 2026, Psiphon Inc.
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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

const sqliteTestRoleEnv = "PSIPHON_SQLITE_TEST_ROLE"
const sqliteTestDirectoryEnv = "PSIPHON_SQLITE_TEST_DIRECTORY"

type sqliteTestProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr bytes.Buffer
}

func TestSQLiteMultiProcess(t *testing.T) {
	role := os.Getenv(sqliteTestRoleEnv)
	if role != "" {
		runSQLiteTestProcess(t, role, os.Getenv(sqliteTestDirectoryEnv))
		return
	}

	directory := t.TempDir()
	idle := startSQLiteTestProcess(t, "idle", directory)
	idle.waitReady(t)

	db, err := datastoreOpenDB(directory, false)
	if err != nil {
		t.Fatal(err)
	}
	err = db.update(func(tx *datastoreTx) error {
		return tx.bucket([]byte("test")).put([]byte("idle"), []byte("ok"))
	})
	if err != nil {
		t.Fatal(err)
	}
	err = db.close()
	if err != nil {
		t.Fatal(err)
	}
	idle.release(t)
	idle.wait(t)

	db, err = datastoreOpenDB(directory, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.close()

	writer := startSQLiteTestProcess(t, "writer", directory)
	writer.waitReady(t)

	result := make(chan error, 1)
	go func() {
		result <- db.update(func(tx *datastoreTx) error {
			return tx.bucket([]byte("test")).put([]byte("writer"), []byte("ok"))
		})
	}()

	select {
	case err = <-result:
		t.Fatalf("concurrent write completed before release: %v", err)
	case <-time.After(1250 * time.Millisecond):
	}

	writer.release(t)
	select {
	case err = <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent write did not complete")
	}
	writer.wait(t)
}

func runSQLiteTestProcess(t *testing.T, role, directory string) {
	db, err := datastoreOpenDB(directory, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.close()

	switch role {
	case "idle":
		fmt.Fprintln(os.Stdout, "ready")
		_, err = io.ReadFull(os.Stdin, make([]byte, 1))
	case "writer":
		err = db.update(func(tx *datastoreTx) error {
			err := tx.bucket([]byte("test")).put([]byte("held"), []byte("ok"))
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, "ready")
			_, err = io.ReadFull(os.Stdin, make([]byte, 1))
			return err
		})
	default:
		t.Fatalf("invalid role: %s", role)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func startSQLiteTestProcess(
	t *testing.T, role, directory string) *sqliteTestProcess {

	process := &sqliteTestProcess{}
	process.cmd = exec.Command(os.Args[0], "-test.run=^TestSQLiteMultiProcess$")
	process.cmd.Env = append(os.Environ(),
		sqliteTestRoleEnv+"="+role,
		sqliteTestDirectoryEnv+"="+directory)
	process.cmd.Stderr = &process.stderr

	var err error
	process.stdin, err = process.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := process.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	process.stdout = bufio.NewReader(stdout)
	err = process.cmd.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if process.cmd.ProcessState == nil {
			_ = process.cmd.Process.Kill()
			_ = process.cmd.Wait()
		}
	})
	return process
}

func (process *sqliteTestProcess) waitReady(t *testing.T) {
	for {
		line, err := process.stdout.ReadString('\n')
		if err != nil {
			_ = process.cmd.Process.Kill()
			_ = process.cmd.Wait()
			t.Fatalf("helper failed: %v: %s", err, process.stderr.String())
		}
		if line == "ready\n" {
			return
		}
	}
}

func (process *sqliteTestProcess) release(t *testing.T) {
	_, err := process.stdin.Write([]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	err = process.stdin.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func (process *sqliteTestProcess) wait(t *testing.T) {
	err := process.cmd.Wait()
	if err != nil {
		t.Fatalf("helper failed: %v: %s", err, process.stderr.String())
	}
}
