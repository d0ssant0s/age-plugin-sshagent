// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eszio/age-plugin-sshagent/internal/agenttest"
)

const testPassword = "correct horse battery"

type result struct {
	code           int
	stdout, stderr string
}

func cli(t *testing.T, stdin string, passwords []string, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	std := streams{
		stdin:  strings.NewReader(stdin),
		stdout: &stdout,
		stderr: &stderr,
		password: func(string) ([]byte, error) {
			if len(passwords) == 0 {
				t.Fatal("unexpected password prompt")
			}
			p := passwords[0]
			passwords = passwords[1:]
			return []byte(p), nil
		},
	}
	code := run(args, std)
	return result{code, stdout.String(), stderr.String()}
}

// setup serves an in-memory agent and points the store at a fresh directory.
func setup(t *testing.T) string {
	t.Helper()
	kr, _ := agenttest.New(t, "cred@test")
	sock := agenttest.Serve(t, kr)
	t.Setenv("SSHAGENT_CRED_DIR", filepath.Join(t.TempDir(), "cred"))
	return sock
}

func initStore(t *testing.T) {
	t.Helper()
	if r := cli(t, "", []string{testPassword, testPassword}, "init"); r.code != 0 {
		t.Fatalf("init: %s", r.stderr)
	}
}

func TestInitEncryptTokenList(t *testing.T) {
	setup(t)
	initStore(t)

	if r := cli(t, "s3cret\n", nil, "encrypt", "test/example"); r.code != 0 {
		t.Fatalf("encrypt: %s", r.stderr)
	}
	r := cli(t, "", nil, "token", "test/example")
	if r.code != 0 {
		t.Fatalf("token: %s", r.stderr)
	}
	if r.stdout != "s3cret" {
		t.Errorf("token printed %q, want s3cret", r.stdout)
	}
	if r := cli(t, "", nil, "list"); r.stdout != "test/example\n" {
		t.Errorf("list printed %q", r.stdout)
	}
}

func TestInitPasswordsMustMatch(t *testing.T) {
	setup(t)
	if r := cli(t, "", []string{testPassword, "something else!"}, "init"); r.code == 0 {
		t.Error("init accepted two different passwords")
	}
}

func TestTokenUnknownCredential(t *testing.T) {
	setup(t)
	initStore(t)
	if r := cli(t, "", nil, "token", "missing"); r.code == 0 || r.stdout != "" {
		t.Errorf("unknown Credential: code %d, stdout %q", r.code, r.stdout)
	}
}

func TestExportImportAcrossStores(t *testing.T) {
	setup(t)
	initStore(t)
	cli(t, "one", nil, "encrypt", "a")
	export := filepath.Join(t.TempDir(), "export.age")

	if r := cli(t, "", []string{"wrong password!"}, "export", export); r.code == 0 {
		t.Error("export with a wrong password succeeded")
	}
	if _, err := os.Stat(export); err == nil {
		t.Error("a refused export left a file")
	}
	if r := cli(t, "", []string{testPassword}, "export", export); r.code != 0 {
		t.Fatalf("export: %s", r.stderr)
	}
	if r := cli(t, "", []string{testPassword}, "export", export); r.code == 0 {
		t.Error("export overwrote an existing file")
	}

	// A second store under another agent key, as after replacing the key.
	setup(t)
	initStore(t)
	cli(t, "other", nil, "encrypt", "b")
	if r := cli(t, "", []string{testPassword}, "import", export); r.code != 0 {
		t.Fatalf("import: %s", r.stderr)
	}
	if r := cli(t, "", nil, "token", "a"); r.stdout != "one" {
		t.Errorf("imported Credential = %q, want one", r.stdout)
	}

	cli(t, "changed", nil, "encrypt", "-f", "a")
	r := cli(t, "", []string{testPassword}, "import", export)
	if r.code == 0 {
		t.Error("conflicting import succeeded without --overwrite")
	}
	if strings.Contains(r.stderr, "one") || strings.Contains(r.stderr, "changed") {
		t.Errorf("stderr reveals a value: %s", r.stderr)
	}
	if r := cli(t, "", []string{testPassword}, "import", "--overwrite", export); r.code != 0 {
		t.Fatalf("import --overwrite: %s", r.stderr)
	}
	if r := cli(t, "", nil, "token", "a"); r.stdout != "one" {
		t.Errorf("overwritten Credential = %q, want one", r.stdout)
	}
}

// TestExecInjectsCredential runs the built binary, because exec replaces the process.
func TestExecInjectsCredential(t *testing.T) {
	sock := setup(t)
	initStore(t)
	cli(t, "s3cret", nil, "encrypt", "test/example")

	bin := filepath.Join(t.TempDir(), "sshagent-cred")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	cmd := exec.Command(bin, "exec", "-e", "TOKEN=test/example", "--", "sh", "-c", `printf %s "$TOKEN"`)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "s3cret" {
		t.Errorf("child saw %q, want s3cret", out)
	}

	bad := exec.Command(bin, "exec", "-e", "1BAD=test/example", "--", "true")
	bad.Env = cmd.Env
	if err := bad.Run(); err == nil {
		t.Error("invalid variable name accepted")
	}
}
