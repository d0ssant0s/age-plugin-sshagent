// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"
)

const password = "correct horse battery"

func newStore(t *testing.T) (*Store, *age.X25519Identity) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{Dir: filepath.Join(t.TempDir(), "cred"), scryptWorkFactor: 10}
	if err := s.Init("AGE-PLUGIN-SSHAGENT-1TEST\n", id.Recipient().String(), []byte(password)); err != nil {
		t.Fatal(err)
	}
	return s, id
}

func TestPutGetRoundtrip(t *testing.T) {
	s, id := newStore(t)
	if err := s.Put("test/example", []byte("s3cret\n"), false); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("test/example", id)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "s3cret" {
		t.Errorf("got %q, want the value without its trailing newline", got)
	}
	info, err := os.Stat(filepath.Join(s.Dir, "store", "test", "example.age"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestPutRefusesOverwriteUnlessForced(t *testing.T) {
	s, id := newStore(t)
	if err := s.Put("a", []byte("one"), false); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("a", []byte("two"), false); err == nil {
		t.Error("existing Credential overwritten without force")
	}
	if err := s.Put("a", []byte("two"), true); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get("a", id)
	if string(got) != "two" {
		t.Errorf("got %q, want two", got)
	}
}

func TestPutRejectsBadInput(t *testing.T) {
	s, _ := newStore(t)
	for _, name := range []string{"", "../x", "/abs", "a/../b", ".hidden", "a//b", "Upper", "a b", "a/"} {
		if err := s.Put(name, []byte("v"), false); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	if err := s.Put("empty", []byte("\n"), false); err == nil {
		t.Error("empty value accepted")
	}
	if err := s.Put("binary", []byte{0xff, 0xfe}, false); err == nil {
		t.Error("non-UTF-8 value accepted")
	}
}

func TestGetUnknown(t *testing.T) {
	s, id := newStore(t)
	if _, err := s.Get("missing", id); err == nil {
		t.Error("unknown Credential returned a value")
	}
}

func TestList(t *testing.T) {
	s, _ := newStore(t)
	for _, name := range []string{"b", "a/x", "a/y"} {
		if err := s.Put(name, []byte("v"), false); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a/x", "a/y", "b"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestInitRefusesExistingStore(t *testing.T) {
	s, id := newStore(t)
	if err := s.Init("x\n", id.Recipient().String(), []byte(password)); err == nil {
		t.Error("init overwrote an existing store")
	}
}

func TestInitRejectsShortPassword(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	s := &Store{Dir: filepath.Join(t.TempDir(), "cred"), scryptWorkFactor: 10}
	if err := s.Init("x\n", id.Recipient().String(), []byte("short")); err == nil {
		t.Error("short export password accepted")
	}
}

func TestCheckPassword(t *testing.T) {
	s, _ := newStore(t)
	if err := s.CheckPassword([]byte(password)); err != nil {
		t.Errorf("right password rejected: %v", err)
	}
	if err := s.CheckPassword([]byte("wrong password!")); err == nil {
		t.Error("wrong password accepted")
	}
	check, err := os.ReadFile(filepath.Join(s.Dir, "export-check.age"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(check, []byte(password)) {
		t.Error("the password is readable from the store")
	}
}

func exportAll(t *testing.T, s *Store, id age.Identity) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := s.Export(&buf, id, []byte(password)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExportNeedsThePassword(t *testing.T) {
	s, id := newStore(t)
	s.Put("a", []byte("v"), false)
	if err := s.Export(io.Discard, id, []byte("wrong password!")); err == nil {
		t.Error("export with a wrong password succeeded")
	}
}

func TestExportIsReadableWithStockAge(t *testing.T) {
	s, id := newStore(t)
	s.Put("test/example", []byte("s3cret"), false)
	exported := exportAll(t, s, id)

	pw, err := age.NewScryptIdentity(password)
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(bytes.NewReader(exported), pw)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(r)
	if want := `{"name":"test/example","value":"s3cret"}` + "\n"; string(plain) != want {
		t.Errorf("got %q, want %q", plain, want)
	}
}

func TestImportIntoNewStore(t *testing.T) {
	src, srcID := newStore(t)
	src.Put("a", []byte("one"), false)
	src.Put("b/c", []byte("two"), false)
	exported := exportAll(t, src, srcID)

	dst, dstID := newStore(t)
	res, err := dst.Import(bytes.NewReader(exported), dstID, []byte(password), false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 2 || res.Unchanged != 0 || len(res.Conflicts) != 0 {
		t.Errorf("result = %+v", res)
	}
	got, _ := dst.Get("b/c", dstID)
	if string(got) != "two" {
		t.Errorf("got %q, want two", got)
	}
}

func TestImportMergeRefusesConflicts(t *testing.T) {
	src, srcID := newStore(t)
	src.Put("same", []byte("v"), false)
	src.Put("differs", []byte("new"), false)
	src.Put("added", []byte("x"), false)
	exported := exportAll(t, src, srcID)

	dst, dstID := newStore(t)
	dst.Put("same", []byte("v"), false)
	dst.Put("differs", []byte("old"), false)

	res, err := dst.Import(bytes.NewReader(exported), dstID, []byte(password), false)
	if err == nil {
		t.Fatal("conflicting import succeeded")
	}
	if !slices.Equal(res.Conflicts, []string{"differs"}) {
		t.Errorf("conflicts = %v, want [differs]", res.Conflicts)
	}
	if strings.Contains(err.Error(), "new") || strings.Contains(err.Error(), "old") {
		t.Errorf("error reveals a value: %v", err)
	}
	if names, _ := dst.List(); slices.Contains(names, "added") {
		t.Error("a refused import must write nothing")
	}

	res, err = dst.Import(bytes.NewReader(exported), dstID, []byte(password), true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 || res.Unchanged != 1 || res.Overwritten != 1 {
		t.Errorf("result = %+v", res)
	}
	got, _ := dst.Get("differs", dstID)
	if string(got) != "new" {
		t.Errorf("got %q, want new", got)
	}
}

func TestImportNeedsThePassword(t *testing.T) {
	src, srcID := newStore(t)
	src.Put("a", []byte("v"), false)
	exported := exportAll(t, src, srcID)

	dst, dstID := newStore(t)
	if _, err := dst.Import(bytes.NewReader(exported), dstID, []byte("wrong password!"), false); err == nil {
		t.Error("import with a wrong password succeeded")
	}
}
