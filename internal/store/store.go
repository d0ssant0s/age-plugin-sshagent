// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package store keeps Credentials as one age file each, encrypted to a single
// recipient, plus a password check for exports.
package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
)

const (
	identityFile    = "identity.txt"
	recipientFile   = "recipient.txt"
	exportCheckFile = "export-check.age"
	credentialDir   = "store"
	extension       = ".age"

	exportCheck       = "sshagent-cred export check v1"
	minPasswordLength = 12
)

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$`)

// Store is a Credential store in Dir.
type Store struct {
	Dir string

	// scryptWorkFactor overrides age's default for the export password; tests only.
	scryptWorkFactor int
}

// ImportResult counts what an import did, or would have done when it was refused.
type ImportResult struct {
	Added, Unchanged, Overwritten int
	Conflicts                     []string
}

type exported struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Init creates the store: the identity file (no secret), the recipient
// Credentials are encrypted to, and a check of the export password.
func (s *Store) Init(identity, recipient string, password []byte) error {
	if _, err := os.Stat(filepath.Join(s.Dir, identityFile)); err == nil {
		return fmt.Errorf("%s already holds a Credential store", s.Dir)
	}
	if _, err := age.ParseX25519Recipient(recipient); err != nil {
		return err
	}
	if len(password) < minPasswordLength {
		return fmt.Errorf("the export password needs at least %d characters", minPasswordLength)
	}
	if err := os.MkdirAll(filepath.Join(s.Dir, credentialDir), 0o700); err != nil {
		return err
	}
	check, err := s.encryptWithPassword([]byte(exportCheck), password)
	if err != nil {
		return err
	}
	for name, content := range map[string][]byte{
		identityFile:    []byte(identity),
		recipientFile:   []byte(recipient + "\n"),
		exportCheckFile: check,
	} {
		if err := writeFile(filepath.Join(s.Dir, name), content); err != nil {
			return err
		}
	}
	return nil
}

// IdentityFile returns the path of the store's identity file.
func (s *Store) IdentityFile() string {
	return filepath.Join(s.Dir, identityFile)
}

// Put encrypts value as Credential name. One trailing newline is dropped, so
// `echo token | sshagent-cred encrypt NAME` stores just the token.
func (s *Store) Put(name string, value []byte, force bool) error {
	path, err := s.path(name)
	if err != nil {
		return err
	}
	value = bytes.TrimSuffix(value, []byte("\n"))
	if len(value) == 0 {
		return errors.New("the value is empty")
	}
	if !utf8.Valid(value) {
		return errors.New("the value is not UTF-8 text")
	}
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("Credential %s exists; replace it with -f", name)
	}
	recipient, err := s.recipient()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return err
	}
	if _, err := w.Write(value); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFile(path, buf.Bytes())
}

// Get decrypts Credential name with id.
func (s *Store) Get(name string, id age.Identity) ([]byte, error) {
	path, err := s.path(name)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no Credential %s", name)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, id)
	if err != nil {
		return nil, fmt.Errorf("decrypting %s: %v", name, err)
	}
	return io.ReadAll(r)
}

// List returns the Credential names in order.
func (s *Store) List() ([]string, error) {
	root := filepath.Join(s.Dir, credentialDir)
	var names []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, extension) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		names = append(names, filepath.ToSlash(strings.TrimSuffix(rel, extension)))
		return nil
	})
	slices.Sort(names)
	return names, err
}

// CheckPassword reports whether password is the export password set at Init.
func (s *Store) CheckPassword(password []byte) error {
	f, err := os.Open(filepath.Join(s.Dir, exportCheckFile))
	if err != nil {
		return err
	}
	defer f.Close()
	got, err := decryptWithPassword(f, password)
	if err != nil || string(got) != exportCheck {
		return errors.New("wrong export password")
	}
	return nil
}

// Export writes every Credential as JSON Lines, encrypted with the export
// password. Stock `age -d` reads it with that password alone.
func (s *Store) Export(w io.Writer, id age.Identity, password []byte) error {
	if err := s.CheckPassword(password); err != nil {
		return err
	}
	names, err := s.List()
	if err != nil {
		return err
	}
	var plain bytes.Buffer
	enc := json.NewEncoder(&plain)
	enc.SetEscapeHTML(false)
	for _, name := range names {
		value, err := s.Get(name, id)
		if err != nil {
			return err
		}
		if err := enc.Encode(exported{Name: name, Value: string(value)}); err != nil {
			return err
		}
	}
	out, err := s.encryptWithPassword(plain.Bytes(), password)
	if err != nil {
		return err
	}
	_, err = w.Write(out)
	return err
}

// Import reads an export made with password. Missing Credentials are added
// and identical ones left alone. A differing one is a conflict that refuses
// the whole import, writing nothing, unless overwrite is set.
func (s *Store) Import(r io.Reader, id age.Identity, password []byte, overwrite bool) (ImportResult, error) {
	var res ImportResult
	plain, err := decryptWithPassword(r, password)
	if err != nil {
		return res, fmt.Errorf("decrypting the export: %v", err)
	}
	var writes []exported
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(plain))
	scanner.Buffer(nil, len(plain)+1)
	for scanner.Scan() {
		var e exported
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return res, fmt.Errorf("malformed export: %v", err)
		}
		if _, err := s.path(e.Name); err != nil {
			return res, err
		}
		if seen[e.Name] {
			return res, fmt.Errorf("malformed export: %s appears twice", e.Name)
		}
		seen[e.Name] = true
		current, err := s.Get(e.Name, id)
		switch {
		case err != nil && !s.exists(e.Name):
			res.Added++
			writes = append(writes, e)
		case err != nil:
			return res, err
		case string(current) == e.Value:
			res.Unchanged++
		default:
			res.Conflicts = append(res.Conflicts, e.Name)
			res.Overwritten++
			writes = append(writes, e)
		}
	}
	if err := scanner.Err(); err != nil {
		return res, err
	}
	if len(res.Conflicts) > 0 && !overwrite {
		res.Overwritten = 0
		return res, fmt.Errorf("%d Credentials differ from the export (%s); nothing imported, use --overwrite to replace them",
			len(res.Conflicts), strings.Join(res.Conflicts, ", "))
	}
	for _, e := range writes {
		if err := s.Put(e.Name, []byte(e.Value), true); err != nil {
			return res, err
		}
	}
	return res, nil
}

func (s *Store) exists(name string) bool {
	path, err := s.path(name)
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

func (s *Store) path(name string) (string, error) {
	if len(name) > 200 || !namePattern.MatchString(name) {
		return "", fmt.Errorf("invalid Credential name %q: use lowercase segments of a-z, 0-9, '.', '_', '-' separated by '/'", name)
	}
	return filepath.Join(s.Dir, credentialDir, filepath.FromSlash(name)+extension), nil
}

func (s *Store) recipient() (age.Recipient, error) {
	data, err := os.ReadFile(filepath.Join(s.Dir, recipientFile))
	if err != nil {
		return nil, fmt.Errorf("%v (run sshagent-cred init)", err)
	}
	return age.ParseX25519Recipient(strings.TrimSpace(string(data)))
}

func (s *Store) encryptWithPassword(plain, password []byte) ([]byte, error) {
	r, err := age.NewScryptRecipient(string(password))
	if err != nil {
		return nil, err
	}
	if s.scryptWorkFactor > 0 {
		r.SetWorkFactor(s.scryptWorkFactor)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decryptWithPassword(r io.Reader, password []byte) ([]byte, error) {
	id, err := age.NewScryptIdentity(string(password))
	if err != nil {
		return nil, err
	}
	plain, err := age.Decrypt(r, id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(plain)
}

// writeFile replaces path atomically with a 0600 file.
func writeFile(path string, content []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
