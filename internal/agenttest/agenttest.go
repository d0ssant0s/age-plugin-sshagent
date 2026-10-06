// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package agenttest provides in-memory ssh agents for tests.
package agenttest

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// New returns an in-memory agent holding one fresh ssh-ed25519 key.
func New(t testing.TB, comment string) (agent.Agent, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return WithKey(t, priv, comment)
}

// WithKey returns an in-memory agent holding priv.
func WithKey(t testing.TB, priv any, comment string) (agent.Agent, ssh.PublicKey) {
	t.Helper()
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: priv, Comment: comment}); err != nil {
		t.Fatal(err)
	}
	keys, err := kr.List()
	if err != nil {
		t.Fatal(err)
	}
	return kr, keys[0]
}

// Serve exposes ag on a unix socket, points SSH_AUTH_SOCK at it, and returns
// the socket path.
func Serve(t testing.TB, ag agent.Agent) string {
	t.Helper()
	// macOS caps unix socket paths at 104 bytes (sun_path); avoid t.TempDir()
	// which embeds the long test name. Use a short base dir + short filename.
	dir, err := os.MkdirTemp("", "ap")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(ag, conn)
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
	return sock
}
