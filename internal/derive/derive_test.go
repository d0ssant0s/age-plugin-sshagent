// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derive

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/eszio/age-plugin-sshagent/internal/agenttest"
)

func newEd25519Identity(t *testing.T, key ssh.PublicKey) *Identity {
	t.Helper()
	d, err := NewIdentity(key, ssh.KeyAlgoED25519)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestEd25519GoldenVector pins the ssh-ed25519 derivation to the value the
// pre-RSA code produced, so existing identities keep decrypting.
func TestEd25519GoldenVector(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	kr, key := agenttest.WithKey(t, ed25519.NewKeyFromSeed(seed), "golden")
	d := &Identity{fingerprint: sha256.Sum256(key.Marshal()), format: ssh.KeyAlgoED25519}
	for i := range d.salt {
		d.salt[i] = byte(i)
	}
	id, err := X25519(kr, key, d)
	if err != nil {
		t.Fatal(err)
	}
	const want = "age1r75y2td0u4p0m44nvg735h3eqhwz96tvr3cd9xw68kshpu46jpcsaa9jgk"
	if got := id.Recipient().String(); got != want {
		t.Errorf("recipient = %s, want %s", got, want)
	}
}

func TestDeriveDeterministic(t *testing.T) {
	kr, key := agenttest.New(t, "a@b")
	d := newEd25519Identity(t, key)
	id1, err := X25519(kr, key, d)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := X25519(kr, key, d)
	if err != nil {
		t.Fatal(err)
	}
	if id1.String() != id2.String() {
		t.Error("derivation is not deterministic")
	}
	if id1.Recipient().String() != id2.Recipient().String() {
		t.Error("recipients differ")
	}
}

func TestSaltSeparatesIdentities(t *testing.T) {
	kr, key := agenttest.New(t, "a@b")
	d1 := newEd25519Identity(t, key)
	d2 := newEd25519Identity(t, key)
	id1, err := X25519(kr, key, d1)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := X25519(kr, key, d2)
	if err != nil {
		t.Fatal(err)
	}
	if id1.String() == id2.String() {
		t.Error("identities with different salts must differ")
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	kr, key := agenttest.New(t, "a@b")
	d := newEd25519Identity(t, key)
	id, err := X25519(kr, key, d)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello mnemon")
	var ciphertext bytes.Buffer
	w, err := age.Encrypt(&ciphertext, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Re-derive from scratch, as a fresh process would.
	id2, err := X25519(kr, key, d)
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(&ciphertext, id2)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("got %q, want %q", got, plaintext)
	}
}

func TestPayloadRoundtrip(t *testing.T) {
	_, key := agenttest.New(t, "a@b")
	d := newEd25519Identity(t, key)
	parsed, err := ParseIdentity(d.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.fingerprint != d.fingerprint || parsed.salt != d.salt {
		t.Error("payload did not round-trip")
	}
}

func TestPayloadRejectsBadInput(t *testing.T) {
	if _, err := ParseIdentity([]byte{0x01, 0x02}); err == nil {
		t.Error("short payload accepted")
	}
	_, key := agenttest.New(t, "a@b")
	d := newEd25519Identity(t, key)
	enc := d.Encode()
	enc[0] = 0x7f
	if _, err := ParseIdentity(enc); err == nil {
		t.Error("unknown version accepted")
	}
}

func TestPickKeySelector(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	kr := agent.NewKeyring()
	kr.Add(agent.AddedKey{PrivateKey: priv1, Comment: "work@laptop"})
	kr.Add(agent.AddedKey{PrivateKey: priv2, Comment: "personal@laptop"})

	if _, err := PickKey(kr, ""); err == nil {
		t.Error("ambiguous pick with two eligible keys must fail")
	}
	key, err := PickKey(kr, "work")
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := kr.List()
	if string(key.Marshal()) != string(keys[0].Marshal()) {
		t.Error("selector picked the wrong key")
	}
}

func TestDeriveFromPayloadViaSocket(t *testing.T) {
	kr, key := agenttest.New(t, "sock@test")
	agenttest.Serve(t, kr)

	d := newEd25519Identity(t, key)
	id, err := FromPayload(d.Encode())
	if err != nil {
		t.Fatal(err)
	}
	direct, err := X25519(kr, key, d)
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != direct.String() {
		t.Error("socket-derived identity differs from direct derivation")
	}
}

func TestDeriveFromPayloadKeyNotLoaded(t *testing.T) {
	kr, _ := agenttest.New(t, "sock@test")
	agenttest.Serve(t, kr)

	_, other := agenttest.New(t, "other@test")
	d := newEd25519Identity(t, other)
	if _, err := FromPayload(d.Encode()); err == nil {
		t.Error("missing agent key must fail")
	}
}
