// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derive

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/eszio/age-plugin-sshagent/internal/agenttest"
)

func rsaAgent(t *testing.T, bits int) (agent.Agent, ssh.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return agenttest.WithKey(t, priv, "CAPI:test (RSA)")
}

// noSHA512 refuses rsa-sha2-512, like an agent whose key store can't hash SHA-512.
type noSHA512 struct{ agent.ExtendedAgent }

func (a noSHA512) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if flags&agent.SignatureFlagRsaSha512 != 0 {
		return nil, errors.New("sha-512 not supported")
	}
	return a.ExtendedAgent.SignWithFlags(key, data, flags)
}

// downgrading answers an rsa-sha2-512 request with an rsa-sha2-256 signature.
type downgrading struct{ agent.ExtendedAgent }

func (a downgrading) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	return a.ExtendedAgent.SignWithFlags(key, data, agent.SignatureFlagRsaSha256)
}

func TestRSAKeygenPrefersSHA512AndRoundtrips(t *testing.T) {
	kr, key := rsaAgent(t, 2048)
	d, id, err := Keygen(kr, key)
	if err != nil {
		t.Fatal(err)
	}
	if d.format != ssh.KeyAlgoRSASHA512 {
		t.Fatalf("format = %q, want %q", d.format, ssh.KeyAlgoRSASHA512)
	}

	var ciphertext bytes.Buffer
	w, err := age.Encrypt(&ciphertext, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("rsa secret"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	agenttest.Serve(t, kr)
	again, err := FromPayload(d.Encode())
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(&ciphertext, again)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r)
	if string(got) != "rsa secret" {
		t.Errorf("got %q", got)
	}
}

func TestRSAKeygenFallsBackToSHA256(t *testing.T) {
	kr, key := rsaAgent(t, 2048)
	ag := noSHA512{kr.(agent.ExtendedAgent)}
	d, _, err := Keygen(ag, key)
	if err != nil {
		t.Fatal(err)
	}
	if d.format != ssh.KeyAlgoRSASHA256 {
		t.Fatalf("format = %q, want %q", d.format, ssh.KeyAlgoRSASHA256)
	}
}

func TestRSANoFallbackAfterKeygen(t *testing.T) {
	kr, key := rsaAgent(t, 2048)
	d, _, err := Keygen(kr, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := X25519(noSHA512{kr.(agent.ExtendedAgent)}, key, d); err == nil {
		t.Error("an agent refusing the recorded format must fail, not fall back")
	}
	if _, err := X25519(downgrading{kr.(agent.ExtendedAgent)}, key, d); err == nil {
		t.Error("a signature in another format must be rejected")
	}
}

func TestRSAFormatSeparatesIdentities(t *testing.T) {
	kr, key := rsaAgent(t, 2048)
	d512, err := NewIdentity(key, ssh.KeyAlgoRSASHA512)
	if err != nil {
		t.Fatal(err)
	}
	d256 := *d512
	d256.format = ssh.KeyAlgoRSASHA256
	id512, err := X25519(kr, key, d512)
	if err != nil {
		t.Fatal(err)
	}
	id256, err := X25519(kr, key, &d256)
	if err != nil {
		t.Fatal(err)
	}
	if id512.String() == id256.String() {
		t.Error("identities for different signature formats must differ")
	}
}

func TestPayloadVersions(t *testing.T) {
	_, edKey := agenttest.New(t, "ed@b")
	ed, err := NewIdentity(edKey, ssh.KeyAlgoED25519)
	if err != nil {
		t.Fatal(err)
	}
	if v := ed.Encode()[0]; v != 0x01 {
		t.Errorf("ssh-ed25519 payload version = %d, want 1 (unchanged from upstream)", v)
	}

	_, rsaKey := rsaAgent(t, 2048)
	for _, format := range []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512} {
		d, err := NewIdentity(rsaKey, format)
		if err != nil {
			t.Fatal(err)
		}
		enc := d.Encode()
		if enc[0] != 0x02 {
			t.Errorf("%s payload version = %d, want 2", format, enc[0])
		}
		parsed, err := ParseIdentity(enc)
		if err != nil {
			t.Fatal(err)
		}
		if *parsed != *d {
			t.Errorf("%s payload did not round-trip", format)
		}
	}

	bad, _ := NewIdentity(rsaKey, ssh.KeyAlgoRSASHA512)
	enc := bad.Encode()
	enc[len(enc)-1] = 0x7f
	if _, err := ParseIdentity(enc); err == nil {
		t.Error("unknown signature format code accepted")
	}
}

func TestRejectsIneligibleKeys(t *testing.T) {
	small, smallKey := rsaAgent(t, 1024)
	if _, _, err := Keygen(small, smallKey); err == nil {
		t.Error("1024-bit rsa key accepted")
	}
	if _, err := PickKey(small, ""); err == nil {
		t.Error("1024-bit rsa key picked")
	}

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecAgent, ecKey := agenttest.WithKey(t, ec, "ec@b")
	if _, _, err := Keygen(ecAgent, ecKey); err == nil {
		t.Error("ecdsa key accepted: its signatures are randomized")
	}
	if _, err := PickKey(ecAgent, ""); err == nil {
		t.Error("ecdsa key picked")
	}
}

func TestPickKeyWithEd25519AndRSA(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: edPriv, Comment: "bgroup\\user@laptop"}); err != nil {
		t.Fatal(err)
	}
	if err := kr.Add(agent.AddedKey{PrivateKey: rsaPriv, Comment: "CAPI:abc (RSA)"}); err != nil {
		t.Fatal(err)
	}
	if _, err := PickKey(kr, ""); err == nil {
		t.Error("two eligible keys without a selector must be ambiguous")
	}
	key, err := PickKey(kr, "CAPI")
	if err != nil {
		t.Fatal(err)
	}
	if key.Type() != ssh.KeyAlgoRSA {
		t.Errorf("picked %s, want ssh-rsa", key.Type())
	}
}
