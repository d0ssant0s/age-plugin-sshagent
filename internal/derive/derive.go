// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package derive re-derives X25519 age identities from deterministic
// ssh-agent signatures, so the ssh private key never leaves the agent.
package derive

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/eszio/age-plugin-sshagent/internal/bech32"
)

const (
	// PluginName is the age plugin name: identities read AGE-PLUGIN-SSHAGENT-1...
	PluginName = "sshagent"

	// The first payload byte. Version 1 (ssh-ed25519, unchanged from
	// upstream) holds fingerprint and salt; version 2 adds the RSA signature
	// format. Bump it for any change to the layout or the derivation scheme.
	payloadV1 = 0x01
	payloadV2 = 0x02

	saltSize        = 16
	fingerprintSize = sha256.Size
	minRSABits      = 2048

	challengeContext = "age-plugin-sshagent/v1/derive"
	hkdfContext      = "age-plugin-sshagent/v1/x25519"
)

// rsaFormats are the RSA signature formats in order of preference, with their
// payload codes. All are PKCS#1 v1.5 (RFC 8332), hence deterministic; SHA-1
// ssh-rsa is never used.
var rsaFormats = []struct {
	name string
	code byte
	flag agent.SignatureFlags
}{
	{ssh.KeyAlgoRSASHA512, 2, agent.SignatureFlagRsaSha512},
	{ssh.KeyAlgoRSASHA256, 1, agent.SignatureFlagRsaSha256},
}

// Identity is the public payload encoded in an AGE-PLUGIN-SSHAGENT-1...
// string. It contains no secret material: only a reference to which agent key
// to use (a SHA-256 fingerprint), a per-identity random salt, and the
// signature format. The actual decryption key is re-derived on demand from
// the agent's signature.
type Identity struct {
	fingerprint [fingerprintSize]byte // SHA-256 of the ssh public key wire format
	salt        [saltSize]byte
	format      string // ssh signature format the agent must return
}

// NewIdentity returns an Identity for key and signature format with a fresh
// random salt.
func NewIdentity(key ssh.PublicKey, format string) (*Identity, error) {
	if err := checkFormat(key, format); err != nil {
		return nil, err
	}
	d := &Identity{fingerprint: sha256.Sum256(key.Marshal()), format: format}
	if _, err := rand.Read(d.salt[:]); err != nil {
		return nil, err
	}
	return d, nil
}

// Encode returns the payload for plugin.EncodeIdentity.
func (d *Identity) Encode() []byte {
	out := make([]byte, 0, 2+fingerprintSize+saltSize)
	if d.format == ssh.KeyAlgoED25519 {
		out = append(out, payloadV1)
	} else {
		out = append(out, payloadV2)
	}
	out = append(out, d.fingerprint[:]...)
	out = append(out, d.salt[:]...)
	for _, f := range rsaFormats {
		if f.name == d.format {
			out = append(out, f.code)
		}
	}
	return out
}

// ParseIdentity parses a payload produced by Encode.
func ParseIdentity(data []byte) (*Identity, error) {
	const v1Size = 1 + fingerprintSize + saltSize
	if len(data) == 0 {
		return nil, fmt.Errorf("malformed identity payload: empty")
	}
	d := &Identity{}
	switch {
	case data[0] == payloadV1 && len(data) == v1Size:
		d.format = ssh.KeyAlgoED25519
	case data[0] == payloadV2 && len(data) == v1Size+1:
		for _, f := range rsaFormats {
			if f.code == data[v1Size] {
				d.format = f.name
			}
		}
		if d.format == "" {
			return nil, fmt.Errorf("malformed identity payload: unknown signature format %d", data[v1Size])
		}
	case data[0] != payloadV1 && data[0] != payloadV2:
		return nil, fmt.Errorf("unsupported identity version %d (this binary supports versions %d and %d)", data[0], payloadV1, payloadV2)
	default:
		return nil, fmt.Errorf("malformed identity payload: unexpected length %d", len(data))
	}
	copy(d.fingerprint[:], data[1:1+fingerprintSize])
	copy(d.salt[:], data[1+fingerprintSize:v1Size])
	return d, nil
}

// Eligible reports why key can't back an identity, or nil if it can. Only
// keys with deterministic signatures qualify: ssh-ed25519 (RFC 8032) and
// ssh-rsa of at least 2048 bits (PKCS#1 v1.5). ECDSA signatures are
// randomized and sk-* signatures include a counter.
func Eligible(key ssh.PublicKey) error {
	switch key.Type() {
	case ssh.KeyAlgoED25519:
		return nil
	case ssh.KeyAlgoRSA:
		parsed, err := ssh.ParsePublicKey(key.Marshal())
		if err != nil {
			return err
		}
		pub, ok := parsed.(ssh.CryptoPublicKey).CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("unexpected ssh-rsa key encoding")
		}
		if bits := pub.N.BitLen(); bits < minRSABits {
			return fmt.Errorf("ssh-rsa key has %d bits, need at least %d", bits, minRSABits)
		}
		return nil
	default:
		return fmt.Errorf("unsupported ssh key type %q: only ssh-ed25519 and ssh-rsa produce deterministic signatures", key.Type())
	}
}

// checkFormat reports whether key is eligible and format is a signature
// format this plugin uses for it.
func checkFormat(key ssh.PublicKey, format string) error {
	if err := Eligible(key); err != nil {
		return err
	}
	if key.Type() == ssh.KeyAlgoED25519 && format == ssh.KeyAlgoED25519 {
		return nil
	}
	for _, f := range rsaFormats {
		if key.Type() == ssh.KeyAlgoRSA && format == f.name {
			return nil
		}
	}
	return fmt.Errorf("signature format %q does not fit a %s key", format, key.Type())
}

// challenge is the message the agent signs. It is domain-separated by a fixed
// context string and bound to the identity's salt, so the signature (and the
// key derived from it) can't be obtained by tricking the user into signing
// something else, and two identities over the same ssh key are independent.
func (d *Identity) challenge() []byte {
	c := make([]byte, 0, len(challengeContext)+1+saltSize)
	c = append(c, challengeContext...)
	c = append(c, 0x00)
	c = append(c, d.salt[:]...)
	return c
}

// X25519 asks the agent to sign the identity's challenge with the referenced
// key in the identity's signature format, and derives an X25519 age identity
// from the signature. The ssh private key never leaves the agent.
func X25519(ag agent.Agent, key ssh.PublicKey, d *Identity) (*age.X25519Identity, error) {
	if err := checkFormat(key, d.format); err != nil {
		return nil, err
	}
	challenge := d.challenge()
	sig, err := sign(ag, key, challenge, d.format)
	if err != nil {
		return nil, fmt.Errorf("ssh agent refused to sign: %v", err)
	}
	// Another format would derive another key, and the file would just fail
	// to decrypt; fail loudly instead of falling back.
	if sig.Format != d.format {
		return nil, fmt.Errorf("ssh agent returned a %s signature, the identity requires %s", sig.Format, d.format)
	}
	// A misbehaving agent would silently derive a different identity and the
	// file would just fail to decrypt; fail loudly here instead.
	if err := key.Verify(challenge, sig); err != nil {
		return nil, fmt.Errorf("ssh agent returned an invalid signature: %v", err)
	}
	info := hkdfContext + "\x00" + string(d.fingerprint[:])
	if d.format != ssh.KeyAlgoED25519 {
		info += "\x00" + d.format
	}
	secret, err := hkdf.Key(sha256.New, sig.Blob, d.salt[:], info, 32)
	if err != nil {
		return nil, err
	}
	s, err := bech32.Encode("AGE-SECRET-KEY-", secret)
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Identity(strings.ToUpper(s))
}

// FindKey locates the ssh key referenced by the identity among the keys
// currently loaded in the agent.
func FindKey(ag agent.Agent, d *Identity) (ssh.PublicKey, error) {
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("cannot list ssh agent keys: %v", err)
	}
	for _, k := range keys {
		if sha256.Sum256(k.Marshal()) == d.fingerprint {
			return k, nil
		}
	}
	return nil, fmt.Errorf("ssh key %s is not loaded in the agent: add it with ssh-add and retry",
		rawFingerprint(d.fingerprint))
}

func rawFingerprint(fp [fingerprintSize]byte) string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(fp[:])
}

// FromPayload is the full decrypt-side path: parse the payload, find the
// key in the agent, and derive the X25519 identity.
func FromPayload(data []byte) (*age.X25519Identity, error) {
	d, err := ParseIdentity(data)
	if err != nil {
		return nil, err
	}
	ag, err := Connect()
	if err != nil {
		return nil, err
	}
	key, err := FindKey(ag, d)
	if err != nil {
		return nil, err
	}
	return X25519(ag, key, d)
}

// Keygen creates an Identity for key and derives it twice, catching agents
// that don't sign deterministically before anything is encrypted to a
// recipient that could never be decrypted again. For RSA it records the first
// signature format the agent supports; decryption later demands that format.
func Keygen(ag agent.Agent, key ssh.PublicKey) (*Identity, *age.X25519Identity, error) {
	if err := Eligible(key); err != nil {
		return nil, nil, err
	}
	formats := []string{ssh.KeyAlgoED25519}
	if key.Type() == ssh.KeyAlgoRSA {
		formats = nil
		for _, f := range rsaFormats {
			formats = append(formats, f.name)
		}
	}
	var errs []string
	for _, format := range formats {
		d, err := NewIdentity(key, format)
		if err != nil {
			return nil, nil, fmt.Errorf("generating salt: %v", err)
		}
		id1, err := X25519(ag, key, d)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		id2, err := X25519(ag, key, d)
		if err != nil {
			return nil, nil, err
		}
		if id1.String() != id2.String() {
			return nil, nil, fmt.Errorf("agent produced non-deterministic %s signatures for %s; this key cannot be used", format, ssh.FingerprintSHA256(key))
		}
		return d, id1, nil
	}
	return nil, nil, fmt.Errorf("%s", strings.Join(errs, "; "))
}

func sign(ag agent.Agent, key ssh.PublicKey, data []byte, format string) (*ssh.Signature, error) {
	if format == ssh.KeyAlgoED25519 {
		return ag.Sign(key, data)
	}
	ext, ok := ag.(agent.ExtendedAgent)
	if !ok {
		return nil, fmt.Errorf("agent cannot select an RSA signature format")
	}
	for _, f := range rsaFormats {
		if f.name == format {
			return ext.SignWithFlags(key, data, f.flag)
		}
	}
	return nil, fmt.Errorf("unknown signature format %q", format)
}

// PickKey selects an eligible key from the agent. With an empty selector
// the agent must hold exactly one eligible key; otherwise the selector is
// matched as a substring of the key's comment or SHA256 fingerprint.
func PickKey(ag agent.Agent, selector string) (ssh.PublicKey, error) {
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("cannot list ssh agent keys: %v", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("the ssh agent holds no keys: add one with ssh-add")
	}

	var eligible []*agent.Key
	for _, k := range keys {
		if Eligible(k) != nil {
			continue
		}
		if selector != "" &&
			!strings.Contains(k.Comment, selector) &&
			!strings.Contains(ssh.FingerprintSHA256(k), selector) {
			continue
		}
		eligible = append(eligible, k)
	}

	switch len(eligible) {
	case 1:
		return eligible[0], nil
	case 0:
		if selector != "" {
			return nil, fmt.Errorf("no eligible agent key matches %q (run 'age-plugin-sshagent list')", selector)
		}
		return nil, fmt.Errorf("the ssh agent holds no eligible keys (ssh-ed25519, or ssh-rsa of at least %d bits; run 'age-plugin-sshagent list')", minRSABits)
	default:
		var lines []string
		for _, k := range eligible {
			lines = append(lines, fmt.Sprintf("  %s %s", ssh.FingerprintSHA256(k), k.Comment))
		}
		return nil, fmt.Errorf("multiple eligible keys match; pick one with -k:\n%s", strings.Join(lines, "\n"))
	}
}
