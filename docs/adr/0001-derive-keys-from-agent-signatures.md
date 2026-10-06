# 0001: Derive age keys from ssh-agent signatures

Inherited from upstream and recorded here because the fork builds on it.

The ssh-agent protocol can only list keys and sign. age decrypts with X25519,
which needs a private scalar the agent never hands out. Keeping a separate age
identity file means a decryption secret on disk.

The plugin asks the agent to sign a fixed, salted challenge with a key whose
signatures are deterministic, then turns the signature into an X25519 key with
HKDF-SHA256. The identity file stores only the key's fingerprint and the salt.
Recipients are ordinary `age1...` keys, so encrypting needs only stock age.

Status: accepted (upstream, 2026-06; recorded 2026-10-06).

Consequences: nothing secret on disk, and keys that can't be exported still
work. In exchange, anyone who can reach the agent can derive the key, and one
leaked signature leaks it for good ([security](../security.md#who-can-decrypt)).
Changing the challenge, the HKDF inputs or the payload layout changes every
derived key, so any change needs a new payload version and a test that pins
the old derivation.

Considered options: an age identity file (secret at rest); an identity file
protected by a passphrase (a prompt every time); a hardware age plugin (the
hardware must be local to the process decrypting).
