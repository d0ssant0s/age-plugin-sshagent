# 0002: Accept RSA keys with a pinned signature format

Upstream accepted only `ssh-ed25519`, on the grounds that RSA agents "may use
randomized PSS padding". The SSH agent protocol has no PSS. Its RSA signatures
(`ssh-rsa`, `rsa-sha2-256`, `rsa-sha2-512`) are PKCS#1 v1.5 (RFC 8332), and
those are deterministic. The key the maintainer wanted to use is a TPM-backed
RSA key exposed as a Windows CAPI key through Pageant. A TPM key can't be
exported, which a software Ed25519 key in Pageant can.

The plugin accepts `ssh-rsa` keys of at least 2048 bits. `keygen` asks for
`rsa-sha2-512`, falls back to `rsa-sha2-256`, derives twice and records the
format that worked in a version 2 identity payload. The format is also mixed
into the HKDF `info`. Decryption requests exactly that format and fails if the
agent returns another. SHA-1 `ssh-rsa` signatures are never used. Ed25519
identities keep payload version 1 and the upstream derivation, pinned by a
golden test.

Status: accepted (2026-10-06). On 2026-10-06 a `keygen` against the TPM key
picked `rsa-sha2-512` and both derivations matched.

Consequences: TPM and smart-card RSA keys work. If an agent update ever stops
signing the recorded format, decryption stops with a clear error rather than
deriving a different key, and the user has to find an agent that signs it
again or restore from an export. RSA identities don't work with the upstream
plugin.

Considered options: Ed25519 only (excludes keys that can't be exported); RSA
with whatever format the agent picks (a silent format change would make every
file unreadable); allowing SHA-1 (not needed, and a bad default).
