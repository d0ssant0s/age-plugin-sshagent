# Security model and limitations

[README](../README.md) | [Getting started](getting-started.md) | [age-plugin-sshagent](age-plugin-sshagent.md) | [sshagent-cred](sshagent-cred.md)

Read this before you trust either tool with anything. Remember that this fork
is a proof of concept and that AI agents wrote its changes. No one has
reviewed it.

## How the key is derived

```
challenge = "age-plugin-sshagent/v1/derive" || 0x00 || salt
signature = agent.sign(ssh key, challenge, format)
info      = "age-plugin-sshagent/v1/x25519" || 0x00 || fingerprint
            [|| 0x00 || format, RSA only]
key       = HKDF-SHA256(ikm = signature, salt = salt, info = info) -> X25519 identity
```

The ssh key signs a fixed challenge. A deterministic signature always gives
the same bytes for the same key and challenge. Hashing those bytes gives the
same age key every time, without storing it anywhere. The plugin checks each
signature against the public key before using it.

The approach comes from upstream and has prior art in
[sagecipher](https://github.com/p-sherratt/sagecipher) and
[hiera-eyaml-sshagent](https://github.com/asottile/hiera-eyaml-sshagent).
age's author declined it for age itself
([FiloSottile/age#7](https://github.com/FiloSottile/age/issues/7)): the agent
protocol can only sign, and deriving encryption keys from signatures isn't
what signatures are designed for. The upstream README called it "stunt
cryptography". That's fair.

## What it protects against

- Disk exposure. Backups, synced folders, a stolen laptop image or another
  user reading your home directory find only ciphertext, public keys and
  salts.
- Copying the private key, if the key lives in a TPM or smart card. The
  attacker needs the agent to sign, so the decryption key can't leave your
  machine without a signature leaving with it.
- Plaintext secrets in config files and shell history, if programs get
  Credentials through `sshagent-cred exec` or `token`.

## Who can decrypt

Anyone who can ask your agent for a signature:

- Every process running as your user on any machine where the agent socket is
  reachable. That includes AI coding agents, editor extensions and anything
  `npm install` just ran.
- Root on every host you forward the agent to, for as long as the forwarded
  session is open.

That is broader than ssh authentication. A hijacked forwarded agent can log in
only while you're connected. Here, one signature over the challenge gives the
decryption key permanently, including for files encrypted later to the same
recipient.

So:

- Forward the agent only to hosts whose root you trust. Use a key you never
  forward if you can.
- Treat a compromised host where the agent was forwarded as a leaked key.
  Rotate the ssh key and re-encrypt.
- A confirmation prompt per signature in the agent (`ssh-add -c`, or a TPM or
  smart card PIN policy) turns "the agent is reachable" into "you approved
  this". Without one, decryption is silent.

## What it doesn't protect against

- An attacker running as your user while your agent is loaded.
- A malicious or prompt-injected AI agent in your terminal. A hook that blocks
  commands naming these tools stops accidents only. The agent can write a
  script that calls them.
- Reading a secret from a process's environment after `exec` hands it over.
- Offline guessing of a weak export password, using `export-check.age` or an
  export file.
- Metadata. Credential names, file sizes and modification times are in clear
  text.

## Pros and cons compared with other options

| Option | Secret at rest | Unattended use | Survives losing the key | Who can decrypt |
| --- | --- | --- | --- | --- |
| This fork | none | yes | only through an export | anyone reaching the agent |
| Plain age identity file | the identity file | yes | if you back up the file | anyone reading the file |
| age identity with a passphrase | encrypted identity file | no, needs the passphrase | if you back up the file and remember the passphrase | anyone with the file and passphrase |
| age-plugin-yubikey or a TPM plugin | none | with a touch or PIN policy | no | anyone with the device, its PIN and local access |
| Plaintext tool config (0600) | the secret itself | yes | if you back it up | your user, root, backups |

This fork makes sense when the key you have to protect lives in a TPM or smart
card you can only reach through a forwarded agent, and when you accept the
"anyone reaching the agent" row. If you can run a hardware plugin on the same
machine, that is the better choice.

## Key types and determinism

See [eligible keys](age-plugin-sshagent.md#eligible-keys). The plugin records
the RSA signature format in the identity and refuses another format later. An
agent that changes from SHA-512 to SHA-256 after an update would otherwise
derive a different key, and your files would no longer decrypt. Failing with
an error is better than a silent mismatch.

## Rotation and loss

- A new ssh key gives new identities. Re-encrypt files and run
  `sshagent-cred init` again in a new store, then `import` an export.
- If the ssh key is gone, files encrypted to its recipient can't be recovered.
  `sshagent-cred` exports are the only way back, so make one after adding
  Credentials.
- Prefer secrets you can reissue at their source, such as API tokens. Then
  losing the key is an inconvenience, not a disaster.

## Known gaps in this proof of concept

- No security review of the code or the scheme.
- The tests cover behavior with in-memory agents and one manual probe of a
  Windows CAPI RSA key through Pageant. Other agents, such as gpg-agent,
  YubiKey PIV and macOS Keychain, are untested.
- No signed releases, no reproducible builds and no fuzzing.
- `sshagent-cred` has no locking, no delete or rename, and no way to change
  the export password.
