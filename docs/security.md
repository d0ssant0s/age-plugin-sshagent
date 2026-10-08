# Security model and limitations

[README](../README.md) | [Getting started](getting-started.md) | [age-plugin-sshagent](age-plugin-sshagent.md) | [sshagent-cred](sshagent-cred.md)

Read this before you trust either tool with anything. This fork is a proof of
concept, and AI agents wrote its changes. Different agents and models have
read the code. This checkout can name one pass: Grok 4.7 in GitHub Copilot,
on 2026-10-08. Other passes are not listed, because this environment has no
record of them. None of that is a human review, and none of it clears an
open finding. Whether each finding was implemented, accepted, or rejected
is tracked in
[docs/reviews/2026-10-08-security.md](reviews/2026-10-08-security.md).

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
- Plaintext secrets in config files and shell history, if you pass a
  Credential with `exec` and do not put the secret on a command line.
  `token` still writes the value to stdout. A variable the shell already
  set can hide the Credential.

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
  export file. The password does not stop `token` or `exec`. Those commands
  need no password.
- Metadata. Credential names, file sizes and modification times are in clear
  text.
- A store you copied, synced, or pulled. `encrypt` trusts `recipient.txt`
  and does not ask the agent. Compare a fresh recipient before you encrypt
  into a store you did not just create:
  `age-plugin-sshagent recipient -i identity.txt`.
- A shell variable that is already set. `exec` appends `NAME=value` and, on
  Linux and on macOS, the first value wins. The program then runs with the
  old value and no error. Unset the name first.
- A short `-k` match, and whatever agent `SSH_AUTH_SOCK` points at when you
  run `keygen` or `init`. A unique substring is used even when it is the
  wrong key. Read the full fingerprint before you encrypt to the new
  recipient.
- `age -e -i identity.txt`. That asks the agent to sign, same as decryption.
  `age -e -r age1...` does not run the plugin.
- Whatever binary named `age-plugin-sshagent` is first on `PATH`. It receives
  the identity stanza and can ask the agent to sign while it runs as you.
- A parent of the process. The password prompt is real against stdin and
  the environment. It is not real against a parent that can trace the child.
  On the machine where this was reviewed, Yama `ptrace_scope` was 1, which
  allows that. A wrapper earlier on `PATH` is enough too.
- The agent confirmation prompt, if you only look at the text. The challenge
  starts with `age-plugin-sshagent/v1/derive` every time. The prompt does not
  name the file or the Credential. It still stops a silent signature.

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

- The 2026-10-08 review is an AI read of the tree, not a human review, and
  not a proof of the signature-to-key construction. Open code items are
  still open: `exec` does not replace an existing variable, `encrypt` trusts
  `recipient.txt`, a NUL is accepted as text, and `import` does not roll
  back. The error string says characters. The check is 12 bytes. `init`
  does not tighten a store directory that already exists.
- `keygen` checks that two signatures match. Decrypt does not repeat that
  check. A later mismatch fails decryption. It does not return someone
  else's plaintext.
- Passwords, HKDF output, and Credential bytes are not wiped. Do not treat
  a best-effort zeroing patch as a fix.
- The tests cover behavior with in-memory agents and one manual probe of a
  Windows CAPI RSA key through Pageant. Other agents, such as gpg-agent,
  YubiKey PIV and macOS Keychain, are untested.
- No signed releases, no reproducible builds and no fuzzing.
- `sshagent-cred` has no locking, no delete or rename, and no way to change
  the export password.
