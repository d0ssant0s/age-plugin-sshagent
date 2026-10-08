# age-plugin-sshagent (experimental fork)

> **Status: proof of concept.** This fork is an experiment. Its changes to the
> upstream code, and all of this documentation, were written by AI coding
> agents under the maintainer's direction. Different agents and models have
> read the code. That is not a human review, and it does not clear the open
> findings in
> [the 2026-10-08 security review](docs/reviews/2026-10-08-security.md).
> Don't protect anything with it that you can't afford to lose or to have
> read by others.

This repository holds two command-line tools that turn a key in your
ssh-agent into an [age](https://age-encryption.org) decryption key:

- `age-plugin-sshagent` is an age plugin. `age -d` uses it to decrypt files
  encrypted to an `age1...` recipient derived from your ssh key.
- `sshagent-cred` keeps named secrets, such as API tokens, encrypted with that
  same derived key, and hands them to programs that need them.

The private key never leaves the agent, and nothing secret is written to disk.
Decryption works whenever the agent holding the key is reachable, without a
prompt.

It is a fork of
[eszio/age-plugin-sshagent](https://github.com/eszio/age-plugin-sshagent) at
commit `8bc67c4`. The fork adds RSA keys (for keys held in a TPM or smart card)
and `sshagent-cred`. It has diverged on purpose and is not meant to go back
upstream.

## Should you use it?

Use it to learn from, or for secrets you can reissue at any time. The design
trades a real security property for convenience.

What you gain:

- No decryption secret at rest. The identity file holds only a key fingerprint
  and a random salt, so backups, synced dotfiles or a stolen disk image don't
  contain anything that decrypts your files.
- Keys that can't be exported still work. A TPM- or smart-card-backed RSA key
  in Pageant can decrypt files on a Linux host you reach over SSH.
- Encrypting needs nothing special. Anyone with stock `age` and your `age1...`
  recipient can encrypt to you.
- Scripts can decrypt unattended while the agent holds the key, because
  there's no password prompt.

What you give up:

- Anything that can talk to your agent can decrypt. That includes every
  process running as your user (AI coding agents too) and root on every host
  you forward the agent to.
- One leaked signature is a permanent leak. Someone who gets the agent to sign
  the challenge once can derive the key forever. You can't revoke it. You have
  to change the ssh key and re-encrypt everything.
- No consent per use. Unless your agent asks before each signature, a program
  can decrypt without you noticing.
- Lose the ssh key, lose the data. Only a `sshagent-cred` export, protected by
  a password, survives that.
- Deriving encryption keys from signatures is unusual, and age's author
  declined to support it ([FiloSottile/age#7](https://github.com/FiloSottile/age/issues/7)).

[docs/security.md](docs/security.md) explains each point and lists the
remaining limitations.

## Quick start

You need Linux or macOS, Go 1.25 or later, age 1.1 or later, and an ssh-agent
holding an `ssh-ed25519` key or an `ssh-rsa` key of at least 2048 bits. The
repository pins Go and age in [mise.toml](mise.toml).

```sh
git clone https://github.com/d0ssant0s/age-plugin-sshagent
cd age-plugin-sshagent
mise install                                   # or use your own Go and age
mise exec -- go build -o ~/.local/bin/ ./cmd/...

age-plugin-sshagent list                       # which agent keys are eligible?
```

`go install github.com/eszio/...` installs the upstream version, which has no
RSA support and no `sshagent-cred`. Build from this checkout instead.

Encrypt and decrypt a file:

```sh
age-plugin-sshagent keygen -o identity.txt     # prints the age1... public key
age -e -r age1... secret.txt > secret.txt.age
age -d -i identity.txt secret.txt.age
```

Keep a token for a script:

```sh
sshagent-cred init                             # asks for an export password
printf %s "$TOKEN" | sshagent-cred encrypt example/token
env -u TOKEN sshagent-cred exec -e TOKEN=example/token -- ./my-script.sh
```

[docs/getting-started.md](docs/getting-started.md) walks through both
step by step.

## Documentation

- [Getting started](docs/getting-started.md): install, pick a key, first
  encryption, first Credential.
- [age-plugin-sshagent](docs/age-plugin-sshagent.md): commands, the identity
  file and key selection.
- [sshagent-cred](docs/sshagent-cred.md): the Credential store, giving
  secrets to programs, and export and import.
- [Security model and limitations](docs/security.md): how the key is
  derived, who can decrypt, and what this doesn't protect against.
- [Security review, 2026-10-08](docs/reviews/2026-10-08-security.md):
  open findings, and whether each one was implemented, accepted, or
  rejected.
- [Development](docs/development.md): code layout, tests and how the fork
  was built.
- [Decisions](docs/adr/): why the fork works the way it does.

## License

BSD-3-Clause, the same license as age. See [LICENSE](LICENSE). The
`internal/bech32` package is vendored from
[filippo.io/age](https://github.com/FiloSottile/age) and is MIT-licensed; its
license header is kept in the source file.
