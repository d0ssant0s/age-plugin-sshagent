# Getting started

[README](../README.md) | [age-plugin-sshagent](age-plugin-sshagent.md) | [sshagent-cred](sshagent-cred.md) | [Security](security.md)

This guide takes you from a fresh checkout to one encrypted file and one
stored Credential. Read the [security model](security.md) first if you plan to
keep anything real in it. This is an experiment.

## 1. Check what you need

- Linux or macOS. The tools talk to the agent over a Unix socket.
- An ssh-agent reachable through `SSH_AUTH_SOCK`, holding an `ssh-ed25519` key
  or an `ssh-rsa` key of at least 2048 bits. A forwarded agent works, for
  example Pageant forwarded through PuTTY.
- Go 1.25 or later and age 1.1 or later. With [mise](https://mise.jdx.dev),
  `mise install` in the checkout installs the pinned versions.

```sh
ssh-add -l          # the agent answers and lists your keys
```

## 2. Build

```sh
git clone https://github.com/d0ssant0s/age-plugin-sshagent
cd age-plugin-sshagent
mise install
mise exec -- go build -o ~/.local/bin/ ./cmd/...
```

This builds `age-plugin-sshagent` and `sshagent-cred`. The plugin must be on
your `PATH`, because `age` finds plugins by name there. Don't use
`go install github.com/eszio/...`, which installs the upstream version.

## 3. Pick a key

```sh
age-plugin-sshagent list
```

```
ssh-ed25519 SHA256:6fGO... user@laptop [eligible]
ssh-rsa SHA256:EL5f... CAPI:b966... [eligible]
```

With more than one eligible key, select one with `-k` and a substring of its
comment or fingerprint, such as `-k CAPI`. Prefer a key that can't be
exported, such as one held in a TPM or smart card, and one you don't forward
to hosts you don't trust. [Security](security.md#who-can-decrypt) explains why.

## 4. Encrypt and decrypt a file

```sh
age-plugin-sshagent keygen -k CAPI -o identity.txt
```

`keygen` asks the agent to sign twice and checks that both signatures match.
For an RSA key it tries `rsa-sha2-512` first. It prints the public key:

```
Public key: age1zeknf3xpp7mj4rr2vv4eph4dvn7g0xeuthwkr4msv5nvf8k63ctqdsxn20
```

Anyone can encrypt to that key with stock age. Decrypting needs the identity
file and the agent:

```sh
age -e -r age1zeknf3... notes.txt > notes.txt.age
age -d -i identity.txt notes.txt.age
```

`identity.txt` holds no secret. You can commit it or copy it anywhere.

## 5. Store a Credential

```sh
sshagent-cred init -k CAPI
```

`init` derives its own identity the same way and asks twice for an export
password, at least 12 characters. You need that password only to export or
import the store, never to read a Credential. Write it down somewhere safe.

```sh
printf %s 'my-api-token' | sshagent-cred encrypt example/token
sshagent-cred list
sshagent-cred exec -e TOKEN=example/token -- sh -c 'test -n "$TOKEN" && echo token set'
```

Pass Credentials to programs with `exec` or `token`, and avoid printing them
in a terminal you share with others or with an AI agent.

## 6. Make a backup

```sh
sshagent-cred export ~/sshagent-cred-backup.age
```

The export is encrypted with your export password only, so you can restore it
after losing the ssh key. Without an export, a lost key means reissuing every
secret at its source.

## Next

- [age-plugin-sshagent reference](age-plugin-sshagent.md)
- [sshagent-cred reference](sshagent-cred.md)
- [Security model and limitations](security.md)
