# age-plugin-sshagent

[README](../README.md) | [Getting started](getting-started.md) | [sshagent-cred](sshagent-cred.md) | [Security](security.md)

`age-plugin-sshagent` is an age plugin. You run it yourself to create an
identity. After that, `age` runs it when it needs to decrypt. Encrypting
never needs it.

## Commands

### keygen

```sh
age-plugin-sshagent keygen [-k SELECTOR] [-o FILE]
```

Creates an identity from an eligible key in the agent and prints the
`age1...` public key to stderr.

- `-k` selects the key by a substring of its comment or `SHA256:` fingerprint.
  Without it, the agent must hold exactly one eligible key.
- `-o` writes the identity to FILE with mode 0600 and refuses to overwrite an
  existing file. Without it, the identity goes to stdout.
- It derives the key twice and stops if the results differ, so an agent with
  non-deterministic signatures fails here, before you encrypt anything.
- For RSA it tries `rsa-sha2-512`, then `rsa-sha2-256`, and records the first
  format that works in the identity.

Output:

```
# created: 2026-10-06T14:40:28+02:00
# ssh key: SHA256:EL5f... CAPI:b966...
# public key: age1zeknf3...
AGE-PLUGIN-SSHAGENT-1QGG...
```

### recipient

```sh
age-plugin-sshagent recipient [-i FILE]
```

Re-derives and prints the public key of each identity in FILE, or in stdin.
Use it when the `# public key:` comment is lost. It needs the agent.

### list

```sh
age-plugin-sshagent list
```

Lists the agent's keys, and for each one whether it is eligible or why not.
It doesn't sign anything.

## Encrypting and decrypting

```sh
age -e -r age1... file > file.age        # stock age, no plugin needed
age -d -i identity.txt file.age          # age runs the plugin from PATH
```

One identity file can hold several identities. age tries each.

## Eligible keys

| Key type | Eligible | Reason |
| --- | --- | --- |
| `ssh-ed25519` | yes | Signatures are deterministic by design (RFC 8032). |
| `ssh-rsa`, 2048 bits or more | yes | SSH RSA signatures are PKCS#1 v1.5 (RFC 8332), which uses no randomness. |
| `ssh-rsa`, under 2048 bits | no | Too weak to rely on. |
| `ecdsa-sha2-*` | no | Signatures are randomized, so each one derives a different key. |
| `sk-*` (FIDO) | no | Signatures include a counter that changes on every use. |

## The identity file

The `AGE-PLUGIN-SSHAGENT-1...` line contains no secret:

| Payload version | Key type | Contents |
| --- | --- | --- |
| 1 | `ssh-ed25519` | SHA-256 fingerprint of the ssh public key, 16-byte random salt |
| 2 | `ssh-rsa` | the same, plus the signature format (`rsa-sha2-256` or `rsa-sha2-512`) |

Ed25519 identities from upstream keep working unchanged. RSA identities don't
work with the upstream plugin.

## Errors you may see

- `ssh key SHA256:... is not loaded in the agent`: the agent doesn't hold the
  key this identity was made from. Load it, or check `SSH_AUTH_SOCK`.
- `ssh agent returned a rsa-sha2-256 signature, the identity requires
  rsa-sha2-512`: the agent no longer signs in the format recorded at `keygen`.
  The plugin refuses to fall back, because another format derives another key.
- `multiple eligible keys match; pick one with -k`: add a selector.
- `SSH_AUTH_SOCK is not set`: no agent in this shell.
