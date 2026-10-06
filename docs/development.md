# Development

[README](../README.md) | [Security](security.md) | [Decisions](adr/)

## How this fork was made

The fork started from upstream commit `8bc67c4` on 2026-10-06. AI coding agents
wrote every change after that, from the restructure to RSA support,
`sshagent-cred` and this documentation. They worked test-first, under the
maintainer's direction, in one session. A person made the design decisions in
[docs/adr/](adr/) and ran the RSA probe, but nobody did a line-by-line
security review. Read the code with that in mind.

## Layout

```
cmd/age-plugin-sshagent/   the age plugin and its keygen, recipient and list commands
cmd/sshagent-cred/         the Credential store command
internal/derive/           identity payloads, key eligibility, signing and key derivation
internal/store/            the Credential store on disk, export and import
internal/agenttest/        in-memory ssh agents for tests
internal/bech32/           vendored from filippo.io/age (MIT)
```

Both binaries use `internal/derive`. Neither imports the other.

## Toolchain

[mise.toml](../mise.toml) pins Go 1.27.1 (minimum 1.25 per `go.mod`) and age
1.3.2 from its GitHub release. The end-to-end test runs the real `age` CLI.

```sh
mise install
mise exec -- go vet ./...
mise exec -- gofmt -l .
mise exec -- go test ./...
```

## Tests worth knowing about

- `TestEd25519GoldenVector` pins one Ed25519 derivation to the value the
  upstream code produced. If it fails, existing identities would stop
  decrypting.
- The `TestRSA*` tests cover choosing a format, falling back to SHA-256 at
  `keygen`, and refusing a different format afterwards.
- `TestAgeCLIEndToEnd` builds the plugin, encrypts with stock age and
  decrypts through `age -d -i` against a socket-served agent.
- `TestExecInjectsCredential` builds `sshagent-cred`, because `exec` replaces
  the process.
- The `sshagent-cred` CLI tests take about 10 seconds. Export passwords use
  age's default scrypt cost, on purpose.

No test talks to a real agent. The only real-hardware evidence is one manual
`keygen` against a TPM-backed Windows CAPI RSA key through Pageant on
2026-10-06, which produced deterministic `rsa-sha2-512` signatures.

## Module path

`go.mod` still says `github.com/eszio/age-plugin-sshagent`. Build from a
checkout. `go install` with that path fetches upstream.
