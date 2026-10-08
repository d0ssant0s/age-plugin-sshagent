# sshagent-cred

[README](../README.md) | [Getting started](getting-started.md) | [age-plugin-sshagent](age-plugin-sshagent.md) | [Security](security.md)

`sshagent-cred` stores named secrets, called Credentials, encrypted to a key
derived from your ssh-agent. It hands them to the programs that need them. It
decrypts in-process and doesn't need the `age` binary or the plugin at run
time.

## Commands

| Command | Needs the agent | Asks for the export password | What it does |
| --- | --- | --- | --- |
| `init [-k SELECTOR]` | yes | yes, twice | Creates the store and its identity. |
| `encrypt [-f] NAME` | no | no | Encrypts stdin as NAME. `-f` replaces an existing Credential. |
| `token NAME` | yes | no | Writes the value to stdout, with no trailing newline. |
| `exec -e VAR=NAME ... -- CMD [ARGS]` | yes | no | Runs CMD with each Credential in an environment variable. |
| `list` | no | no | Lists the names. |
| `export FILE` | yes | yes | Writes all Credentials to a new FILE. |
| `import [--overwrite] FILE` | yes | yes | Reads an export into this store. |

`encrypt` doesn't need the agent, because encrypting uses only the public key.

## The store

The store is the directory in `SSHAGENT_CRED_DIR`, or `sshagent-cred` in your
user config directory (`~/.config/sshagent-cred` on Linux).

```
identity.txt         the derived identity, no secret
recipient.txt        the age1... public key Credentials are encrypted to
export-check.age     a fixed text encrypted with the export password
store/<name>.age     one age file per Credential
```

- Names are lowercase segments of `a-z`, `0-9`, `.`, `_` and `-`, separated by
  `/`, such as `graylog/prod/token`. Anything else is rejected, including
  `..`.
- Values must be UTF-8 text, and must not contain a NUL byte. A NUL is
  valid UTF-8, and the current code accepts it. `exec` then truncates the
  value at the first NUL. `token` writes the full bytes. Do not store one.
  `encrypt` drops one trailing newline, so
  `echo token | sshagent-cred encrypt NAME` stores just `token`.
- Files are written with mode 0600 and replaced atomically. `init` creates
  a missing store directory mode 0700 and does not tighten one that already
  exists. A directory others can list leaks Credential names.
- The files hold only ciphertext and public data. You can copy the store, sync
  it or keep it in Git, but the Credential names are visible in clear text.

## Giving a Credential to a program

Prefer `exec`, which puts the value in the child's environment only. If the
shell already has that name set, unset it first. On Linux and on macOS the
first value wins, and the program runs with the old one and no error:

```sh
env -u GRAYLOG_TOKEN sshagent-cred exec -e GRAYLOG_TOKEN=graylog/prod/token -- glquery count ...
```

For a program that runs a command to get its password, use `token`:

```yaml
token_command: sshagent-cred token graylog/prod/token
```

Either way the value doesn't appear in your shell history or in a config file.
`token` writes the raw value to stdout. Command substitution into another
program's arguments puts that value in the process list. Prefer `exec`.

A process running as your user can still read another process's environment,
and anyone who can run `sshagent-cred` can print any Credential. `token` and
`exec` need no password. See [Security](security.md).

## Export and import

`init` sets an export password. The store keeps only `export-check.age`, which
lets `export` check the password but doesn't contain it.

```sh
sshagent-cred export backup.age
sshagent-cred import backup.age
sshagent-cred import --overwrite backup.age
```

- `export` refuses an existing file and a wrong password. It writes every
  Credential as one JSON line, `{"name": ..., "value": ...}`, encrypted with
  the export password using age's scrypt mode.
- Stock `age -d backup.age` and the password are enough to read an export, so
  it survives losing the ssh key or this tool.
- `import` decrypts with the password you type, which doesn't have to be this
  store's export password. It adds missing Credentials and leaves identical
  ones alone. If any differ, it lists their names, never their values, and
  imports nothing unless you pass `--overwrite`. After that check, writes are
  one Credential at a time. A later failure can leave the earlier names
  already replaced. Do not treat `--overwrite` as a transaction.
- After a copy, sync, or pull, re-derive the recipient and compare it with
  `recipient.txt` before the next `encrypt`. The command is
  `age-plugin-sshagent recipient -i identity.txt`. Comparing the comment in
  `identity.txt` is not a check. `encrypt` does not do this itself.

Passwords are read from the terminal (`/dev/tty`) only, never from stdin,
arguments or the environment. Scripts can't export or import, by design.

## Limitations

- No command changes the export password, renames a Credential or deletes one.
  Delete `store/<name>.age` by hand.
- No locking. Two `sshagent-cred` processes writing the same Credential at the
  same moment can lose one write.
- Values are text only. Encode binary data, for example with base64.
- The guard against weak export passwords is a 12-byte minimum. The error
  text says characters. Nothing else checks the password. Anyone who can
  read `export-check.age` or an export file can try to guess it offline.
  The password does not stop `token` or `exec`.
