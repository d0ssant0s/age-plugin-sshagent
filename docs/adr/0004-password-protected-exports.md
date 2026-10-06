# 0004: Exports are encrypted with a password set at init

Credentials are encrypted to a key that exists only while one ssh key does.
If the key is lost, so are the Credentials. The maintainer wanted to export
and re-import them, merging or overwriting, and wanted an AI agent running in
the same terminal to be unable to make a usable export.

`init` asks twice for an export password, at least 12 characters, and stores
only `export-check.age`, a fixed text encrypted with that password in age's
scrypt mode. `export` asks for the password on the terminal, checks it against
that file, and writes all Credentials as JSON Lines encrypted with the same
password. `import` decrypts an export with the password typed, adds missing
Credentials, skips identical ones and refuses differing ones by name unless
`--overwrite` is given.

Status: accepted (2026-10-06).

Consequences: an export survives losing the ssh key and this tool, because
stock `age -d` and the password are enough. An agent that doesn't know the
password can't produce an export, but anyone who can read `export-check.age`
can try to guess the password offline, so a weak password undoes this. Scripts
can't export, because the password comes from `/dev/tty` only. There is no way
yet to change the password.

Considered options: a new password at each export (an agent could pick its own
and read the result); a second recovery identity encrypted with a password
(more files to keep, same guessing risk); no export (losing the key means
reissuing everything).
