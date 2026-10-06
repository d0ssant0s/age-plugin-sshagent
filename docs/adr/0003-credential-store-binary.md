# 0003: sshagent-cred as a second binary with one file per Credential

The maintainer needed somewhere to keep tool credentials, such as a Graylog
API token, that scripts can read without a prompt, decrypted only while their
ssh-agent is reachable. The ideas discussed were a Python tool in another
repository, a SQLite database of secrets, and new subcommands on the plugin.

`sshagent-cred` is a second Go binary in this repository. It shares the
derivation in `internal/derive`, decrypts in-process with the age library, and
stores one age file per Credential under a directory that is a setting. It
hands values to programs through `exec` (environment variables) or `token`
(stdout, for a program's password command).

Status: accepted (2026-10-06).

Consequences: one build and one place for the key derivation code. No `age`
CLI is needed at run time. One file per Credential works on network file
systems and can be copied, synced or kept in Git. SQLite locking is unreliable
over NFS, and a binary database can't be merged. The plugin binary stays
small, because age runs it as a plugin. Names and file sizes are visible.
There is no locking between concurrent writers.

Considered options: SQLite (unreliable on network storage, can't be merged);
[passage](https://github.com/FiloSottile/passage) (a tool outside the
maintainer's control, and it shells out to age); subcommands on
`age-plugin-sshagent` (would mix a store into the program age executes).
