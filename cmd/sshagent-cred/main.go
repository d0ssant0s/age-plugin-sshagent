// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// sshagent-cred keeps Credentials encrypted to an identity derived from a key
// in your ssh-agent, and hands them to the programs that need them.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/eszio/age-plugin-sshagent/internal/derive"
	"github.com/eszio/age-plugin-sshagent/internal/store"
)

const usage = `Usage:
  sshagent-cred init [-k SELECTOR]
      Create the Credential store with an identity derived from an ssh-agent
      key, and set the export password.
  sshagent-cred encrypt [-f] NAME
      Encrypt the value read from stdin as Credential NAME (-f replaces it).
  sshagent-cred token NAME
      Print Credential NAME, for a program's token or password command.
  sshagent-cred exec -e VAR=NAME [-e VAR=NAME ...] -- COMMAND [ARGS...]
      Run COMMAND with the Credentials in environment variables.
  sshagent-cred list
      List Credential names.
  sshagent-cred export FILE
      Write all Credentials to FILE, encrypted with the export password.
  sshagent-cred import [--overwrite] FILE
      Import an export: add missing Credentials and refuse differing ones
      unless --overwrite is given.

The store is $SSHAGENT_CRED_DIR, or sshagent-cred in the user config directory.
Passwords are read from the terminal only. Decrypting needs the ssh-agent
key (SSH_AUTH_SOCK).
`

var varPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type streams struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	password       func(prompt string) ([]byte, error)
}

func main() {
	os.Exit(run(os.Args[1:], streams{os.Stdin, os.Stdout, os.Stderr, terminalPassword}))
}

func run(args []string, std streams) int {
	if len(args) == 0 {
		fmt.Fprint(std.stderr, usage)
		return 2
	}
	s, err := openStore()
	if err == nil {
		err = dispatch(args[0], args[1:], s, std)
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(std.stderr, "sshagent-cred: %v\n", err)
		return 1
	}
	return 0
}

func dispatch(cmd string, args []string, s *store.Store, std streams) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(std.stderr)
	switch cmd {
	case "init":
		sel := fs.String("k", "", "select the agent key by comment or SHA256 fingerprint (substring match)")
		if err := parse(fs, args, 0); err != nil {
			return err
		}
		return cmdInit(s, *sel, std)
	case "encrypt":
		force := fs.Bool("f", false, "replace an existing Credential")
		if err := parse(fs, args, 1); err != nil {
			return err
		}
		value, err := io.ReadAll(std.stdin)
		if err != nil {
			return err
		}
		return s.Put(fs.Arg(0), value, *force)
	case "token":
		if err := parse(fs, args, 1); err != nil {
			return err
		}
		id, err := identity(s)
		if err != nil {
			return err
		}
		value, err := s.Get(fs.Arg(0), id)
		if err != nil {
			return err
		}
		_, err = std.stdout.Write(value)
		return err
	case "exec":
		var vars assignments
		fs.Var(&vars, "e", "set environment variable `VAR=NAME` to Credential NAME (repeatable)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if len(vars) == 0 || fs.NArg() == 0 {
			return errors.New("usage: sshagent-cred exec -e VAR=NAME [-e ...] -- COMMAND [ARGS...]")
		}
		return cmdExec(s, vars, fs.Args())
	case "list":
		if err := parse(fs, args, 0); err != nil {
			return err
		}
		names, err := s.List()
		if err != nil {
			return err
		}
		for _, n := range names {
			fmt.Fprintln(std.stdout, n)
		}
		return nil
	case "export":
		if err := parse(fs, args, 1); err != nil {
			return err
		}
		return cmdExport(s, fs.Arg(0), std)
	case "import":
		overwrite := fs.Bool("overwrite", false, "replace Credentials that differ from the export")
		if err := parse(fs, args, 1); err != nil {
			return err
		}
		return cmdImport(s, fs.Arg(0), *overwrite, std)
	case "help", "-h", "--help":
		fmt.Fprint(std.stdout, usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
	}
}

func parse(fs *flag.FlagSet, args []string, nargs int) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != nargs {
		return fmt.Errorf("%s takes %d argument(s)\n\n%s", fs.Name(), nargs, usage)
	}
	return nil
}

func openStore() (*store.Store, error) {
	if dir := os.Getenv("SSHAGENT_CRED_DIR"); dir != "" {
		return &store.Store{Dir: dir}, nil
	}
	config, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	return &store.Store{Dir: filepath.Join(config, "sshagent-cred")}, nil
}

func cmdInit(s *store.Store, selector string, std streams) error {
	ag, err := derive.Connect()
	if err != nil {
		return err
	}
	key, err := derive.PickKey(ag, selector)
	if err != nil {
		return err
	}
	d, id, err := derive.Keygen(ag, key)
	if err != nil {
		return err
	}
	pw, err := std.password("New export password: ")
	if err != nil {
		return err
	}
	again, err := std.password("Repeat the export password: ")
	if err != nil {
		return err
	}
	if !bytes.Equal(pw, again) {
		return errors.New("the passwords differ")
	}
	recipient := id.Recipient().String()
	identity := fmt.Sprintf("# created: %s\n# ssh key: %s\n# public key: %s\n%s\n",
		time.Now().Format(time.RFC3339), ssh.FingerprintSHA256(key), recipient,
		plugin.EncodeIdentity(derive.PluginName, d.Encode()))
	if err := s.Init(identity, recipient, pw); err != nil {
		return err
	}
	fmt.Fprintf(std.stdout, "Created the Credential store in %s\nPublic key: %s\n", s.Dir, recipient)
	return nil
}

// identity re-derives the store's decryption key through the ssh-agent.
func identity(s *store.Store) (age.Identity, error) {
	f, err := os.Open(s.IdentityFile())
	if err != nil {
		return nil, fmt.Errorf("%v (run sshagent-cred init)", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		name, data, err := plugin.ParseIdentity(strings.TrimSpace(scanner.Text()))
		if err == nil && name == derive.PluginName {
			return derive.FromPayload(data)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no AGE-PLUGIN-SSHAGENT-1 identity in %s", s.IdentityFile())
}

type assignments []string

func (a *assignments) String() string { return strings.Join(*a, ",") }

func (a *assignments) Set(v string) error {
	name, _, ok := strings.Cut(v, "=")
	if !ok || !varPattern.MatchString(name) {
		return fmt.Errorf("want VAR=NAME with a valid variable name, got %q", v)
	}
	*a = append(*a, v)
	return nil
}

func cmdExec(s *store.Store, vars assignments, command []string) error {
	path, err := exec.LookPath(command[0])
	if err != nil {
		return err
	}
	id, err := identity(s)
	if err != nil {
		return err
	}
	env := os.Environ()
	for _, v := range vars {
		name, cred, _ := strings.Cut(v, "=")
		value, err := s.Get(cred, id)
		if err != nil {
			return err
		}
		env = append(env, name+"="+string(value))
	}
	return syscall.Exec(path, command, env)
}

func cmdExport(s *store.Store, path string, std streams) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s exists", path)
	}
	pw, err := std.password("Export password: ")
	if err != nil {
		return err
	}
	if err := s.CheckPassword(pw); err != nil {
		return err
	}
	id, err := identity(s)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := s.Export(&buf, id, pw); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func cmdImport(s *store.Store, path string, overwrite bool, std streams) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	pw, err := std.password("Password of the export: ")
	if err != nil {
		return err
	}
	id, err := identity(s)
	if err != nil {
		return err
	}
	res, err := s.Import(f, id, pw, overwrite)
	if err != nil {
		return err
	}
	fmt.Fprintf(std.stdout, "added %d, unchanged %d, overwritten %d\n", res.Added, res.Unchanged, res.Overwritten)
	return nil
}

// terminalPassword reads a password from the controlling terminal, never
// from stdin, arguments or the environment.
func terminalPassword(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("a password needs a terminal: %v", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	pw, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return pw, err
}
