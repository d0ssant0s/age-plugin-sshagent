// Copyright 2026 The age-plugin-sshagent Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"filippo.io/age/plugin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/eszio/age-plugin-sshagent/internal/derive"
)

func cmdKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	keySel := fs.String("k", "", "select the agent key by comment or SHA256 fingerprint (substring match)")
	out := fs.String("o", "", "write the identity to `FILE` (default stdout)")
	fs.Parse(args)

	ag, err := derive.Connect()
	if err != nil {
		return fatalf("%v", err)
	}
	key, err := derive.PickKey(ag, *keySel)
	if err != nil {
		return fatalf("%v", err)
	}
	d, id, err := derive.Keygen(ag, key)
	if err != nil {
		return fatalf("%v", err)
	}

	recipient := id.Recipient().String()
	identity := plugin.EncodeIdentity(derive.PluginName, d.Encode())

	w := io.Writer(os.Stdout)
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fatalf("%v", err)
		}
		defer f.Close()
		w = f
	}
	fmt.Fprintf(w, "# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "# ssh key: %s %s\n", ssh.FingerprintSHA256(key), keyComment(ag, key))
	fmt.Fprintf(w, "# public key: %s\n", recipient)
	fmt.Fprintf(w, "%s\n", identity)
	fmt.Fprintf(os.Stderr, "Public key: %s\n", recipient)
	return 0
}

func keyComment(ag agent.Agent, key ssh.PublicKey) string {
	keys, err := ag.List()
	if err != nil {
		return ""
	}
	marshaled := key.Marshal()
	for _, k := range keys {
		if string(k.Marshal()) == string(marshaled) {
			return k.Comment
		}
	}
	return ""
}

func cmdList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	fs.Parse(args)

	ag, err := derive.Connect()
	if err != nil {
		return fatalf("%v", err)
	}
	keys, err := ag.List()
	if err != nil {
		return fatalf("cannot list ssh agent keys: %v", err)
	}
	if len(keys) == 0 {
		fmt.Println("(the ssh agent holds no keys)")
		return 0
	}
	for _, k := range keys {
		eligible := "eligible"
		if err := derive.Eligible(k); err != nil {
			eligible = "not eligible: " + err.Error()
		}
		fmt.Printf("%s %s %s [%s]\n", k.Type(), ssh.FingerprintSHA256(k), k.Comment, eligible)
	}
	return 0
}

// cmdRecipient re-derives and prints the recipient(s) for identities read
// from a file or stdin. Useful to recover a lost public key, since the
// identity itself stores no key material.
func cmdRecipient(args []string) int {
	fs := flag.NewFlagSet("recipient", flag.ExitOnError)
	in := fs.String("i", "", "read identities from `FILE` (default stdin)")
	fs.Parse(args)

	r := io.Reader(os.Stdin)
	if *in != "" {
		f, err := os.Open(*in)
		if err != nil {
			return fatalf("%v", err)
		}
		defer f.Close()
		r = f
	}

	found := false
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, data, err := plugin.ParseIdentity(line)
		if err != nil || name != derive.PluginName {
			continue
		}
		id, err := derive.FromPayload(data)
		if err != nil {
			return fatalf("%v", err)
		}
		fmt.Println(id.Recipient().String())
		found = true
	}
	if err := scanner.Err(); err != nil {
		return fatalf("%v", err)
	}
	if !found {
		return fatalf("no AGE-PLUGIN-SSHAGENT-1 identity found in input")
	}
	return 0
}

func fatalf(format string, v ...any) int {
	fmt.Fprintf(os.Stderr, "age-plugin-sshagent: "+format+"\n", v...)
	return 1
}
