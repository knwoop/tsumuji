package main

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Keychain access via the `security` CLI (no cgo). Secrets are passed on
// stdin in interactive mode so they never appear in `ps` output.

const (
	keychainAccount   = "tsumuji"
	servicePairingKey = "tsumuji.pairing-key"
	servicePassword   = "tsumuji.login-password"
)

var ErrKeychainNotFound = errors.New("keychain item not found")

// keychainSet stores (or replaces) a generic password item.
func keychainSet(service string, secret []byte) error {
	// security -i reads commands from stdin; -U updates an existing item.
	cmd := exec.Command("security", "-i")
	var script bytes.Buffer
	fmt.Fprintf(&script, "add-generic-password -U -a %s -s %s -w %s\n",
		keychainAccount, service, quoteForSecurity(secret))
	cmd.Stdin = &script
	out, err := cmd.CombinedOutput()
	Zero(script.Bytes())
	if err != nil {
		return fmt.Errorf("security add-generic-password: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// keychainGet retrieves a generic password item as bytes. Caller must Zero it.
func keychainGet(service string) ([]byte, error) {
	cmd := exec.Command("security", "find-generic-password", "-a", keychainAccount, "-s", service, "-w")
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 44 {
			return nil, ErrKeychainNotFound
		}
		return nil, fmt.Errorf("security find-generic-password: %w", err)
	}
	return bytes.TrimRight(out, "\r\n"), nil
}

func keychainDelete(service string) error {
	cmd := exec.Command("security", "delete-generic-password", "-a", keychainAccount, "-s", service)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("security delete-generic-password: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// quoteForSecurity wraps s in double quotes for the `security -i` parser,
// escaping backslashes and quotes.
func quoteForSecurity(s []byte) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range s {
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('"')
	return b.String()
}

// LoadPairingKey reads the pairing key from the Keychain.
func LoadPairingKey() ([]byte, error) {
	raw, err := keychainGet(servicePairingKey)
	if err != nil {
		return nil, err
	}
	defer Zero(raw)
	return ParsePairingKeyHex(string(raw))
}

// LoadPassword reads the login password from the Keychain. Caller must Zero it.
func LoadPassword() ([]byte, error) {
	return keychainGet(servicePassword)
}
