// tsumuji-helper — Mac-side daemon for the tsumuji password typer.
//
// Usage:
//
//	tsumuji-helper serve [--port /dev/cu.usbmodemXXXX] [--insecure-text "..."]
//	tsumuji-helper pair <64-hex-char pairing key>
//	tsumuji-helper set-password           (reads the password from the terminal)
//	tsumuji-helper unpair
//
// Bring-up: run `serve --insecure-text "hello"` — every EV is answered with the
// plaintext text. Normal: run `serve` — only authenticated EV requests are
// answered, with the Keychain password encrypted under a per-request session key.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(os.Args[1:], logger); err != nil {
		if errors.Is(err, errUsage) {
			usage()
			os.Exit(2)
		}
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

func run(args []string, logger *slog.Logger) error {
	if len(args) < 1 {
		return errUsage
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:], logger)
	case "pair":
		return cmdPair(args[1:])
	case "set-password":
		return cmdSetPassword()
	case "unpair":
		return cmdUnpair()
	default:
		return errUsage
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  tsumuji-helper serve [--port PATH] [--insecure-text TEXT]
  tsumuji-helper pair <hex-key>
  tsumuji-helper set-password
  tsumuji-helper unpair`)
}

func cmdServe(args []string, logger *slog.Logger) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	port := fs.String("port", "", "serial port path (auto-detect if empty)")
	insecure := fs.String("insecure-text", "", "bring-up: answer every EV with this plaintext (no crypto)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var handler Handler
	if *insecure != "" {
		logger.Warn("running in INSECURE plaintext mode; replying with fixed text")
		handler = plainHandler(*insecure)
	} else {
		key, err := LoadPairingKey()
		if err != nil {
			return fmt.Errorf("load pairing key: %w (run `tsumuji-helper pair <hex>` first)", err)
		}
		pw, err := LoadPassword()
		Zero(pw) // startup check only; never keep the plaintext around
		if err != nil {
			return fmt.Errorf("load password: %w (run `tsumuji-helper set-password` first)", err)
		}
		handler = secureHandler(key, NewNonceCache(4096), LoadPassword)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := RunForever(ctx, *port, handler, logger)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func cmdPair(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: tsumuji-helper pair <64-hex-char key>  (generate with: openssl rand -hex 32)")
	}
	key, err := ParsePairingKeyHex(args[0])
	if err != nil {
		return err
	}
	Zero(key)
	if err := keychainSet(servicePairingKey, []byte(strings.TrimSpace(args[0]))); err != nil {
		return err
	}
	fmt.Println("pairing key stored in Keychain. Now put the same key into firmware/tsumuji_keyboard/secrets.h")
	return nil
}

func cmdSetPassword() error {
	var pw []byte
	var err error
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Login password to store: ")
		pw, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
	} else {
		pw, err = bufio.NewReader(os.Stdin).ReadBytes('\n')
		if err == nil || len(pw) > 0 {
			pw = bytes.TrimRight(pw, "\r\n")
			err = nil
		}
	}
	if err != nil {
		return err
	}
	defer Zero(pw)
	if len(pw) == 0 {
		return errors.New("empty password")
	}
	if err := keychainSet(servicePassword, pw); err != nil {
		return err
	}
	fmt.Println("password stored in Keychain")
	return nil
}

func cmdUnpair() error {
	var firstErr error
	for _, s := range []string{servicePairingKey, servicePassword} {
		if err := keychainDelete(s); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
