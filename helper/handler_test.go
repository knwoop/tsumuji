package main

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func noKeychain(t *testing.T) func() ([]byte, error) {
	return func() ([]byte, error) {
		t.Error("Keychain must not be touched on a refused request")
		return nil, errors.New("unexpected")
	}
}

func TestSecureHandlerRefusesBeforeKeychain(t *testing.T) {
	k := testKey(t)
	h := secureHandler(k, NewNonceCache(8), noKeychain(t))

	n, _ := NewNonce()
	badMAC := strings.Repeat("00", MACSize)
	cases := []struct {
		name      string
		line      string
		wantReply string
		wantErr   error
	}{
		{"plaintext EV", "EV\n", FormatError(), ErrPlaintextRefused},
		{"malformed", "hello\n", "", ErrMalformed},
		{"bad MAC", "EV " + hex.EncodeToString(n) + " " + badMAC + "\n", FormatError(), ErrBadMAC},
	}
	for _, c := range cases {
		reply, err := h(c.line)
		if reply != c.wantReply {
			t.Errorf("%s: reply %q, want %q", c.name, reply, c.wantReply)
		}
		if !errors.Is(err, c.wantErr) {
			t.Errorf("%s: err %v, want %v", c.name, err, c.wantErr)
		}
	}
}

func TestSecureHandlerRejectsReplay(t *testing.T) {
	k := testKey(t)
	cache := NewNonceCache(8)
	n, _ := NewNonce()
	_ = cache.Check(n) // pretend the nonce was already used
	h := secureHandler(k, cache, noKeychain(t))
	line := "EV " + hex.EncodeToString(n) + " " + hex.EncodeToString(RequestMAC(k, n)) + "\n"
	reply, err := h(line)
	if reply != FormatError() {
		t.Errorf("reply %q, want ERR", reply)
	}
	if !errors.Is(err, ErrReplay) {
		t.Errorf("err %v, want ErrReplay", err)
	}
}

func TestSecureHandlerRoundTrip(t *testing.T) {
	k := testKey(t)
	pw := "correct horse battery staple"
	h := secureHandler(k, NewNonceCache(8), func() ([]byte, error) { return []byte(pw), nil })

	n, _ := NewNonce()
	line := "EV " + hex.EncodeToString(n) + " " + hex.EncodeToString(RequestMAC(k, n)) + "\n"
	reply, err := h(line)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	fields := strings.Fields(reply)
	if len(fields) != 3 || fields[0] != "PW" {
		t.Fatalf("reply %q not in PW <ct> <mac> form", reply)
	}
	ct, _ := hex.DecodeString(fields[1])
	m, _ := hex.DecodeString(fields[2])
	s, _ := DeriveSessionKey(k, n)
	got, err := DecryptResponse(s, n, ct, m)
	if err != nil {
		t.Errorf("device-side decrypt: %v", err)
	}
	if string(got) != pw {
		t.Errorf("decrypted %q, want %q", got, pw)
	}

	// Same nonce again is a replay.
	if _, err := h(line); !errors.Is(err, ErrReplay) {
		t.Errorf("second use: err %v, want ErrReplay", err)
	}
}

func TestPlainHandler(t *testing.T) {
	h := plainHandler("hello world")
	if reply, err := h("EV\n"); reply != "PW hello world\n" || err != nil {
		t.Errorf("got %q, %v", reply, err)
	}
	n, _ := NewNonce()
	line := "EV " + hex.EncodeToString(n) + " " + strings.Repeat("00", MACSize) + "\n"
	if reply, err := h(line); reply != FormatError() || !errors.Is(err, ErrAuthenticatedRefused) {
		t.Errorf("authenticated EV in plaintext mode: got %q, %v", reply, err)
	}
}
