package main

import (
	"strings"
	"testing"
)

func TestParseRequestPlain(t *testing.T) {
	r, err := ParseRequest("EV\r\n")
	if err != nil || !r.Plaintext() {
		t.Errorf("plain EV: %v %+v", err, r)
	}
}

func TestParseRequestAuthenticated(t *testing.T) {
	nonce := strings.Repeat("ab", NonceSize)
	m := strings.Repeat("cd", MACSize)
	r, err := ParseRequest("EV " + nonce + " " + m + "\n")
	if err != nil || r.Plaintext() || len(r.Nonce) != NonceSize || len(r.MAC) != MACSize {
		t.Errorf("auth EV: %v %+v", err, r)
	}
}

func TestParseRequestRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "PW x", "EV zz", "EV abcd " + strings.Repeat("00", 32), "EV a b c"} {
		if _, err := ParseRequest(in); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestFormatPlainReplyStripsNewlines(t *testing.T) {
	if got := FormatPlainReply("a\nb"); got != "PW a b\n" {
		t.Errorf("got %q", got)
	}
}
