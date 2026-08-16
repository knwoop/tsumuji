package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Wire protocol: newline-terminated ASCII lines over USB CDC.
//
//   Device -> Helper
//     EV                          plaintext (only honored in --insecure-text mode)
//     EV <nonce_hex> <mac_hex>    authenticated request
//
//   Helper -> Device
//     PW <text>                   plaintext reply: type <text> verbatim
//     PW <ct_hex> <mac_hex>       authenticated reply: verify, decrypt, then type
//     ERR                         request rejected (no details on purpose)

var ErrMalformed = errors.New("malformed request")

// Request is a parsed EV line.
type Request struct {
	Nonce []byte // nil for a plaintext request
	MAC   []byte
}

// Plaintext reports whether the request carries no authentication material.
func (r Request) Plaintext() bool { return r.Nonce == nil }

// ParseRequest parses one line from the device.
func ParseRequest(line string) (Request, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 || fields[0] != "EV" {
		return Request{}, ErrMalformed
	}
	switch len(fields) {
	case 1:
		return Request{}, nil
	case 3:
		nonce, err := hex.DecodeString(fields[1])
		if err != nil || len(nonce) != NonceSize {
			return Request{}, ErrMalformed
		}
		m, err := hex.DecodeString(fields[2])
		if err != nil || len(m) != MACSize {
			return Request{}, ErrMalformed
		}
		return Request{Nonce: nonce, MAC: m}, nil
	default:
		return Request{}, ErrMalformed
	}
}

// FormatPlainReply builds a plaintext reply line.
func FormatPlainReply(text string) string {
	// The device reads up to a newline, so strip any embedded ones.
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "\r", " ")
	return "PW " + text + "\n"
}

// FormatEncryptedReply builds an authenticated reply line.
func FormatEncryptedReply(ct, respMAC []byte) string {
	return fmt.Sprintf("PW %s %s\n", hex.EncodeToString(ct), hex.EncodeToString(respMAC))
}

// FormatError builds the generic rejection line.
func FormatError() string { return "ERR\n" }
