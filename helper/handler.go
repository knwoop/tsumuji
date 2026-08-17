package main

import (
	"errors"
	"fmt"
)

// Handler turns one request line into a reply line. An empty reply means
// "send nothing". A non-nil error explains why the request was refused or
// failed; the caller decides how to report it. Refusals still carry the
// generic ERR reply so the device can stop waiting.
type Handler func(line string) (reply string, err error)

var (
	ErrPlaintextRefused     = errors.New("plaintext EV refused in authenticated mode")
	ErrAuthenticatedRefused = errors.New("authenticated EV refused in plaintext mode")
)

// plainHandler implements plaintext bring-up mode: any well-formed EV gets
// the fixed text.
func plainHandler(text string) Handler {
	return func(line string) (string, error) {
		req, err := ParseRequest(line)
		if err != nil {
			return "", err
		}
		if !req.Plaintext() {
			return FormatError(), ErrAuthenticatedRefused
		}
		return FormatPlainReply(text), nil
	}
}

// secureHandler implements authenticated mode. Failure paths come first:
// any MAC or replay problem yields ERR and the Keychain is never touched.
func secureHandler(pairingKey []byte, nonces *NonceCache, loadPassword func() ([]byte, error)) Handler {
	return func(line string) (string, error) {
		req, err := ParseRequest(line)
		if err != nil {
			return "", err
		}
		if req.Plaintext() {
			return FormatError(), ErrPlaintextRefused
		}
		if !VerifyRequestMAC(pairingKey, req.Nonce, req.MAC) {
			return FormatError(), ErrBadMAC
		}
		if err := nonces.Check(req.Nonce); err != nil {
			return FormatError(), err
		}

		session, err := DeriveSessionKey(pairingKey, req.Nonce)
		if err != nil {
			return FormatError(), fmt.Errorf("derive session key: %w", err)
		}
		defer Zero(session)

		pw, err := loadPassword()
		if err != nil {
			return FormatError(), fmt.Errorf("load password: %w", err)
		}
		ct, respMAC, err := EncryptResponse(session, req.Nonce, pw)
		Zero(pw) // plaintext lifetime ends here
		if err != nil {
			return FormatError(), fmt.Errorf("encrypt: %w", err)
		}
		return FormatEncryptedReply(ct, respMAC), nil
	}
}
