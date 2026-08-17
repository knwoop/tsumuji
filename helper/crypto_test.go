package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k, err := ParsePairingKeyHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRequestMACRoundTrip(t *testing.T) {
	k := testKey(t)
	n, _ := NewNonce()
	m := RequestMAC(k, n)
	if !VerifyRequestMAC(k, n, m) {
		t.Error("valid MAC rejected")
	}
	m[0] ^= 1
	if VerifyRequestMAC(k, n, m) {
		t.Error("tampered MAC accepted")
	}
	other := make([]byte, PairingKeySize)
	if VerifyRequestMAC(other, n, RequestMAC(k, n)) {
		t.Error("MAC accepted under wrong key")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	k := testKey(t)
	n, _ := NewNonce()
	s, err := DeriveSessionKey(k, n)
	if err != nil {
		t.Fatal(err)
	}
	pw := []byte("correct horse battery staple")
	ct, m, err := EncryptResponse(s, n, pw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct, pw) {
		t.Error("ciphertext equals plaintext")
	}
	got, err := DecryptResponse(s, n, ct, m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pw) {
		t.Errorf("round trip mismatch: %q", got)
	}
	// Tampered ciphertext must fail MAC.
	ct[0] ^= 1
	if _, err := DecryptResponse(s, n, ct, m); err != ErrBadMAC {
		t.Errorf("expected ErrBadMAC, got %v", err)
	}
}

func TestSessionKeyDependsOnNonce(t *testing.T) {
	k := testKey(t)
	n1, _ := NewNonce()
	n2, _ := NewNonce()
	s1, _ := DeriveSessionKey(k, n1)
	s2, _ := DeriveSessionKey(k, n2)
	if bytes.Equal(s1, s2) {
		t.Error("session keys identical for different nonces")
	}
}

// Known-answer test so the firmware implementation can be checked against it.
func TestKnownAnswer(t *testing.T) {
	k := testKey(t)
	n, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	s, _ := DeriveSessionKey(k, n)
	ct, m, _ := EncryptResponse(s, n, []byte("hello"))
	t.Logf("reqMAC  = %x", RequestMAC(k, n))
	t.Logf("session = %x", s)
	t.Logf("ct      = %x", ct)
	t.Logf("respMAC = %x", m)
	want := map[string]string{
		"reqMAC":  "73f690cc5195e893ab7b82c33d6ee4c5229890070379474416afa72ccb3edba0",
		"session": "c9bfd10d0eccec2e1b16bd717b55aeb9df341d9234de3a0cd7e0318f9b5c095f",
		"ct":      "084ce369f1",
		"respMAC": "662e6179e00d9b89364bbfbe29ead0cbe8d47b88d2cfa91c30e67c44e1ef9802",
	}
	got := map[string]string{
		"reqMAC":  hex.EncodeToString(RequestMAC(k, n)),
		"session": hex.EncodeToString(s),
		"ct":      hex.EncodeToString(ct),
		"respMAC": hex.EncodeToString(m),
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: got %s want %s", name, got[name], w)
		}
	}
}

func TestNonceCacheRejectsReplay(t *testing.T) {
	c := NewNonceCache(2)
	a := []byte("aaaaaaaaaaaaaaaa")
	b := []byte("bbbbbbbbbbbbbbbb")
	d := []byte("dddddddddddddddd")
	if err := c.Check(a); err != nil {
		t.Error(err)
	}
	if err := c.Check(a); err != ErrReplay {
		t.Errorf("expected replay, got %v", err)
	}
	_ = c.Check(b)
	_ = c.Check(d) // evicts a
	if err := c.Check(a); err != nil {
		t.Errorf("evicted nonce should be accepted again, got %v", err)
	}
	if err := c.Check(d); err != ErrReplay {
		t.Error("recent nonce should still be rejected")
	}
}

func TestParsePairingKeyHex(t *testing.T) {
	if _, err := ParsePairingKeyHex("abc"); err == nil {
		t.Error("short key accepted")
	}
	if _, err := ParsePairingKeyHex("zz"); err == nil {
		t.Error("non-hex accepted")
	}
}

func TestZero(t *testing.T) {
	b := []byte("secret")
	Zero(b)
	for _, c := range b {
		if c != 0 {
			t.Error("not zeroed")
		}
	}
}
