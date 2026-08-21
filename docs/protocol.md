# tsumuji wire protocol

Transport: USB CDC serial, newline-terminated ASCII lines. Hex is lowercase.

## Plaintext mode (bring-up only)

```
Device → Helper:  EV\n
Helper → Device:  PW <text>\n
```

The helper only answers plaintext `EV` when started with `--insecure-text`.

## Authenticated mode (PSK)

Shared state: `K` = 32-byte pairing key (Keychain on the Mac, `secrets.h` on the ESP32).

```
Device:  n = random 16 bytes
         reqMAC = HMAC-SHA256(K, "tsumuji/req/v1" || n)
Device → Helper:  EV <hex(n)> <hex(reqMAC)>\n

Helper:  verify reqMAC (constant time), reject if n was seen before
         S       = HMAC-SHA256(K, "tsumuji/session/v1" || n)
         ct      = AES-256-CTR(key = S, iv = n, password)
         respMAC = HMAC-SHA256(S, "tsumuji/resp/v1" || ct)
Helper → Device:  PW <hex(ct)> <hex(respMAC)>\n
             or:  ERR\n            (MAC/replay failure — no ciphertext, no detail)

Device:  S = HMAC-SHA256(K, "tsumuji/session/v1" || n)
         verify respMAC, decrypt, type via HID, wipe buffers
```

Known-answer vector (see `helper/crypto_test.go` `TestKnownAnswer`):

| item | value |
|---|---|
| K | `000102…1e1f` (bytes 0x00..0x1f) |
| n | `00112233445566778899aabbccddeeff` |
| plaintext | `hello` |
| reqMAC | `73f690cc5195e893ab7b82c33d6ee4c5229890070379474416afa72ccb3edba0` |
| S | `c9bfd10d0eccec2e1b16bd717b55aeb9df341d9234de3a0cd7e0318f9b5c095f` |
| ct | `084ce369f1` |
| respMAC | `662e6179e00d9b89364bbfbe29ead0cbe8d47b88d2cfa91c30e67c44e1ef9802` |

Use this vector to validate the ESP32 (mbedtls) implementation before wiring it end-to-end.

## Notes

- The reply is **Encrypt-then-MAC**: AES-CTR for confidentiality, `respMAC` (HMAC-SHA256 under the
  session key, over the ciphertext) for integrity. The device MUST verify `respMAC` in constant time
  *before* decrypting, and MUST NOT type anything if verification fails. Because the session key is
  derived from the request nonce, a reply cannot be spliced onto a different request.
- AES-GCM would give the same guarantee with a single primitive and less room for ordering mistakes
  on the firmware side; switching is a candidate for when the firmware's authenticated mode is written
  (helper change: `cipher.NewGCM` + updated known-answer vectors).
- `ERR` replies are unauthenticated by design: an attacker who can forge them can only prevent typing.
- Nonce replay cache lives in helper memory (bounded, FIFO eviction). A restart forgets it; acceptable for a desk device.
- The fingerprint match is a local gate on the ESP32 and is *not* bound to this protocol (see hardening options in the plan).
