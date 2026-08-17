# tsumuji

Fingerprint-triggered password typer for Mac. An ESP32-S3 acts as a USB HID keyboard;
on a fingerprint match it asks a Mac-side Go helper (over USB CDC) for the login password,
which is delivered encrypted under a pre-shared key and typed via HID.

Inspired by [tinyTouch](https://github.com/zimengxiong/tinytouch). Not a Touch ID bypass —
an external password-entry device.

> Wire protocol: [docs/protocol.md](docs/protocol.md).

## Layout

```
firmware/tsumuji_keyboard/   Arduino sketch for XIAO ESP32-S3 (HID + CDC)
  secrets.h.example          copy to secrets.h (git-ignored) for authenticated mode
helper/                      Go helper (serial, crypto, Keychain)
launchd/                     LaunchAgent plist for running the helper at login
docs/                        protocol
```

## Status

- [x] Bring-up: firmware (button → `EV` → type reply) + helper `--insecure-text` mode — **needs board to verify**
- [x] Helper authenticated mode: PSK MAC / session key / AES-CTR / nonce replay cache, unit-tested with KAT
- [ ] Firmware authenticated mode (mbedtls HMAC + AES-CTR, `secrets.h`)
- [ ] ZW101 fingerprint trigger
- [ ] launchd daemon
- [ ] Hardening (flash encryption / secure boot / asymmetric / SE)

## Bring-up quick start

Firmware (Arduino IDE, esp32 board package by Espressif):

1. Board: **XIAO_ESP32S3**, `USB CDC On Boot: Enabled`, `USB Mode: USB-OTG (TinyUSB)`.
2. Open `firmware/tsumuji_keyboard/tsumuji_keyboard.ino`, upload.
3. Standalone check: focus a text field, press the BOOT button → `tsumuji hid ok` is typed
   (falls back to the demo string when no helper answers within 2 s).

Helper:

```sh
make test          # unit tests (no hardware needed)
make run-plain     # answers every EV with a fixed string
```

Press BOOT again → the helper's string is typed instead of the demo string.

## Authenticated mode setup (helper side)

```sh
openssl rand -hex 32                     # pairing key
bin/tsumuji-helper pair <hex>            # → Keychain
bin/tsumuji-helper set-password          # → Keychain (prompted, not echoed)
bin/tsumuji-helper serve                 # secure mode
```

Put the same hex into `firmware/tsumuji_keyboard/secrets.h` (see `secrets.h.example`). Never commit it.

## Device detection

The helper auto-detects the board by USB VID `303A` / PID `1001` / product string `tsumuji`
(set by the firmware). It refuses to guess: no match or more than one match is an error.
Override with `serve --port /dev/cu.usbmodemXXXX` (e.g. before the custom firmware is flashed).

## Gotchas

- ESP32-**C3** cannot be a HID keyboard; use S3.
- Both XIAO and ZW101 are 3.3 V; UART is crossed (TX↔RX).
- Failure branches first: no `EV` on fingerprint mismatch, no ciphertext on MAC/replay failure.
