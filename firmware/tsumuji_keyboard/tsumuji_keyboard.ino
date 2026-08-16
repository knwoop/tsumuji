// tsumuji — fingerprint-triggered password typer for Mac.
// Target: Seeed XIAO ESP32-S3 (native USB-OTG).
//
// Board-only bring-up (plaintext mode, no sensor, no crypto).
//   - Enumerates as a composite USB device: HID keyboard + CDC serial.
//   - BOOT button (GPIO0) acts as the trigger (stand-in for the fingerprint sensor).
//   - On press: send "EV\n" to the Mac helper over CDC, wait for "PW <text>\n",
//     then type <text> as keyboard input.
//   - If STANDALONE_DEMO is defined and no helper answers, type a fixed string
//     so the HID path can be verified without the helper.
//
// Arduino IDE board settings (REQUIRED, otherwise HID/CDC will not work):
//   Board:            XIAO_ESP32S3
//   USB CDC On Boot:  Enabled
//   USB Mode:         USB-OTG (TinyUSB)
//
// Wire protocol (line-based, ASCII, "\n" terminated) — see docs/protocol.md.

#include "USB.h"
#include "USBHIDKeyboard.h"

// ---- Configuration ---------------------------------------------------------

// Uncomment to type a fixed string when the helper does not respond.
#define STANDALONE_DEMO
static const char *DEMO_TEXT = "tsumuji hid ok";

static const int TRIGGER_PIN = 0;               // BOOT button, active-low
static const unsigned long DEBOUNCE_MS = 50;
static const unsigned long COOLDOWN_MS = 1500;  // ignore re-triggers for a while
static const unsigned long HELPER_TIMEOUT_MS = 2000;
static const bool PRESS_ENTER_AFTER_TYPING = true;

// USB identity. The helper matches on VID/PID/product, so keep these in sync
// with helper/serial.go. 0x303A/0x1001 are the Espressif ESP32-S3 defaults.
static const uint16_t USB_VID_TSUMUJI = 0x303A;
static const uint16_t USB_PID_TSUMUJI = 0x1001;
static const char *USB_PRODUCT_NAME = "tsumuji";
static const char *USB_MANUFACTURER_NAME = "tsumuji";

// Longest accepted reply line. In authenticated mode a reply is
// "PW <hex(ct)> <hex(mac)>" = 3 + 2*len(pw) + 1 + 64, so 512 allows a
// password of ~220 bytes. Longer lines are rejected as a whole, never truncated.
static const size_t MAX_LINE = 512;

// ---- State -----------------------------------------------------------------

USBHIDKeyboard Keyboard;

static char lineBuf[MAX_LINE];
static size_t lineLen = 0;

static int lastRawState = HIGH;
static int stableState = HIGH;
static unsigned long lastChangeMs = 0;
static unsigned long lastTriggerMs = 0;

// ---- Helpers ---------------------------------------------------------------

static void wipe(char *buf, size_t len) {
  // volatile pointer so the compiler cannot optimize the clear away.
  volatile char *p = buf;
  while (len--) *p++ = 0;
}

static void typeText(const char *text) {
  Keyboard.print(text);
  if (PRESS_ENTER_AFTER_TYPING) {
    Keyboard.write(KEY_RETURN);
  }
}

// Read one "\n"-terminated line from Serial into lineBuf within timeoutMs.
// Returns true on success; lineBuf is NUL-terminated (CR stripped).
// A line longer than MAX_LINE-1 is consumed and rejected in full: typing a
// truncated password (and pressing Enter) would be worse than typing nothing.
static bool readLine(unsigned long timeoutMs) {
  lineLen = 0;
  bool overflow = false;
  unsigned long start = millis();
  while (millis() - start < timeoutMs) {
    while (Serial.available()) {
      char c = (char)Serial.read();
      if (c == '\n') {
        if (overflow) {
          wipe(lineBuf, sizeof(lineBuf));
          lineLen = 0;
          return false;
        }
        if (lineLen > 0 && lineBuf[lineLen - 1] == '\r') lineLen--;
        lineBuf[lineLen] = '\0';
        return true;
      }
      if (lineLen < MAX_LINE - 1) {
        lineBuf[lineLen++] = c;
      } else {
        overflow = true;  // keep draining until newline, then reject
      }
    }
    delay(1);
  }
  wipe(lineBuf, sizeof(lineBuf));
  lineLen = 0;
  return false;
}

// Ask the helper for the text to type. Returns true if a "PW " line arrived.
static bool requestFromHelper() {
  // Drain any stale input first.
  while (Serial.available()) Serial.read();

  Serial.print("EV\n");
  Serial.flush();

  if (!readLine(HELPER_TIMEOUT_MS)) return false;
  return strncmp(lineBuf, "PW ", 3) == 0;
}

static void onTrigger() {
  bool ok = requestFromHelper();
  if (ok) {
    typeText(lineBuf + 3);
    wipe(lineBuf, sizeof(lineBuf));
    return;
  }
#ifdef STANDALONE_DEMO
  typeText(DEMO_TEXT);
#endif
}

// Debounced falling-edge detection on the trigger pin.
static bool triggerPressed() {
  int raw = digitalRead(TRIGGER_PIN);
  unsigned long now = millis();
  if (raw != lastRawState) {
    lastChangeMs = now;
    lastRawState = raw;
  }
  if (now - lastChangeMs >= DEBOUNCE_MS && raw != stableState) {
    stableState = raw;
    if (stableState == LOW && now - lastTriggerMs >= COOLDOWN_MS) {
      lastTriggerMs = now;
      return true;
    }
  }
  return false;
}

// ---- Arduino entry points --------------------------------------------------

void setup() {
  pinMode(TRIGGER_PIN, INPUT_PULLUP);

  // Descriptor fields must be set before USB.begin().
  USB.VID(USB_VID_TSUMUJI);
  USB.PID(USB_PID_TSUMUJI);
  USB.productName(USB_PRODUCT_NAME);
  USB.manufacturerName(USB_MANUFACTURER_NAME);

  // Serial is the USB CDC port when "USB CDC On Boot" is enabled.
  Serial.begin(115200);
  Keyboard.begin();
  USB.begin();

  // Give the host a moment to enumerate the composite device.
  delay(1000);
}

void loop() {
  if (triggerPressed()) {
    onTrigger();
  }
  delay(2);
}
