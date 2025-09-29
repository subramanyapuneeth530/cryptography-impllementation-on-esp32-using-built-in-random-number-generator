/*
  ESP32 + ChaCha20-Poly1305 (AEAD) demo
  - HW RNG for key (32B) and nonce prefix (4B)
  - Nonce = 4B random prefix || 8B counter (big-endian)
  - AAD = the 8B counter (so message order tampering is detected)
  - Reads a line from Serial, encrypts, decrypts, prints timings

  Libraries:
    - Crypto by rweather (Library Manager): provides ChaChaPoly
  Board:
    - Any ESP32 (e.g., ESP32 Dev Module)

  SECURITY NOTE: This prints the key for demo purposes.
  Do NOT print or log keys in real applications.
*/

#include <Arduino.h>
#include <WiFi.h>          // used only to enable RF so HW RNG has entropy
#include <esp_system.h>    // esp_fill_random()
#include <Crypto.h>
#include <ChaChaPoly.h>
#include <vector>

// ---------- Config ----------
static const uint32_t SERIAL_BAUD = 115200;

// ---------- Global state ----------
static uint8_t g_key[32];        // 32-byte AEAD key (demo: generated once at boot)
static uint8_t g_nonce_prefix[4];// 4-byte random prefix for nonce uniqueness across reboots
static uint64_t g_counter = 0;   // 8-byte message counter (nonce suffix)

// ---------- Utilities ----------
static inline void random_bytes(uint8_t* buf, size_t len) {
  // Ensure RF is ON so esp_fill_random draws from true HW entropy.
  if (WiFi.getMode() == WIFI_OFF) {
    WiFi.mode(WIFI_STA); // doesn't connect; just powers RF front-end
  }
  esp_fill_random(buf, len);
}

static void u64_to_be(uint64_t x, uint8_t out[8]) {
  for (int i = 7; i >= 0; --i) { out[i] = uint8_t(x & 0xFF); x >>= 8; }
}

static void printHex(const uint8_t* data, size_t len) {
  static const char* hex = "0123456789ABCDEF";
  for (size_t i = 0; i < len; ++i) {
    uint8_t b = data[i];
    Serial.print(hex[b >> 4]);
    Serial.print(hex[b & 0x0F]);
  }
}

static String readLine() {
  // Allow long input; block until a line arrives.
  Serial.setTimeout(600000); // 10 minutes
  String s = Serial.readStringUntil('\n');
  s.trim(); // remove CR/LF and surrounding spaces
  return s;
}

static void build_nonce(uint8_t nonce[12], uint64_t counter) {
  memcpy(nonce, g_nonce_prefix, 4);
  u64_to_be(counter, nonce + 4);
}

// ---------- AEAD helpers ----------
static bool chachapoly_encrypt(const uint8_t* pt, size_t pt_len,
                               const uint8_t* aad, size_t aad_len,
                               const uint8_t key[32],
                               const uint8_t nonce[12],
                               uint8_t* ct, uint8_t tag[16],
                               unsigned long& enc_us) {
  ChaChaPoly aead;
  aead.setKey(key, 32);
  aead.setIV(nonce, 12);
  if (aad && aad_len) aead.addAuthData(aad, aad_len);

  unsigned long t0 = micros();
  aead.encrypt(ct, pt, pt_len);
  aead.computeTag(tag, 16);
  enc_us = micros() - t0;
  return true;
}

static bool chachapoly_decrypt(const uint8_t* ct, size_t ct_len,
                               const uint8_t* aad, size_t aad_len,
                               const uint8_t key[32],
                               const uint8_t nonce[12],
                               const uint8_t tag[16],
                               uint8_t* pt_out,
                               unsigned long& dec_us,
                               bool& auth_ok) {
  ChaChaPoly aead;
  aead.setKey(key, 32);
  aead.setIV(nonce, 12);
  if (aad && aad_len) aead.addAuthData(aad, aad_len);

  unsigned long t0 = micros();
  aead.decrypt(pt_out, ct, ct_len);   // plaintext not trusted until tag verifies
  auth_ok = aead.checkTag(tag, 16);
  dec_us = micros() - t0;
  return true;
}

// ---------- Arduino ----------
void setup() {
  Serial.begin(SERIAL_BAUD);
  while (!Serial) { delay(1); }
  delay(250);

  Serial.println();
  Serial.println(F("== ESP32 ChaCha20-Poly1305 (AEAD) demo =="));
  Serial.println(F("Note: Wi-Fi will be enabled (not connected) to power HW RNG."));

  // Power RF so TRNG has full entropy
  WiFi.mode(WIFI_STA);

  // Generate key and nonce prefix from HW RNG
  random_bytes(g_key, sizeof g_key);
  random_bytes(g_nonce_prefix, sizeof g_nonce_prefix);

  Serial.print(F("Key (32B)           : ")); printHex(g_key, sizeof g_key); Serial.println();
  Serial.print(F("Nonce prefix (4B)   : ")); printHex(g_nonce_prefix, sizeof g_nonce_prefix); Serial.println();
  Serial.println(F("Security note: Don't print keys in production."));
  Serial.println();

  Serial.println(F("Type a line and press Enter to encrypt/decrypt."));
  Serial.println(F("(Each message uses a new nonce = prefix || counter)"));
  Serial.println();
}

void loop() {
  if (Serial.available() == 0) {
    delay(10);
    return;
  }

  String line = readLine();
  if (line.length() == 0) {
    Serial.println(F("[empty line]"));
    return;
  }

  // Prepare buffers
  std::vector<uint8_t> pt(line.length());
  memcpy(pt.data(), line.c_str(), pt.size());

  std::vector<uint8_t> ct(pt.size());
  std::vector<uint8_t> pt_out(pt.size());
  uint8_t tag[16];
  uint8_t nonce[12];

  // Nonce and AAD = 8B counter (big-endian)
  build_nonce(nonce, g_counter);
  uint8_t aad[8]; u64_to_be(g_counter, aad);

  // Timings
  unsigned long total_t0 = micros();
  unsigned long enc_us = 0, dec_us = 0;
  bool ok = false;

  // Encrypt
  chachapoly_encrypt(pt.data(), pt.size(), aad, sizeof(aad),
                     g_key, nonce, ct.data(), tag, enc_us);

  // Decrypt + verify
  chachapoly_decrypt(ct.data(), ct.size(), aad, sizeof(aad),
                     g_key, nonce, tag, pt_out.data(), dec_us, ok);

  unsigned long total_us = micros() - total_t0;

  // Output
  Serial.println(F("------------------------------------------------------------"));
  Serial.print  (F("Counter (AAD)       : ")); Serial.println((unsigned long)(g_counter & 0xFFFFFFFFULL)); // low 32 shown
  Serial.print  (F("Nonce (12B)         : ")); printHex(nonce, sizeof nonce); Serial.println();
  Serial.print  (F("Ciphertext (hex)    : ")); printHex(ct.data(), ct.size()); Serial.println();
  Serial.print  (F("Tag (16B)           : ")); printHex(tag, sizeof tag); Serial.println();

  if (!ok) {
    Serial.println(F("AUTH FAIL: tag mismatch. Discarding plaintext."));
  } else {
    Serial.print  (F("Decrypted plaintext : "));
    // Print as text safely (not adding extra newline besides this one)
    for (size_t i = 0; i < pt_out.size(); ++i) Serial.write(pt_out[i]);
    Serial.println();
  }

  // Timings
  auto print_time = [](const __FlashStringHelper* label, unsigned long us){
    Serial.print(label);
    Serial.print(us); Serial.print(F(" us  ("));
    Serial.print(us / 1000.0, 3); Serial.println(F(" ms)"));
  };
  print_time(F("Encrypt time        : "), enc_us);
  print_time(F("Decrypt+verify time : "), dec_us);
  print_time(F("Total (enc→dec)     : "), total_us);

  Serial.println(F("------------------------------------------------------------"));
  Serial.println();
  Serial.println(F("Type another line..."));
  Serial.println();

  // Next message
  g_counter++;
}
