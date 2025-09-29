# cryptography-impllementation-on-esp32-using-built-in-random-number-generator
This Markdown explains an Arduino sketch for ESP32 that demonstrates authenticated encryption using ChaCha20-Poly1305 (AEAD) via the rweather Crypto library. The program generates a random 32-byte key and a 12-byte nonce per message (built from a 4-byte random prefix and an 8-byte counter), treats the counter as AAD (additional authenticated data) to catch reordering/tampering, and then encrypts whatever you type over Serial. It immediately decrypts/validates the result and prints timings. It’s a teaching demo — it even prints the key (do not do that in real systems).


# How the code works

## 1) Setup & entropy

- **Serial & Wi-Fi**  
  Initializes Serial at `115200` and enables `WiFi.mode(WIFI_STA)` **without connecting**. This powers the RF circuitry so the ESP32’s TRNG has strong entropy.

- **Random key & prefix**  
  Calls `esp_fill_random()` (wrapped in `random_bytes()`) to fill:
  - `g_key[32]` — the ChaCha20-Poly1305 key (once at boot).
  - `g_nonce_prefix[4]` — a per-boot random prefix to help avoid nonce reuse across reboots.

- **Visibility (demo only)**  
  Prints the key and prefix for demonstration purposes.

---

## 2) Nonce & AAD strategy

- **Nonce**  
  `12` bytes = `4`-byte random prefix `||` `8`-byte **big-endian** counter.  
  Built by `build_nonce(nonce, g_counter)`, where `g_counter` starts at `0` and increments per message.

- **AAD (Additional Authenticated Data)**  
  The **same 8-byte counter** is supplied as AAD.  
  This doesn’t hide data but **binds** the message to its counter, so reordering or stripping messages triggers authentication failure.

---

## 3) Encrypt / Decrypt (AEAD)

- **Library**  
  Uses `ChaChaPoly` from the rweather **Crypto** library.

- **Encrypt (`chachapoly_encrypt`)**
  - `setKey(key)`, `setIV(nonce)`, `addAuthData(aad)`
  - `encrypt(pt → ct)` and `computeTag(tag)`
  - Measures elapsed microseconds.

- **Decrypt + verify (`chachapoly_decrypt`)**
  - Same key/nonce/AAD
  - `decrypt(ct → pt_out)` then `checkTag(tag)`
  - **Only prints plaintext if the tag verifies**.

---

## 4) I/O & timings

- **Input**  
  Reads a line from Serial (`readLine()`), trims it.

- **Process**  
  Converts to byte vector → **encrypts** → **decrypts** → **prints**:
  - Counter (lower 32 bits for readability)
  - Nonce (hex), Ciphertext (hex), Tag (hex)
  - Decrypted plaintext (only if `auth_ok`)
  - **Encrypt**, **Decrypt+verify**, and **Total** times (in microseconds and milliseconds)

- **Next message**  
  Increments `g_counter` for the next message.


# Annotated structure
This section orients you to the sketch’s moving parts at a glance. It lists the global variables that hold secrets and counters, the utility helpers for randomness and formatting, the AEAD wrappers for encrypt/decrypt, and the Arduino lifecycle functions. Read it first to see how the code is layered and how data flows from Serial input to authenticated ciphertext and back.

## Globals
- `g_key[32]` — 32-byte ChaCha20-Poly1305 key (demo-only; generated at boot).
- `g_nonce_prefix[4]` — per-boot random prefix to reduce cross-reboot nonce collision risk.
- `g_counter` — 64-bit message counter; used in nonce and as AAD.

## Utilities
- `random_bytes(buf, len)` — Ensures `WiFi.mode(WIFI_STA)` then fills `buf` via `esp_fill_random()`.
- `u64_to_be(x, out[8])` — Encodes a 64-bit integer big-endian.
- `printHex(data, len)` — Hex dump to Serial.
- `readLine()` — Blocks until a line arrives on Serial; trims whitespace/CRLF.
- `build_nonce(nonce[12], counter)` — Concatenates `g_nonce_prefix` (4B) and `counter` (8B big-endian).

## AEAD helpers
- `chachapoly_encrypt(pt, pt_len, aad, aad_len, key, nonce, ct, tag, enc_us)`  
  Sets key/IV, adds AAD, encrypts PT→CT, computes 16B tag, measures time.
- `chachapoly_decrypt(ct, ct_len, aad, aad_len, key, nonce, tag, pt_out, dec_us, auth_ok)`  
  Sets key/IV, adds AAD, decrypts CT→PT, verifies tag, measures time.

## Arduino lifecycle
- `setup()`  
  - Starts Serial, enables Wi-Fi (entropy), generates key + nonce prefix.  
  - Prints demo banner, key/prefix (teaching only), and usage notes.
- `loop()`  
  - If a line is available: read, build nonce & AAD from `g_counter`, encrypt, decrypt+verify.  
  - Prints counter, nonce, ciphertext, tag, decrypted plaintext (only if `auth_ok`), timings.  
  - Increments `g_counter` for next message.


# Security notes & best practices
This is the “don’t shoot your foot” checklist. It covers key handling (never print/log), nonce uniqueness discipline, why AAD is authenticated but not secret, verify-before-use rules, replay defenses, and guidance on session keys and rotation. Use these guardrails to harden the demo into something you can trust.

- **Do not print keys in production.** Remove all key logging; treat secrets as sensitive from boot.
- **Guarantee nonce uniqueness per key.**  
  - Current demo: 4B random prefix + 64B counter per boot → low collision risk, not zero across reboots.  
  - Better: persist counter and/or use a larger persistent prefix (e.g., 12B total stored in NVS).
- **Consider session keys.** Derive `session_key = HKDF(master_key, salt=session_random)` so accidental nonce reuse across sessions doesn’t collide under the same key.
- **Validate before use.** Never act on decrypted bytes until `auth_ok == true`.
- **Don’t put secrets in AAD.** AAD is authenticated, not encrypted.
- **Key lifecycle.** Plan rotation, revocation, and per-device uniqueness; prefer provisioning or ECDH-derived keys.
- **Replay protection.** Track highest accepted counter per peer; reject stale or duplicate counters.
- **Side-channel hygiene.** Avoid timing-based branching on secret data beyond the library’s constant-time operations.


# Scalability & productionizing
These notes explain how to evolve from a single-device demo to a fleet-ready system: improving throughput and memory usage, persisting counters across reboots, defining a stable message frame, integrating real transports, provisioning per-device keys, and adding observability without leaking secrets.

## Throughput & resource use
- Reuse buffers and (optionally) `ChaChaPoly` objects to reduce setup overhead.
- Operate on binary frames; avoid `String` conversions for large payloads.
- Measure with the built-in microsecond timers to size buffers and choose transports.

## Multi-device fleets
- **Disjoint nonce spaces**: per-device keys or persistent unique prefixes stored in NVS.
- **Provisioning**: factory-programmed keys/certs; secure boot and flash encryption where possible.

## Robustness across reboots
- Persist **counter** and/or a **session ID**; resume without risking nonce reuse.
- Implement **anti-replay windows** on receivers.

## Transport integration
- Replace Serial with **BLE**, **Wi-Fi (MQTT/TCP/UDP)**; define a frame like:  
  `version | prefix(4 or 12) | counter(8) | ct(len) | tag(16)`  
  Keep versioning to allow future migrations.

## Key management & rotation
- Use HKDF to derive sub-keys (e.g., `enc`, `mac`, `control`) from a master or session secret.
- Schedule rotation; invalidate old keys; support over-the-air rekeying.

## Observability
- Log only **metadata** (e.g., counter, sizes, timing) — never keys or plaintext.
- Emit auth failures and replay rejections with bounded detail for debugging.

## Hardening
- Input limits and sanity checks on message sizes.
- Wipe sensitive buffers after use when feasible.


# Applications
Here you’ll find concrete ways to reuse this pattern beyond a console demo. It highlights embedded scenarios—secure telemetry, command channels, device-to-cloud links—and shows how swapping Serial for BLE/MQTT/TCP quickly turns the example into a practical, authenticated and confidential messaging path.

- **Secure telemetry**: Encrypt sensor readings; bind counters via AAD to detect replays/reordering.
- **Command/control channels**: Verify authenticity/integrity before acting on received commands.
- **Device-to-cloud messaging**: Lightweight AEAD suitable for ESP32 performance envelopes.
- **Edge logging**: Confidential logs where integrity is paramount (tag verification gates reads).
- **Prototyping AEAD flows**: Swap Serial for BLE/MQTT/TCP to trial message security in real transports.
- **Session-bound data**: Use a session identifier in AAD to tie messages to a connection lifecycle.


# Summary

This demo is a concise ESP32 implementation of **ChaCha20-Poly1305 AEAD** showing correct nonce discipline (`prefix || counter`), authenticated metadata via **AAD** (the counter), and strict **verify-before-trust** handling. It’s suitable as a learning scaffold and can evolve into a production channel by (1) removing key prints, (2) persisting nonce state or deriving **session keys**, (3) adding replay protections, and (4) moving from Serial to a real transport with framed messages. With those changes, it scales from a console demo to a reliable, secure messaging layer for embedded devices.
