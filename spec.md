## KBVault — Keyboard Password Vault

### Design & Requirements Document v2

**Project:** Embedded password manager for Keychron Q3 Max
**Platform:** STM32F401xC (ARM Cortex-M4, 84 MHz, 256 KB flash, 64 KB SRAM)
**Firmware:** QMK fork
**Author:** hermo
**Status:** Draft v3
**Date:** 2026-03-14

---

### 1. Overview

KBVault is a minimal password vault embedded in keyboard firmware. It stores up
to 5 passwords encrypted in MCU flash, protected by a master password and
hardware-bound key derivation. Passwords are stored elsewhere as backup — vault
loss (re-flash, wipe, hardware failure) is acceptable and expected.

The crypto core is provided by **hxcrypt**, a separate standalone C library
(symlinked at `hxcrypt/`). hxcrypt is malloc-free, has zero external dependencies,
and provides all cryptographic primitives used by KBVault: BLAKE2s, ChaCha20,
PBKDF2-BLAKE2s, HKDF-Expand-BLAKE2s, constant-time comparison, and secure
zeroing. KBVault contains no crypto code of its own — it calls the `hx_*` API
exclusively.

---

### 2. Threat Model

#### In Scope

| Threat | Mitigation |
|---|---|
| Shoulder surfing | Keyboard types stored password via HID |
| Flash dump via debug interface | RDP1 — debug access triggers mass erase |
| Offline brute-force of vault | KDF bound to unextractable unique ID + pepper |
| Ciphertext manipulation | Encrypt-then-MAC, verified before decrypt |
| Physical coercion | Duress password wipes vault, indistinguishable from wrong password |
| Brute-force via HID injection | Exponential lockout after failed attempts (1 s → 30 s cap) |
| Unattended unlocked device | 120-minute auto-lock |

#### Out of Scope

| Threat | Reason |
|---|---|
| Compromised host | Assumed trusted enough |
| Chip decapping / fault injection | Nation-state, out of scope |
| Offline brute-force of flash dump | Non-standard PBKDF2-BLAKE2s pipeline (no hashcat module), high-entropy master password, UID-bound salt (unreadable at RDP1). See ADR 006. |
| BT/2.4 GHz HID sniffing | Accepted risk — passwords are low-value duplicates |
| Side-channel / power analysis | Low risk with ChaCha20; accepted |

---

### 3. Cryptographic Design

#### 3.1 Primitives (provided by hxcrypt)

| Primitive | hxcrypt function | Usage |
|---|---|---|
| BLAKE2s (keyed, 32B out) | `hx_blake2s()` | PRF, MAC, password verification |
| ChaCha20 | `hx_chacha20_xor()` | Stream cipher for vault encryption |
| PBKDF2-BLAKE2s | `hx_pbkdf2_blake2s()` | Password stretching (4096 rounds — see ADR 006) |
| HKDF-Expand-BLAKE2s | `hx_hkdf_expand_blake2s()` | Per-slot key derivation |
| Constant-time compare | `hx_ct_equal()` | Tag and verify_tag comparison |
| Secure zeroing | `hx_explicit_zero()` | Key/plaintext wiping |
| CSPRNG (ChaCha20-BLAKE2s DRBG) | `hx_csprng_*()` | Salt, pepper, nonce generation |

**Note:** The STM32F401 does not have a hardware TRNG (unlike F405/F407/L4xx).
The CSPRNG (DRBG + entropy pool) lives in hxcrypt. Platform-specific entropy
collection (ADC noise, DWT jitter, keystroke timing) lives in kbvault and
feeds the DRBG via `hx_csprng_stir()` + `hx_csprng_seed()`.

All crypto primitives come from hxcrypt. KBVault has no crypto dependencies
beyond `#include "hxcrypt.h"`.

#### 3.2 Key Derivation

```
Inputs:
  unique_id   : 96-bit MCU hardware ID (at 0x1FFF7A10, unreadable at RDP1+)
  pepper      : 256-bit random (generated once, in flash)
  salt        : 128-bit random (generated once, stored in vault header)
  master_pwd  : user-provided

Derivation:
  bound_salt  = BLAKE2s(salt, key = unique_id || pepper)
  prk         = PBKDF2-BLAKE2s(master_pwd, bound_salt, 4096)

Verification (stored in header):
  verify_tag  = BLAKE2s("kbv.verify", key = prk)

Per-slot keys (slot i = 0..4):
  enc_key[i]  = HKDF-Expand(prk, "enc" || byte(i), 32)
  mac_key[i]  = HKDF-Expand(prk, "mac" || byte(i), 32)
```

One KDF call per unlock. HKDF-Expand is cheap per slot.

#### 3.3 Duress Password

Duress password goes through the identical KDF:

```
duress_prk  = PBKDF2-BLAKE2s(duress_pwd, bound_salt, 4096)
duress_tag  = BLAKE2s("kbv.duress", key = duress_prk)
```

Stored in header alongside `verify_tag`.

#### 3.4 Authentication Flow

```
prk = PBKDF2-BLAKE2s(input, bound_salt, 4096)   // one KDF call
tag = BLAKE2s("kbv.verify", key = prk)

if ct_equal(tag, stored_verify_tag)  → UNLOCK (keep prk in SRAM)
elif ct_equal(tag, stored_duress_tag) → WIPE (flash + SRAM, then fake "wrong")
else                                  → WRONG PASSWORD
```

Single KDF call regardless of outcome.

#### 3.5 Encryption

Encrypt-then-MAC per slot:

```
Encrypt:
  nonce  = CSPRNG(12)
  ct     = ChaCha20(enc_key[i], nonce, plaintext)
  tag    = BLAKE2s(nonce || ct, key = mac_key[i])
  store  = nonce || ct_len || ct || tag

Decrypt:
  recompute tag → constant-time compare → reject or decrypt
  explicit_bzero(plaintext) after use
```

---

### 4. Hardware Security

#### RDP Level 1

| Property | Behavior |
|---|---|
| Flash read via SWD/JTAG | Blocked |
| Debug connection | Mass erase triggered — secrets destroyed |
| Re-flash | Possible after mass erase (vault + pepper gone) |
| Unique device ID | Readable by firmware only |

#### Current Status

RDP1 is **active** on the production keyboard (set 2026-03-14).
Verified via STM32CubeProgrammer: option byte read is now blocked, confirming Level 1 protection.

#### Development Workflow

```
Dev:   RDP0, dummy passwords, test freely
Prod:  flash → set RDP1 → enter passwords
Flash: unlock (mass erase, RDP→0) → flash → lock (RDP→1) → re-enter passwords
```

RDP1 blocks the DFU page-erase command, so `dfu-util` / `qmk flash` will fail
while RDP1 is active. Use STM32_Programmer_CLI directly. A `Makefile` in the
QMK keymap directory provides `make unlock`, `make flash`, `make lock`, and
`make deploy` to automate the full cycle.

To set RDP1 (DFU mode, after flashing):
```sh
STM32_Programmer_CLI -c port=USB1 -ob RDP=0xBB
```

To revert to RDP0 (triggers mass erase — vault + firmware wiped, must reflash):
```sh
STM32_Programmer_CLI -c port=USB1 -ob RDP=0xAA
```

**Never set RDP=0xCC (Level 2) — it is permanent and irreversible.**

STM32CubeProgrammer download: https://www.st.com/en/development-tools/stm32cubeprog.html

---

### 5. Flash Layout

Target: sector 5 (0x08020000, 128 KB physical) — only 16 KB of it used for vault data.
Flash sectors: 4×16K (0-3) + 64K (4) + 128K (5). Vault occupies sector 5; firmware
is capped at sectors 0-4 (112 KB total) by a keymap-specific linker script.

```
Offset  Size   Field
──────────────────────────────────────────
Header (120 bytes):
0x00    4      magic "KBVT"
0x04    1      version
0x05    1      slot_flags (NOR-inverted: bit 0 in flash = slot occupied; erased 0xFF = all empty)
0x06    2      reserved
0x08    32     pepper
0x28    16     salt
0x38    32     verify_tag (master)
0x58    32     duress_tag
0x78    -      (header end, 120 bytes)

Slot 0..4 (174 bytes each, 870 total):
+0x00   12     nonce
+0x0C   1      ct_len (max 128)
+0x0D   128    ciphertext (padded to max)
+0x8D   32     mac_tag
+0xAD   1      reserved/padding
        ──
        174 bytes per slot

Total: 120 + (5 × 174) = 990 bytes < 16 KB sector ✓
```

No labels. Slots identified by number only (1–5).
Maximum password length: 128 bytes.

---

### 6. State Machine

Four states. Only AUTHING and MENU capture keypresses — UNLOCKED is transparent (keyboard operates normally).

```
        power on
       ─────────▶ ┌──────────────┐
                  │    LOCKED    │ ◀── KBV_LOCK (any state)
                  │  (RGB: red)  │ ◀── timeout (120 min)
                  └──────┬───────┘ ◀── wrong/duress pwd
                         │
                    KBV_LOGIN pressed
                         │
                  ┌──────▼───────┐
                  │   AUTHING    │── correct pwd → UNLOCKED
                  │(RGB: amber)  │── duress pwd  → WIPE → LOCKED
                  └──────────────┘── wrong pwd   → LOCKED
                         keys captured, echoed nowhere

                  ┌──────────────┐
                  │   UNLOCKED   │ ◀── correct pwd from AUTHING
                  │ (RGB: green) │ ◀── 'q' from MENU
                  │  transparent │── KBV_MENU  → MENU
                  │  (keys pass  │── KBV_PASS_x → type slot, stay UNLOCKED
                  │   through)   │── KBV_LOCK  → LOCKED
                  └──────────────┘── timeout    → LOCKED

                  ┌──────────────┐
                  │     MENU     │ ◀── KBV_MENU from UNLOCKED
                  │  (RGB: blue) │── q: back to UNLOCKED (no lock)
                  │  keys        │── l/e/d/s/i/h/1-5: vault management
                  │  captured    │── KBV_LOCK: → LOCKED
                  └──────────────┘── timeout: → LOCKED
                    sub-state SETTINGS (p/d/c/b) within MENU
```

#### Hotkeys (defined in QMK keymap)

| Hotkey | Action |
|---|---|
| `KBV_LOGIN` | LOCKED → AUTHING. No-op if already UNLOCKED or MENU. Blocked during lockout (see below). |
| `KBV_MENU` | UNLOCKED → MENU. No-op if LOCKED or AUTHING. |
| `KBV_LOCK` | Any state → LOCKED. Zeroes all key material. |
| `KBV_PASS_1` … `KBV_PASS_5` | If UNLOCKED: decrypt and type that slot's password, stay UNLOCKED. No-op if LOCKED or MENU. |

#### Brute-force lockout

After a failed password attempt, `kbv_login()` ignores calls for an
exponentially increasing period: 1 s after the first failure, 2 s, 4 s, 8 s,
16 s, capping at 30 s. Successful authentication resets the counter. The
lockout state (`fail_count`, `lockout_until_ms`) lives in `kbv_ctx_t` (SRAM)
and resets on power cycle.

#### `kbv_is_active()` semantics

Returns true **only** for AUTHING and MENU — states where the vault captures keypresses. Returns false for LOCKED and UNLOCKED. QMK glue must route all keypresses through `kbv_feed_char()` only when `kbv_is_active()` is true.

---

### 7. User Interface

Teletype style. Keyboard types output as HID keystrokes. User input captured by firmware only in AUTHING and MENU states. Backspace deletes the last entered character. Input is not echoed.

#### 7.1 Login (KBV_LOGIN hotkey)

```
[KBV_LOGIN pressed]
<RGB pulsates amber — no text output>
[user types master password, not echoed, followed by Enter]
<RGB turns green — vault is UNLOCKED, keyboard resumes normal operation>
```

Wrong password or duress:
```
<RGB flashes briefly, returns to red — vault stays LOCKED>
```

#### 7.2 Typing a stored password (KBV_PASS_x hotkeys)

```
[KBV_PASS_2 pressed while UNLOCKED]
[vault types the password stored in slot 2 as HID keystrokes]
[vault stays UNLOCKED — RGB remains green]
```

If slot is empty, flash the keyboard blue.

If vault is locked, flash keyboard red.

#### 7.3 Menu (KBV_MENU hotkey)

```
[KBV_MENU pressed while UNLOCKED]
l=list e=edit d=del s=settings i=info q=exit
kbv:
```

RGB turns blue. Keyboard input is now captured by the vault menu.

#### 7.4 Menu commands

```
kbv: h
l=list e=edit d=del s=set i=info q=exit h=help
kbv:
```

#### 7.4.1 Info

```
kbv: i
ent:1024b 1:* 2:. 3:. 4:. 5:.
kbv:
```

Shows accumulated entropy estimate (in bits) and slot occupancy. Useful for
diagnosing entropy issues when `e` refuses to write with `low entropy`.

#### 7.5 List

```
kbv: l
1:* 2:* 3:. 4:. 5:.
kbv:
```

`*` = occupied, `.` = empty.

#### 7.6 Edit (also allows adding)

```
kbv: e
#?
[user presses slot number, e.g. 3]
pw?
[user types password, not echoed, followed by Enter]
ok
kbv:
```

If less than 256 bits of entropy have been accumulated since boot, the write is
refused and the prompt returns `low entropy`. Use `i` to check; press more keys
to accumulate keystroke entropy, then retry.


#### 7.7 Delete

```
kbv: d
#?
[user presses slot number, e.g. 3]
d3? y/n
[user presses y]
ok
kbv:
```

#### 7.8 Type from menu

```
kbv: 2
[vault types password from slot 2 as HID, stays in MENU]
ok
kbv:
```

#### 7.9 Exit menu

```
kbv: q
[vault returns to UNLOCKED — RGB turns green, keyboard resumes normal operation]
```

`q` does **not** lock the vault. Use `KBV_LOCK` to lock.

#### 7.10 Lock (KBV_LOCK hotkey)

```
[KBV_LOCK pressed]
[vault immediately locks, all key material zeroed, RGB turns red]
```

Works from any state.

#### 7.11 Settings (from menu)

```
kbv: s
p=pass d=duress c=clear b=back
kbv: p
new?
[user types new master password]
confirm?
[user types again]
ok
kbv:
```

Duress change (`d`) — same flow.

Clear (`c`) — erases the vault flash sector and locks:

```
kbv: c
c? y/n
[user presses y]
[vault sector erased, vault locked, RGB red — no text output]
```

---

### 8. Memory Safety

| Rule | Details |
|---|---|
| Plaintext passwords zeroed after encrypt | `hx_explicit_zero()` after ChaCha20 encrypt |
| Plaintext passwords zeroed after HID send | `hx_explicit_zero()` after typing slot |
| Master password zeroed after KDF | `hx_explicit_zero()` once PRK is derived |
| All key material zeroed on lock | `hx_explicit_zero()` on PRK, enc_keys, mac_keys |
| Duress wipes SRAM then flash | SRAM first (keys), then flash (vault + pepper) |

`hx_explicit_zero()` is provided by hxcrypt and maps to a volatile memset to prevent compiler optimization.

---

### 9. Flash Write Policy

Flash is written **only** on:

| Operation | Writes |
|---|---|
| First-time setup | pepper, salt, verify_tag |
| Add/edit password | Slot data + slot_flags (NOR bit-clear, no erase) |
| Delete password | Full sector erase + rewrite (NOR can't flip 0→1 in slot_flags) |
| Change master password | Full sector erase + rewrite with re-encrypted slots (entropy guard applies) |
| Change duress password | duress_tag only (full sector erase + rewrite due to NOR constraints) |
| Duress wipe | Erase vault page |

At 10K cycle endurance and ~few writes per week: **decades of life**.

---

### 10. RGB Feedback

| State | RGB |
|---|---|
| LOCKED | Red (underglow, subtle) |
| AUTHING | Pulsing amber |
| UNLOCKED | Green |
| MENU (including settings sub-state) | Blue |
| ERROR | Brief red flash → LOCKED |
| POST-WIPE | Identical to LOCKED |

---

### 11. Project Structure

```
kbvault/
├── adr/
│   ├── 001-cipher-suite.md       // why ChaCha20+BLAKE2s
│   └── 002-entropy-sources.md    // why ADC + DWT + keystrokes
├── hxcrypt/  → ../hxcrypt/  // symlink to hxcrypt library
│   ├── include/
│   │   └── hxcrypt.h        // blake2s, chacha20, pbkdf2, hkdf, ct_equal, explicit_zero
│   └── src/
│       ├── blake2s.c
│       ├── chacha20.c
│       ├── csprng.c
│       ├── pbkdf2.c
│       ├── hkdf.c
│       └── utils.c
├── include/
│   ├── kbv.h                // public API
│   └── kbv_platform.h       // platform abstraction
├── src/
│   └── kbv.c                // vault logic, state machine (uses hx_* API)
├── platform/
│   ├── kbv_platform_stm32.c // STM32 HAL (flash, UID, CSPRNG)
│   └── kbv_platform_posix.c // POSIX mock (file-backed flash, urandom)
├── test/
│   └── test_vault.c         // vault logic tests (hxcrypt has its own tests)
├── Makefile                  // PC test build (cc, no QMK)
└── README.md
```

Note: hxcrypt is a separate project with its own test suite. KBVault tests
cover vault logic only — crypto primitive correctness is verified in hxcrypt.

#### 11.1 Platform Abstraction

```c
// kbv_platform.h
#pragma once
#include <stdint.h>
#include <stddef.h>

void     kbv_plat_get_uid(uint8_t out[12]);
void     kbv_plat_random(uint8_t *buf, size_t len);
int      kbv_plat_flash_read(uint32_t off, uint8_t *buf, size_t len);
int      kbv_plat_flash_write(uint32_t off, const uint8_t *buf, size_t len);
int      kbv_plat_flash_erase(void);        // erase vault sector
uint32_t kbv_plat_time_ms(void);            // for idle timeout
uint16_t kbv_plat_entropy_bits(void);       // accumulated entropy estimate
// Note: secure zeroing uses hx_explicit_zero() from hxcrypt, not the platform layer
```

QMK-specific functions (HID send, RGB control) are **not** part of the platform abstraction. They are called from QMK glue code in `keymap.c` using the public API in `kbv.h`.

For QMK builds, hxcrypt sources are added to the build via `rules.mk`:

```makefile
# rules.mk (QMK keymap)
SRC += hxcrypt/src/blake2s.c hxcrypt/src/chacha20.c hxcrypt/src/csprng.c \
       hxcrypt/src/pbkdf2.c hxcrypt/src/hkdf.c hxcrypt/src/utils.c
EXTRAFLAGS += -Ihxcrypt/include
```

#### 11.2 Public API (kbv.h)

```c
// Hotkey handlers — call from process_record_user on keydown
void kbv_login(kbv_ctx_t *ctx);          // KBV_LOGIN: LOCKED → AUTHING
void kbv_enter_menu(kbv_ctx_t *ctx);     // KBV_MENU: UNLOCKED → MENU
void kbv_lock(kbv_ctx_t *ctx);           // KBV_LOCK: any → LOCKED
void kbv_type_slot(kbv_ctx_t *ctx, uint8_t slot_idx);  // KBV_PASS_x: type slot if UNLOCKED

// Called every keydown/up when kbv_is_active() — captures input
void kbv_feed_char(kbv_ctx_t *ctx, char c);

// Returns true only for AUTHING and MENU (key capture states)
int  kbv_is_active(const kbv_ctx_t *ctx);

kbv_state_t kbv_get_state(const kbv_ctx_t *ctx);
void kbv_tick(kbv_ctx_t *ctx);           // idle timeout
void kbv_init(kbv_ctx_t *ctx, kbv_output_cb_t, kbv_type_cb_t, kbv_event_cb_t);
```

#### 11.3 QMK Integration

```c
// in keymap.c
#include "kbv.h"
#include "rng.h"

static kbv_ctx_t g_vault;

void keyboard_post_init_user(void) {
    rng_init();
    kbv_init(&g_vault, output_cb, type_cb, event_cb);
}

bool process_record_user(uint16_t keycode, keyrecord_t *record) {
    rng_feed_keypress();

    if (record->event.pressed) {
        switch (keycode) {
            case KBV_LOGIN:   kbv_login(&g_vault);      return false;
            case KBV_MENU:    kbv_enter_menu(&g_vault); return false;
            case KBV_LOCK:    kbv_lock(&g_vault);        return false;
            case KBV_PASS_1 ... KBV_PASS_5:
                kbv_type_slot(&g_vault, keycode - KBV_PASS_1);
                return false;
        }
    }

    if (kbv_is_active(&g_vault) && record->event.pressed) {
        char c = keycode_to_vault_char(keycode, get_mods() & MOD_MASK_SHIFT);
        if (c) kbv_feed_char(&g_vault, c);
        return false;
    }

    // ... normal key handling
}

void housekeeping_task_user(void) { kbv_tick(&g_vault); }
```

#### 11.3 PC Test Build

```makefile
# Makefile
CC = cc
CFLAGS = -Wall -Wextra -std=gnu11 -Iinclude -Ihxcrypt/include -DKBV_TEST

HXCRYPT_SRC = hxcrypt/src/blake2s.c hxcrypt/src/chacha20.c \
              hxcrypt/src/pbkdf2.c hxcrypt/src/hkdf.c hxcrypt/src/utils.c

test: test/test_vault.c src/kbv.c platform/kbv_platform_posix.c $(HXCRYPT_SRC)
	$(CC) $(CFLAGS) -o $@ $^
	./$@
```

---

### 12. Open Questions

| # | Question | Decision |
|---|---|---|
| 1 | Vault hotkeys | KBV_LOGIN / KBV_MENU / KBV_LOCK / KBV_PASS_1-5, positions TBD ✅ |
| 2 | Password entry confirmation — Enter key? | Enter key ✅ |
| 3 | Max master password length? | 64 bytes (`KBV_MAX_MASTER_LEN`) ✅ |
| 4 | Should master password change re-confirm via current password? | Not required (already authenticated) ✅ |
| 5 | Duress change — require master password confirmation? | Not required (already authenticated) ✅ |
| 6 | Should typing a slot auto-press Enter/Tab after the password? | No — user maintains control ✅ |

---

### 13. Not In Scope for now

- TOTP/HOTP
- Vault export/import
- Memory-hard KDF
- USB-serial management interface
- Multiple user profiles
- Configurable timeout
- Slot labels/metadata
