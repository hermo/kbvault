# KBVault

A hardware password manager embedded directly in QMK keyboard firmware.
Passwords are encrypted and stored in MCU flash — no host software, no USB
data channel, no companion app. Unlocking types your password as HID
keystrokes, indistinguishable from manual typing.

Developed for a Keychron Q3 Max (STM32F401xC, no hardware TRNG). Should be
portable to any MCU with ~1 KB of contiguous, independently-erasable NOR flash
and a reasonably fast ADC.

---

## Security notice

KBVault was built as a personal challenge: how far can you get toward a
reasonably secure password manager embedded entirely in a keyboard? Significant
effort has gone into the design — encrypt-then-MAC, hardware-bound keys, duress
wipe, entropy accounting, a faithful NOR flash mock for testing, and a thorough
test suite. The project takes security seriously within its scope.

That said, **use it at your own risk.** The decision to trust it with real
credentials is yours alone. The author would not use this in a professional or
high-stakes setting.

The most honest reason for caution: **this is custom cryptography**. The
algorithms themselves (ChaCha20, BLAKE2s, PBKDF2, HKDF) are standard and
well-regarded. But the way they are composed, the entropy collection, the key
derivation pipeline, and the flash layout have never been audited by a
cryptographer. Rolling your own crypto is discouraged not because the
primitives are wrong, but because the subtle ways they can be misused are
often too esoteric to notice without deep specialist knowledge — and too
consequential to get wrong.

---

## Security model

**Cipher suite:** ChaCha20 (encryption) + keyed BLAKE2s (authentication tag).
Encrypt-then-MAC. See [ADR 001](adr/001-cipher-suite.md) for rationale.

**Key derivation:** PBKDF2(master\_password, salt, iterations) → HKDF →
per-slot enc\_key + mac\_key. The salt and a 32-byte pepper are stored in the
vault header in flash. Keys are bound to the MCU's unique device ID (UID) so a
flash dump is useless without the original hardware.

**Duress password:** A second password wipes the vault (erases flash,
zeroes SRAM) and returns to LOCKED. This is a convenience feature, not a security
control (see spec §2). The BLAKE2s verification tag for the duress key is stored
alongside the normal verify tag so the MCU cannot distinguish the two without
the correct password.

**Nonce:** 12 bytes from the CSPRNG, generated fresh on every slot write.
The boot-time ADC health estimate must reach 256 bits before any write is accepted; the DRBG is reseeded from keystroke timing.

**Lock on idle:** `kbv_tick()` checks an idle timer; the vault auto-locks
after a configurable timeout. All key material in SRAM is zeroed on lock.

**Brute-force throttling:** After a failed password attempt, `kbv_login()` is
blocked for an exponentially increasing lockout period (1 s, 2 s, 4 s, … up
to 30 s cap). Successful authentication resets the counter. The lockout is
in-SRAM only and resets on power cycle.

**No TRNG required:** entropy is accumulated from ADC noise (internal temp
sensor + Vrefint), DWT cycle-counter jitter, and keystroke timing intervals.
See [ADR 002](adr/002-entropy-sources.md) and `include/rng.h`.

---

## Flash layout

All vault data fits in 990 bytes, occupying one 16 KB NOR flash sector.

| Region      | Offset | Size       | Contents                                    |
|-------------|--------|------------|---------------------------------------------|
| Header      | 0x000  | 120 bytes  | magic, version, slot\_flags, pepper, salt, verify\_tag, duress\_tag |
| Slot 0      | 0x078  | 174 bytes  | nonce (12) + ctlen (1) + ciphertext (128) + MAC tag (32) |
| Slot 1      | 0x126  | 174 bytes  | (same layout)                               |
| Slot 2      | 0x1D4  | 174 bytes  |                                             |
| Slot 3      | 0x282  | 174 bytes  |                                             |
| Slot 4      | 0x330  | 174 bytes  |                                             |
| **Total**   |        | **990 B**  |                                             |

`slot_flags` uses inverted NOR semantics: 0xFF = all empty, clearing a bit
marks a slot occupied. This allows individual slots to be marked in-use
without an erase cycle.

---

## State machine

```
LOCKED ──[kbv_login]──► AUTHING ──[correct password]──► UNLOCKED ──[kbv_enter_menu]──► MENU
                                 └──[wrong password]──► LOCKED          │                 │
                                                                   [kbv_lock]        [kbv_lock]
                                                                   [idle timeout]    [idle timeout]
                                                                         ▼                 ▼
                                                                       LOCKED           LOCKED
```

- **LOCKED** — keyboard operates normally; vault keys zeroed.
- **AUTHING** — vault captures keystrokes for password input; RGB pulses amber.
- **UNLOCKED** — transparent pass-through; vault keys live in SRAM; green LED.
- **MENU** — vault captures keystrokes for management commands; blue LED.

---

## Requirements

- MCU: STM32F401xC or compatible (tested), or any Cortex-M with ~1 KB of
  erasable NOR flash and an ADC with internal channels.
- QMK firmware (any recent version with `rgb_matrix` and `send_string`).
- [hxcrypt](https://github.com/hermo/hxcrypt) — provides ChaCha20, BLAKE2s,
  PBKDF2, HKDF, and the ChaCha20-BLAKE2s DRBG (CSPRNG). Added as a submodule.

---

## Integration overview

Full annotated example: [`examples/qmk/keymap_example.c`](examples/qmk/keymap_example.c)

### 1. Add hxcrypt as a submodule

```sh
git submodule add <hxcrypt-url> hxcrypt
```

### 2. Add sources to your keymap's `rules.mk`

```makefile
SRC += $(KEYBOARD_PATH_1)/../../path/to/kbvault/src/kbv.c \
       $(KEYBOARD_PATH_1)/../../path/to/kbvault/src/rng.c \
       $(KEYBOARD_PATH_1)/../../path/to/kbvault/platform/kbv_platform_stm32.c \
       $(KEYBOARD_PATH_1)/../../path/to/kbvault/hxcrypt/chacha20.c \
       $(KEYBOARD_PATH_1)/../../path/to/kbvault/hxcrypt/blake2s.c \
       $(KEYBOARD_PATH_1)/../../path/to/kbvault/hxcrypt/pbkdf2.c \
       $(KEYBOARD_PATH_1)/../../path/to/kbvault/hxcrypt/hkdf.c \
       $(KEYBOARD_PATH_1)/../../path/to/kbvault/hxcrypt/csprng.c

VPATH += $(KEYBOARD_PATH_1)/../../path/to/kbvault/include \
         $(KEYBOARD_PATH_1)/../../path/to/kbvault/hxcrypt
```

### 3. Implement `kbv_platform.h` for your MCU

Six functions to implement (see `include/kbv_platform.h`):

| Function                  | Purpose                                      |
|---------------------------|----------------------------------------------|
| `kbv_plat_get_uid`        | Read 12-byte device UID                      |
| `kbv_plat_random`         | CSPRNG bytes (calls `rng_bytes()` on STM32)  |
| `kbv_plat_flash_read`     | Read from vault flash sector                 |
| `kbv_plat_flash_write`    | Write to vault flash sector (NOR: 1→0 only)  |
| `kbv_plat_flash_erase`    | Erase vault flash sector (sets all bits to 1)|
| `kbv_plat_time_ms`        | Millisecond timer for idle timeout           |
| `kbv_plat_entropy_bits`   | Accumulated entropy estimate (calls `rng_entropy_bits()`) |

The STM32F401 implementation is in `platform/kbv_platform_stm32.c`.
A NOR-faithful POSIX mock for host-side testing is in
`platform/kbv_platform_posix.c`.

### 4. Wire up the key-to-character mapping

`include/kbv_charmap.h` provides `kbv_keycode_to_char(keycode, shifted)` — a
`static inline` function that maps QMK keycodes + shift state to ASCII
characters for vault password input. It is the single source of truth for your
keyboard's layout mapping and is tested on the host by `make test`.

In your `keymap.c`, include it after your QMK headers:

```c
#define KBV_CHARMAP_HAVE_QMK   /* suppress stdbool.h; QMK provides it */
#include "kbv_charmap.h"
```

The file ships with a Finnish ISO QWERTY mapping. Adapt the switch tables for
your layout. `include/kbv_charmap_keycodes.h` provides keycode stubs for
host-side testing — keep it in sync with your layout file.

### 5. Wire up QMK callbacks

In your `keymap.c`:

```c
static kbv_ctx_t g_vault;

void keyboard_post_init_user(void) {
    rng_init();   /* must be before kbv_init */
    kbv_init(&g_vault, output_cb, type_cb, event_cb);
}

bool process_record_user(uint16_t keycode, keyrecord_t *record) {
    rng_feed_keypress();
    /* handle KBV_LOGIN, KBV_MENU, KBV_LOCK, KBV_PASS_1..5 */
    /* route keypresses to kbv_feed_char when kbv_is_active() */
    ...
}

bool rgb_matrix_indicators_user(void) {
    /* drive LED color from kbv_get_state() or event callback */
    ...
}

void housekeeping_task_user(void) {
    kbv_tick(&g_vault);
}
```

See `examples/qmk/keymap_example.c` for the full annotated version.

---

## Entropy note

`rng.c` and `kbv_platform_stm32.c` are STM32F401-specific. They use:

- ADC channels CH16 (internal temperature sensor) and CH17 (Vrefint) for
  boot-time entropy (~11 ms, 512 samples, ~2 bits/sample).
- DWT `CYCCNT` for cycle-counter jitter between operations.
- Keystroke timing deltas fed from `process_record_user`.

To port to a different MCU, replace `rng.c` and the `kbv_platform_*.c`
implementation. The vault core (`src/kbv.c`) has no MCU dependencies.

---

## Flash read protection (RDP)

STM32F4 Read Protection Level 1 blocks flash readout via SWD/JTAG. A flash
dump of the MCU produces nothing useful — firmware and vault ciphertext are
inaccessible without the original hardware. DFU flashing via USB is unaffected.

Tool required: [STM32CubeProgrammer](https://www.st.com/en/development-tools/stm32cubeprog.html)

**Verify current RDP level** (keyboard in DFU mode):
```sh
STM32_Programmer_CLI -c port=USB1 -ob displ
# Look for: RDP : 0xAA (Level 0) or any other value (Level 1)
```

**Set RDP1** (keyboard in DFU mode):
```sh
STM32_Programmer_CLI -c port=USB1 -ob RDP=0xBB
```

> **Important:** RDP1 blocks the DFU page-erase command. `dfu-util` (used by
> `qmk flash`) will fail with `ERASE_PAGE not correctly executed`. To flash new
> firmware you must first unlock (mass erase), flash, then re-lock.

**Firmware update workflow when RDP1 is active:**

1. Use **hardware DFU** (see below), then run read-unprotect (takes a while, triggers mass erase):
   ```sh
   STM32_Programmer_CLI -c port=USB1 -rdu
   ```
   > `-ob RDP=0xAA` does not work reliably from RDP1. Use `-rdu`. Normal ESC+plug
   > DFU entry may stop working mid-command — hardware DFU always works.
2. Flash firmware (normal DFU mode is fine after unlock):
   ```sh
   qmk flash
   ```
3. Put keyboard in DFU mode, then re-lock:
   ```sh
   STM32_Programmer_CLI -c port=USB1 -ob RDP=0xBB
   ```
4. Unplug, replug to boot. Re-enter vault passwords.

A `Makefile` with `make unlock`, `make flash`, `make lock`, and `make deploy`
targets is provided in the QMK keymap directory to automate this workflow.

**Hardware DFU method** (when normal ESC+plug DFU fails):

1. Remove the space bar keycap
2. Hold the PCB reset button (left side of space bar switch)
3. Plug in USB cable
4. Hold for 2 seconds, then release

This bypasses all firmware and option byte state, accessing the STM32 ROM
bootloader directly. It cannot be blocked by RDP or corrupted firmware.

> **Never set RDP=0xCC (Level 2).** It is permanent and irreversible — no
> recovery, no DFU, no mass erase escape.

---

## Building and testing

The test suite runs entirely on the host via a POSIX platform mock:

```sh
make test
```

The vault core, hxcrypt, and platform mock are compiled with the system C
compiler (no ARM toolchain needed for tests).

## License

GPL-2.0-or-later. See [LICENSE](LICENSE) for the full text.
