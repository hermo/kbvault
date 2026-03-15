# ADR 007 — Keycode-to-Character Mapping Extracted to kbv_charmap.h

**Date:** 2026-03-14
**Status:** Accepted

---

## Context

The function that converts QMK keycodes + shift state to ASCII characters for
vault password input (`keycode_to_vault_char`) lived exclusively inside
`keymap.c` in the QMK repo. This made it untestable on the host: the QMK build
environment (ARM toolchain, QMK headers) is not available during `make test`,
and pulling QMK headers into the kbvault test suite would create a hard
dependency on QMK.

Finnish ISO keyboard layout has a non-obvious mapping (e.g. `KC_MINS` → `+`
unshifted, `?` shifted; `KC_NUBS` → `<`/`>`). Any mistranslation silently
produces the wrong character at the vault input layer, leading to passwords
that cannot be re-entered. This class of bug is difficult to catch without
explicit tests.

## Alternatives considered

**Leave the mapping in keymap.c (status quo)**
- Simple; no new files.
- Untestable on the host — the QMK toolchain is not present during `make test`.
- Any layout bug only surfaces when running on hardware.

**Duplicate the mapping into a kbvault test helper**
- Testable, but the mapping exists in two places. They drift.
- The keymap still has the authoritative copy; the test copy is just noise.

**Extract to `include/kbv_charmap.h` (chosen)**
- Single source of truth: `kbv_charmap.h` is the only copy.
- Keymap includes it with `#define KBV_CHARMAP_HAVE_QMK` set, which suppresses
  the stub `#include <stdbool.h>` (QMK provides its own).
- Host tests include `kbv_charmap_keycodes.h` first, which provides numeric
  constants for the QMK keycode identifiers (HID usage values) and the
  `IS_QK_LAYER_TAP` / `IS_QK_MOD_TAP` range macros.
- No QMK types or headers enter the kbvault repo; no kbvault types enter QMK.

## Decision

Extract the mapping to `include/kbv_charmap.h` as a `static inline` function
named `kbv_keycode_to_char`. Add `include/kbv_charmap_keycodes.h` for
host-side keycode stubs. Update `keymap.c` to include `kbv_charmap.h` and
call `kbv_keycode_to_char`.

Add host-side tests covering:
- All 26 lowercase letters (unshifted)
- All 26 uppercase letters (shifted)
- Digits 0–9 (unshifted)
- Finnish shifted number row (`!`, `"`, `#`, `$`, `%`, `&`, `/`, `(`, `)`, `=`)
- All Finnish ISO special keys, both shifted and unshifted
- LT()/MT() composite keycode unwrapping
- Unknown keycodes returning 0
- Full end-to-end roundtrip: every mapped character → vault store → lock →
  re-init → unlock → type → byte-exact match

## Consequences

- The Finnish layout mapping is tested on every `make test` run, with no ARM
  toolchain required.
- Adding or changing a key mapping requires updating only `kbv_charmap.h` and
  the corresponding test case.
- The kbvault public API (`kbv.h`) and vault core (`kbv.c`) are unaffected.
- The QMK keymap is slightly smaller and has no duplicated logic.
- `kbv_charmap_keycodes.h` must be kept in sync with QMK's keycode enum if QMK
  ever renumbers its basic keycodes (this has not happened in QMK's history and
  is considered very unlikely, as the values are HID usage codes).
