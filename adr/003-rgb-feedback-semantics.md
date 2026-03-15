# ADR 003 — RGB Feedback Semantics

**Date:** 2026-03-14
**Status:** Accepted

---

## Context

The keyboard has a full per-key RGB matrix. KBVault needs to communicate vault
state and events to the user without any display. Two distinct categories of
feedback are needed:

- **Persistent state indicators** — always-on signal of the current vault state
  (e.g. "vault is open right now")
- **Transient event flashes** — brief full-keyboard animations triggered by a
  specific event (e.g. "wrong password just entered")

Mixing these carelessly leads to confusing UI: a persistent indicator and a
transient flash need different mechanisms and must not interfere.

## Decision

### Color semantics

| Color  | Meaning                                      |
|--------|----------------------------------------------|
| Amber  | Actively entering password (AUTHING state)   |
| Green  | Vault unlocked / positive feedback           |
| Red    | Failure / vault being locked                 |
| Blue   | In management menu / empty slot attempted    |

### Persistent state (always-on in `rgb_matrix_indicators_user`)

| State      | Effect                                              |
|------------|-----------------------------------------------------|
| LOCKED     | No override — normal RGB lighting                   |
| AUTHING    | Pulsing amber on all keys (breathing animation)     |
| UNLOCKED   | Subtle green on Caps Lock LED (index 51)            |
| MENU       | Blue on Caps Lock LED (index 51)                    |

### Transient event flashes (override for ~300–500 ms, then revert)

| Event                              | Flash              | Duration |
|------------------------------------|--------------------|----------|
| Unlock success (AUTHING → UNLOCKED)| All keys green     | 300 ms   |
| KBV_LOGIN pressed while UNLOCKED   | All keys green     | 300 ms   |
| Unlock fail (wrong password)       | All keys red       | 300 ms   |
| KBV_PASS_x on empty slot           | All keys blue      | 300 ms   |
| kbv_lock() called                  | Fade green → red   | 500 ms   |

Transient flashes are implemented via a `g_flash_until` timestamp and
`g_flash_r/g/b` color in `keymap.c`. In `rgb_matrix_indicators_user`, if
`timer_read32() < g_flash_until`, the flash color overrides all other logic.

### Implementation note

`kbv_feed_char()` and `kbv_type_slot()` need to return signals that let
`keymap.c` detect events (fail, empty-slot). Options evaluated:
- **Return value from `kbv_feed_char`** — cleanest; add a `KBV_EVENT_*` enum
  or just detect state change (state before vs. after).
- **`kbv_last_event()` query** — adds API surface for no gain.
- **Check `slot_flags` before calling `kbv_type_slot`** — works for empty-slot
  detection without changing `kbv.h`.

Chosen: compare `kbv_get_state()` before/after for auth events; check
`slot_flags` directly for empty-slot detection. No new API needed.

## Consequences

- `rgb_matrix_indicators_user` must handle both the persistent and transient
  layers, with the transient taking priority.
- Flash state (`g_flash_until`, color) lives entirely in `keymap.c` — no
  changes to `kbv.c` or `kbv.h` required.
- The Caps Lock LED (index 51) is used as the always-on indicator. This index
  is specific to the Keychron Q3 Max ISO layout and will need adjustment if the
  keymap is ported.
