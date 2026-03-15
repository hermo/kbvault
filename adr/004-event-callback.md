# ADR 004 — Event Callback for Vault Transitions

**Date:** 2026-03-14
**Status:** Accepted (pending implementation)

---

## Context

`keymap.c` (the QMK glue layer) needs to react to vault events — not just
query state — in order to drive RGB feedback animations (ADR 003). Examples:

- Flash red when authentication fails (AUTHING → LOCKED)
- Flash green when unlock succeeds (AUTHING → UNLOCKED)
- Flash blue when a hotkey is pressed on an empty slot

The current API gives no way to detect these transitions cleanly. The naive
workaround would be to compare `kbv_get_state()` before and after each call,
or to read `ctx.slot_flags` directly from `keymap.c`. Both are fragile and
create coupling between the glue layer and internal vault state.

This problem will recur every time a new event type is added.

## Alternatives considered

1. **Compare state before/after in process_record_user** — works for state
   transitions but can't distinguish "typed" from "empty slot" since
   `kbv_type_slot()` returns `void` and both leave state UNLOCKED.

2. **Return value from `kbv_feed_char` / `kbv_type_slot`** — could return an
   event enum, but these functions are called in many places and callers that
   don't care would need to ignore the return. Also doesn't help with events
   that happen inside multi-step menu flows.

3. **Poll-based event queue** — `kbv_poll_event()` returns the next pending
   event. Slightly more complex, requires a queue buffer in `kbv_ctx_t`.

4. **Event callback (chosen)** — a third callback `kbv_event_cb_t` registered
   at `kbv_init` time, alongside `output_cb` and `type_cb`. Called by `kbv.c`
   at every significant transition. Zero overhead, fits the existing design,
   no queue needed.

## Decision

Add a third callback to `kbv_ctx_t`:

```c
typedef enum {
    KBV_EVENT_UNLOCKED,      /* auth success: AUTHING -> UNLOCKED        */
    KBV_EVENT_AUTH_FAILED,   /* wrong password: AUTHING -> LOCKED        */
    KBV_EVENT_LOCKED,        /* vault locked (hotkey or idle timeout)    */
    KBV_EVENT_SLOT_TYPED,    /* password typed via kbv_type_slot()       */
    KBV_EVENT_SLOT_EMPTY,    /* kbv_type_slot() called on empty slot     */
    KBV_EVENT_ENTROPY_LOW,   /* slot write refused: entropy below threshold */
} kbv_event_t;

typedef void (*kbv_event_cb_t)(kbv_event_t event);
```

`kbv_init` gains a fourth parameter. `kbv.c` calls `ctx->event_cb(event)` at
each transition. `keymap.c` implements the handler and drives RGB from it —
no internal struct access needed.

`event_cb` may be NULL (no-op guard in kbv.c) for integrators that don't need
event feedback.

## Consequences

- `keymap.c` never needs to access `ctx` fields directly for event detection.
- All five RGB feedback beads (kbvault-ca3, kbvault-yh3, kbvault-okx,
  kbvault-jsd, kbvault-kws) can be implemented cleanly in the event handler.
- `kbv_init` signature changes — a one-time breaking change before publication.
- Tests must pass `NULL` or a test event handler to `kbv_init`.
- The event callback is the correct integration point for any future
  notification need (e.g. idle-timeout warning, entropy progress).
