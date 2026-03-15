# ADR 005 — Raw Flash vs Emulated EEPROM for Vault Storage

**Date:** 2026-03-14
**Status:** Accepted

---

## Context

STM32F401xC flash is partitioned by the QMK linker script into three regions:
- `flash0` (sector 0, 16 KB) — init code
- `flash1` (sector 1, 16 KB) — QMK emulated EEPROM
- `flash2` (sectors 2–4, 96 KB) — firmware code
- sector 5 (128 KB) — vault (raw flash)

QMK's emulated EEPROM was available as an alternative storage mechanism.
The question was whether the vault's 990-byte binary blob should use the
EEPROM abstraction or manage its own sector directly.

## Alternatives considered

**Emulated EEPROM (flash1)**
- Implements wear levelling: appends small records forward through the sector,
  erases only when full. Extends effective write endurance well beyond the
  10,000 raw erase cycles rated for STM32F4 flash.
- Designed for small, frequently-mutated key-value settings (RGB mode, current
  layer, etc.). Layering a 990-byte binary blob on top is an impedance mismatch.
- Sector 1 is already in use by QMK for its own settings — sharing it is fragile.
- **Security problem**: wear levelling deliberately retains old data in flash
  until the sector fills and is erased. Previous ciphertext versions would
  linger in flash indefinitely. The vault design requires that erase is
  explicit and complete — old ciphertext must not survive a delete or clear.

**Raw flash (sector 5, chosen)**
- Full control over the 990-byte binary layout with no API impedance.
- Erase-before-write is explicit: old ciphertext is definitively gone after
  erase. This is a deliberate security property, incompatible with wear
  levelling.
- NOR flash semantics (1→0 writes, erase to 0xFF) are modelled exactly in
  the platform abstraction and enforced by the POSIX test mock.
- Wear cycle concern is negligible: password changes and slot edits are rare
  (order of tens per year at most). At 10,000 erase cycles the sector would
  outlast the keyboard hardware by decades.

## Decision

Use raw flash (sector 5) with explicit erase-before-write. Do not use
emulated EEPROM for vault data.

The only future scenario where emulated EEPROM would be appropriate is a
frequently-updated metadata field (e.g. failed-unlock attempt counter updated
on every auth attempt). Such a field should go in a separate small EEPROM
record, not in the vault sector. This is not currently implemented.

## Consequences

- Vault storage is fully owned by kbvault, independent of QMK's EEPROM layer.
- The platform abstraction (`kbv_platform.h`) remains the correct porting seam:
  any MCU port needs only to implement the six platform functions.
- The NOR-faithful POSIX mock and test suite correctly model the real hardware
  constraints of raw flash storage.
- Sector 5 is reserved in the linker script; firmware is capped at sectors 0–4
  (112 KB max) to prevent silent overlap.
