# ADR 006 — PBKDF2 Round Count: 4096 and Accepted Brute-Force Risk

**Date:** 2026-03-14
**Status:** Accepted

---

## Context

KBVault derives the vault key using PBKDF2-BLAKE2s with a configurable
iteration count, currently 4096. A security review flagged this as potentially
low: an attacker with a flash dump and a GPU could enumerate candidate
passwords faster than with a standardized PBKDF2-HMAC-SHA256 implementation
at the same count, since no public hashcat module exists for PBKDF2-BLAKE2s
and one would need to be written.

The question was whether to raise the count (e.g. 65536) to increase brute-force
cost, or keep it at 4096.

## Alternatives considered

**Higher round count (e.g. 65536)**
- Increases GPU attack cost proportionally.
- Also increases unlock latency proportionally. At 84 MHz (STM32F401), the
  current 4096-round PBKDF2-BLAKE2s call already takes a perceptible fraction
  of a second. 16× more rounds means ~16× longer unlock. On an embedded MCU
  with no hardware crypto, this is a meaningful UX regression.

**4096 rounds (chosen)**
- Unlock latency remains acceptable.
- Cost is partially compensated by the non-standard pipeline (see below).

## Decision

Keep the round count at 4096. Accept the theoretical brute-force risk for the
following compounding reasons:

1. **Non-standard pipeline requires custom tooling.** No hashcat module exists
   for PBKDF2-BLAKE2s. An attacker cannot simply point existing tooling at a
   flash dump; they must first write and validate a custom GPU kernel. This
   raises the practical bar significantly beyond what the raw round count
   implies.

2. **High-entropy master passwords.** The master password is long and
   high-entropy. Password strength is the dominant factor in brute-force
   resistance — round count is a multiplier on a large base. Guessing
   a high-entropy password is infeasible regardless of GPU speed.

3. **Unlock time provides inherent rate limiting.** The KDF latency on the MCU
   already makes online attacks slow enough that no additional lockout counter
   is warranted (see kbvault-u7t, closed WONTFIX).

4. **Practical attack is rubber-hose, not crypto.** Any adversary with physical
   access to the keyboard can compel disclosure. Significantly increasing
   unlock latency degrades legitimate usability without meaningfully changing
   the real-world threat.

5. **UID binding limits offline utility.** The KDF includes a hardware-bound
   salt derived from the 96-bit STM32 unique device ID, which is not readable
   via SWD at RDP1. An attacker with only the flash dump cannot construct the
   correct `bound_salt` without also recovering the UID — reducing the value
   of an offline attack further.

## Consequences

- Unlock latency remains acceptable on the STM32F401 at 84 MHz.
- A sophisticated adversary (nation-state or equivalent) with both the flash
  dump and the UID could mount a brute-force campaign, but such an adversary
  is explicitly out of scope (see spec.md §2 threat model).
- The round count is defined as a compile-time constant. Raising it in the
  future for a faster MCU port is a one-line change.
- This decision is revisited automatically if kbvault is ported to an MCU with
  hardware KDF acceleration or a hardware TRNG that enables a memory-hard KDF.
