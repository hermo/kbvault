# ADR 002 — Entropy Sources on STM32F401

**Date:** 2026-03-14
**Status:** Accepted

---

## Context

The CSPRNG (hxcrypt's ChaCha20-BLAKE2s DRBG) must be seeded with real entropy
before generating nonces, peppers, and salts. On most STM32 lines (F405, F407,
L4xx) there is a hardware TRNG peripheral. The STM32F401xC does not have one.

## Decision

Use three entropy sources, combined via `hx_csprng_stir()` into the DRBG:

1. **ADC internal channels** (CH16 = temperature sensor, CH17 = Vrefint).
   512 samples alternating between channels at boot (~11 ms). The two LSBs
   of each 12-bit reading carry thermal/shot noise — roughly 1–2 bits of real
   entropy per sample, yielding ~512–1024 bits from this pass alone.

2. **DWT cycle counter jitter.** The ARM DWT `CYCCNT` register runs at 84 MHz.
   It is sampled after each ADC conversion and stirred in, adding timing jitter
   that is difficult to predict or reproduce.

3. **Keystroke timing.** `rng_feed_keypress()` is called on every key event.
   It stirs the delta of `DWT->CYCCNT` since the last keypress. Human typing
   is strongly non-deterministic.

The DRBG is seeded once at boot after ADC collection, and re-stirred on each
keypress. `rng_entropy_bits()` tracks accumulated entropy (saturation counter).

A minimum entropy threshold (`KBV_MIN_ENTROPY_BITS = 256`) is enforced before
any nonce-generating operation (slot write). The menu reports current entropy
via the `i` command.

## Consequences

- ADC-based entropy is slower than a hardware TRNG (~11 ms at boot) but
  perfectly acceptable for this use case.
- If ChibiOS/QMK initializes ADC1 for another purpose before `rng_init()`,
  direct register access in `adc_setup()` may conflict. This is a known risk;
  `rng_init()` must be the first thing called in `keyboard_post_init_user()`.
- The entropy estimate is conservative and approximate. We do not claim
  cryptographic-grade entropy accounting — the threshold is a sanity check,
  not a guarantee.
- On POSIX (test build), `kbv_plat_entropy_bits()` always returns `0xFFFF`
  since `/dev/urandom` is assumed always seeded.
