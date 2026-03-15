# RNG Specification for STM32F401 / QMK

## Hardware Context

- **MCU**: STM32F401xC (confirmed via DFU fingerprint: `ver=2200`, flash layout `04×16K + 64K + 128K`, OTP at `0x1FFF7800`)
- **Core**: ARM Cortex-M4, 84 MHz system clock
- **No hardware TRNG** — the STM32F401 does not have the RNG peripheral present on F405/F407 and L4xx
- **Framework**: ChibiOS 20.x (via QMK), direct CMSIS register access is available alongside it

The CSPRNG must be seeded from software entropy sources before any cryptographic material is generated.

---

## Entropy Sources

Three independent sources must be combined. No single source is sufficient alone.

### Source 1: ADC Internal Channel Noise

The STM32F401 ADC has inherent thermal and shot noise in its LSBs. The internal temperature sensor (CH16) and internal voltage reference Vrefint (CH17) both exhibit this noise and are always available without any external pins.

**Quality**: ~1–2 bits of real entropy per sample from internal channels. This is the only entropy source available before user interaction, making it critical for seeding at boot.

**Implementation requirements** (all from STM32F4 Reference Manual RM0368):

```c
// Enable ADC1 clock on APB2
RCC->APB2ENR |= RCC_APB2ENR_ADC1EN;

// Enable internal temperature sensor and Vrefint.
// TSVREFE bit in ADC Common Control Register (ADC->CCR).
// Must be set before sampling CH16 or CH17.
ADC->CCR |= ADC_CCR_TSVREFE;

// Power on ADC1. Single conversion mode, 12-bit right-aligned (defaults).
ADC1->CR1 = 0;
ADC1->CR2 = ADC_CR2_ADON;

// Wait ≥10 µs for ADC stabilisation (RM0368 §11.3.6).
// At 84 MHz, 1000 NOPs ≈ 12 µs.
for (volatile uint32_t i = 0; i < 1000; i++) __asm__ volatile("nop");
```

**Per-sample procedure:**

```c
// Channel selection. Set FIRST_SQ[4:0] in SQR3 to the channel number.
ADC1->SQR3 = channel; // 16 for temp sensor, 17 for Vrefint

// Sample time. RM0368 §11.3.3 mandates minimum 10 µs for CH16/CH17.
// At ADC clock of 21 MHz (APB2=84 MHz / prescaler 4), 480 cycles = 22.9 µs.
// SMPR1 bits [20:18] control CH16, bits [23:21] control CH17.
// 0b111 = 480 cycles.
if (channel == 16) ADC1->SMPR1 = (7U << 18);
if (channel == 17) ADC1->SMPR1 = (7U << 21);

ADC1->SR = 0;                       // Clear status flags
ADC1->CR2 |= ADC_CR2_SWSTART;      // Start software-triggered conversion
while (!(ADC1->SR & ADC_SR_EOC));   // Spin until end-of-conversion

uint16_t sample = (uint16_t)(ADC1->DR & 0xFFF); // 12-bit result
uint8_t noise = (uint8_t)(sample & 0x03);         // Use bottom 2 LSBs
```

**Teardown after use** (restore state to not interfere with ChibiOS ADC driver if it is used later):

```c
ADC1->CR2 = 0;                              // Power off ADC1
ADC->CCR &= ~ADC_CCR_TSVREFE;             // Disable internal channels
RCC->APB2ENR &= ~RCC_APB2ENR_ADC1EN;     // Gate clock
```

**Collection strategy**: Alternate CH16 and CH17 samples to reduce inter-sample correlation. Collect 512 samples total (yielding 1024 bits of raw noise), XOR into a 64-byte entropy pool via `hx_csprng_stir()`. The pool is conditioned with BLAKE2s (double-hash) at seed time. This takes roughly 512 × 480 ADC cycles ≈ 11 ms at 21 MHz ADC clock — acceptable at boot.

---

### Source 2: DWT Cycle Counter Jitter

The Cortex-M4 Debug Watchpoint and Trace (DWT) unit contains a free-running 32-bit cycle counter (`DWT->CYCCNT`) that increments at the core clock (84 MHz). The counter itself is deterministic, but reading it at interrupt boundaries captures timing jitter between hardware events and the CPU, providing real entropy.

**Enable sequence** (must be done once at init, before use):

```c
CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;  // Enable trace unit
DWT->CTRL        |= DWT_CTRL_CYCCNTENA_Msk;       // Enable cycle counter
DWT->CYCCNT       = 0;                             // Reset counter
```

**Headers required**: `#include "core_cm4.h"` (included transitively via ChibiOS `ch.h`).

**Entropy extraction**: The low bits of `DWT->CYCCNT` read immediately after an interrupt returns to the task level contain real jitter. On a USB full-speed device (1 ms SOF period) and a 1 ms SysTick, the phase difference between these two 1 ms clocks is not phase-locked and varies. The low 4–8 bits of `DWT->CYCCNT` sampled at a key scan or USB callback are usable.

Do not rely on DWT alone for seeding. Use it to continuously stir the entropy pool.

---

### Source 3: Keystroke Timing

Human keystroke timing at DWT cycle resolution is an excellent entropy source because human motor variability produces genuine randomness at the microsecond scale.

**Per-keypress entropy extraction**:

```c
static uint32_t last_key_cycles = 0;

void rng_feed_keypress(void) {
    uint32_t now = DWT->CYCCNT;
    uint32_t delta = now - last_key_cycles;
    last_key_cycles = now;
    // Feed all 32 bits of delta into the pool.
    // Even though not all bits are independent, the mixing
    // function will condition them.
    entropy_pool_stir((uint8_t *)&delta, 4);
}
```

Call `rng_feed_keypress()` from `process_record_user()` on every key event (press and release). By the time the user has typed even a short master password, the pool will have absorbed hundreds of genuine random bits.

**Critical note**: The PBKDF2 salt is generated at first EEPROM initialisation, which happens at boot before any keypresses. The ADC source (Source 1) must therefore provide sufficient entropy on its own for the salt. Keystroke entropy enriches subsequent IV generation.

---

## Entropy Pool

The entropy pool is managed by hxcrypt's `hx_csprng_t`. It is a 64-byte (512-bit) XOR accumulator maintained in static RAM. Raw entropy is added via `hx_csprng_stir()` and conditioned with BLAKE2s at seed time. The pool is never directly output — all output goes through the ChaCha20 DRBG.

### Pool Operations

**Stir (add entropy)** — `hx_csprng_stir(&ctx, data, len)`:

XOR new data into the pool at a wrapping cursor. Increments a `bytes_stirred` counter (saturating, used for the seed threshold).

**Seed (condition and extract)** — `hx_csprng_seed(&ctx)`:

Gates on `bytes_stirred >= 256`. Conditions the pool with BLAKE2s double-hash:
- `h1 = BLAKE2s(pool)` → becomes the ChaCha20 key
- `h2 = BLAKE2s(h1)` → overwrites pool left half (backtracking resistance)
- Nonce is derived from pool second half keyed with h1
- Pool right half zeroed, cursor and counter reset

**Minimum entropy threshold**: Do not produce CSPRNG output until at least 256 bytes have been stirred. Given ADC seeding alone (512 samples × 5 bytes = 2560 bytes stirred), this threshold is met by 10x after boot-time ADC collection, before any keypresses.

---

## CSPRNG: ChaCha20-BLAKE2s DRBG (hxcrypt)

The DRBG is implemented entirely in hxcrypt (`hx_csprng_t`). ChaCha20 is fast on 32-bit ARM (no lookup tables, only add/rotate/XOR), compact, and well-studied. It is used in Linux, FreeBSD, TLS 1.3, and WireGuard.

### Seeding

`hx_csprng_seed()` derives the ChaCha20 key and nonce from the entropy pool using BLAKE2s (see Entropy Pool section above). The caller (rng.c) stirs DWT and `timer_read32()` into the pool before calling seed, ensuring timing data contributes to nonce uniqueness.

### Output Generation

`hx_csprng_bytes()` produces ChaCha20 keystream. Output is buffered in 64-byte blocks.

### Forward Secrecy (Key Erasure)

After every 256 bytes of output (`HX_CSPRNG_REKEY_BYTES`), the DRBG re-keys: it generates 32 bytes of keystream and uses them as the new key, then invalidates the buffer. This ensures that compromising the current DRBG state does not reveal past output.

---

## Initialisation Sequence

`rng_init()` (called from `keyboard_post_init_user()`, before `kbv_init()`):

1. Init hxcrypt CSPRNG: `hx_csprng_init(&g_rng)`
2. Enable DWT cycle counter
3. Collect ADC entropy (~11 ms, blocking): 512 samples alternating CH16/CH17, stir 2 LSBs (1 byte) + DWT CYCCNT (4 bytes) per sample → 2560 bytes stirred
4. Stir `timer_read32()` + DWT for nonce uniqueness
5. Call `hx_csprng_seed()` — if it fails (insufficient entropy), reset `g_entropy_bits` to 0 so the entropy guard in `write_slot()` blocks any slot writes

---

## Ongoing Entropy Accumulation

### From Keystrokes

In `process_record_user()`, unconditionally (before any other processing):

```c
rng_feed_keypress(); // feeds DWT delta into pool
```

This gradually accumulates entropy after boot. At approximately 1 bit per keypress (conservative), after the user types a 10-character master password, ~80 bits of keystroke entropy are added. IV generation (which happens when adding a password) benefits from this.

### Periodic Reseed

When the pool's `bits_added` accumulates ≥ 256 bits of new entropy after the last seed, optionally call `rng_seed()` again to reseed the DRBG. For a keyboard use case this is not critical since total output volume is small.

---

## Public API

```c
// Initialise: collect ADC entropy, seed CSPRNG.
// Must be called from keyboard_post_init_user() before crypto layer init.
void rng_init(void);

// Feed entropy from a key event. Call from process_record_user().
void rng_feed_keypress(void);

// Generate len cryptographically secure random bytes into buf.
// Blocks briefly on first call if not yet seeded (should not happen if
// rng_init() was called). len must be ≤ 255 per call for safety; call
// again for more.
void rng_bytes(uint8_t *out, size_t len);
```

---

## File Layout

```
rng.h    — public API (rng_init, rng_feed_keypress, rng_bytes, rng_entropy_bits)
rng.c    — ADC sampling, DWT helpers, entropy feeding into hxcrypt CSPRNG
```

Dependencies:
- `hxcrypt` — provides `hx_csprng_t` (ChaCha20-BLAKE2s DRBG), `hx_csprng_stir/seed/bytes`
- ChibiOS CMSIS headers — for `DWT->CYCCNT`, `ADC1`, `RCC`, `CoreDebug`
- QMK `timer.h` — for `timer_read32()`

---

## Security Properties

| Property | Status |
|---|---|
| Entropy source independence | ✓ ADC + DWT jitter + keystroke timing are physically independent |
| Pre-output seeding | ✓ ADC seeding at boot ensures salt/IV generation has real entropy |
| Forward secrecy | ✓ Key erasure after every 256 bytes of output |
| Backtracking resistance | ✓ Pool uses BLAKE2s double-hash extract; DRBG output can't reveal pool state |
| Predictability | ✓ ChaCha20 is computationally indistinguishable from random given unknown key |
| Determinism at boot | ✗ Timer alone would be deterministic; ADC seeding prevents this |

## Known Limitations

- ADC entropy quality is lower than a hardware TRNG. The implementation mitigates this by collecting 512 samples (≫ the 256-byte stir threshold) and using BLAKE2s as a conditioner.
- The DWT counter resets to 0 at power-on; cross-boot correlation is zero because the DRBG key changes every boot.
- If the keyboard is powered on and a password is added *immediately* without any keystrokes (unlikely in practice), the IV will have only ADC-derived entropy. This is still cryptographically adequate given the 512-sample ADC collection.
- `len > 32` in a single `rng_bytes()` call requires the DRBG to consume more than one buffered block. This is fine; just be aware that requests much larger than 64 bytes are atypical for this use case (salt = 16 bytes, IV = 16 bytes).
