#pragma once
#include <stdint.h>
#include <stddef.h>

/*
 * Entropy collection and CSPRNG for STM32F401xC.
 *
 * Three entropy sources:
 *   1. ADC internal channels (CH16 temp sensor + CH17 Vrefint) — collected at boot
 *   2. DWT cycle counter jitter — stirred continuously
 *   3. Keystroke timing — stirred per keypress, DRBG reseeded every 64 presses
 *
 * The conditioned entropy feeds hxcrypt's ChaCha20-BLAKE2s DRBG (hx_csprng_t).
 * kbv_plat_random() in kbv_platform_stm32.c calls rng_bytes().
 */

/*
 * Initialise entropy collection and seed the CSPRNG.
 * Collects ~11ms of ADC noise (512 samples, CH16+CH17 alternating).
 * Must be called from keyboard_post_init_user() before kbv_init().
 */
void rng_init(void);

/*
 * Feed keystroke timing entropy into the pool.
 * Call from process_record_user() on every key event (press and release).
 * Uses DWT->CYCCNT delta between keypresses.
 */
void rng_feed_keypress(void);

/*
 * Generate cryptographically secure random bytes.
 * CSPRNG must be seeded (rng_init called). Asserts/hangs if not.
 */
void rng_bytes(uint8_t *out, size_t len);

/*
 * Return the boot-time entropy estimate in bits: the number of observed
 * sample-to-sample ADC changes (0 if the ADC is stuck).  Keypress timing
 * reseeds the DRBG but is not credited.  Used by kbv_plat_entropy_bits().
 */
uint16_t rng_entropy_bits(void);
