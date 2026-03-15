#pragma once
#include <stdint.h>
#include <stddef.h>

void     kbv_plat_get_uid(uint8_t out[12]);

/*
 * kbv_plat_random() — generate cryptographically secure random bytes.
 *
 * CONTRACT (implementers must follow this exactly):
 *   - This function MUST always produce cryptographically random output.
 *   - The implementation is responsible for ensuring the RNG is initialized
 *     before any call reaches this function.
 *   - If randomness is unavailable (RNG not initialized, hardware failure),
 *     the implementation MUST NOT return silently with uninitialized output.
 *     It must hang/panic/loop until randomness is available.
 *   - On STM32: implemented via rng_bytes() which requires rng_init() to have
 *     been called first (done in keyboard_post_init_user before kbv_init).
 *   - The entropy guard in write_slot() provides a second line of defence, but
 *     kbv_plat_random() itself must never silently return bad data.
 */
void     kbv_plat_random(uint8_t *buf, size_t len);
int      kbv_plat_flash_read(uint32_t off, uint8_t *buf, size_t len);
int      kbv_plat_flash_write(uint32_t off, const uint8_t *buf, size_t len);
int      kbv_plat_flash_erase(void);  /* erase vault page */
uint32_t kbv_plat_time_ms(void);      /* for idle timeout */
uint16_t kbv_plat_entropy_bits(void); /* accumulated entropy estimate */
