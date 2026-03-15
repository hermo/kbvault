/*
 * kbv_platform_stm32.c — STM32F401xC platform implementation for KBVault
 *
 * Flash sector 5 (0x0802_0000, 128 KB) is reserved for the vault.
 * Only the first 16 KB of sector 5 is used; the rest is wasted but harmless.
 * UID is read from 0x1FFF7A10 (96-bit, 12 bytes).
 * Random bytes come from the entropy-seeded CSPRNG in rng.c.
 */

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "hal.h"      /* ChibiOS/STM32 CMSIS headers, FLASH_TypeDef, etc. */
#include "timer.h"    /* QMK timer_read32() */

#include "kbv_platform.h"
#include "rng.h"

/* ── Flash layout ────────────────────────────────────────────────────────── */

#define VAULT_FLASH_BASE   0x08020000UL   /* Sector 5, 128KB (only 16KB used for vault) */
#define VAULT_FLASH_SECTOR 5U
#define VAULT_FLASH_SIZE   (16U * 1024U)

/* ── CMSIS fallback defines ──────────────────────────────────────────────── */

#ifndef FLASH_CR_SNB_Pos
#define FLASH_CR_SNB_Pos 3U
#endif
#ifndef FLASH_CR_PSIZE_Pos
#define FLASH_CR_PSIZE_Pos 8U
#endif

/* ── UID ─────────────────────────────────────────────────────────────────── */

void kbv_plat_get_uid(uint8_t out[12])
{
    /*
     * STM32F401 96-bit unique device ID at 0x1FFF7A10.
     * Three 32-bit words: U_ID0 = word at 0x1FFF7A10,
     *                     U_ID1 = word at 0x1FFF7A14,
     *                     U_ID2 = word at 0x1FFF7A18.
     * Reference: RM0368 §24.1
     */
    const uint8_t *uid = (const uint8_t *)0x1FFF7A10UL;
    memcpy(out, uid, 12);
}

/* ── RNG ─────────────────────────────────────────────────────────────────── */

void kbv_plat_random(uint8_t *buf, size_t len)
{
    rng_bytes(buf, len);
}

/* ── Flash helpers ───────────────────────────────────────────────────────── */

static void flash_unlock(void)
{
    if (FLASH->CR & FLASH_CR_LOCK) {
        FLASH->KEYR = 0x45670123UL;
        FLASH->KEYR = 0xCDEF89ABUL;
    }
}

static void flash_lock(void)
{
    FLASH->CR |= FLASH_CR_LOCK;
}

static void flash_wait_busy(void)
{
    while (FLASH->SR & FLASH_SR_BSY);
}

static void flash_clear_errors(void)
{
    /* Clear error flags on STM32F401 (no OPERR on this device) */
    FLASH->SR = FLASH_SR_PGSERR | FLASH_SR_PGPERR |
                FLASH_SR_PGAERR | FLASH_SR_WRPERR;
}

/* ── Public flash API ────────────────────────────────────────────────────── */

int kbv_plat_flash_read(uint32_t off, uint8_t *buf, size_t len)
{
    if (off + len > VAULT_FLASH_SIZE) return -1;
    memcpy(buf, (const uint8_t *)(VAULT_FLASH_BASE + off), len);
    return 0;
}

int kbv_plat_flash_write(uint32_t off, const uint8_t *buf, size_t len)
{
    if (off + len > VAULT_FLASH_SIZE) return -1;

    flash_unlock();
    flash_wait_busy();
    flash_clear_errors();

    /*
     * Program in bytes (PSIZE = 00 = byte writes).
     * For each byte: set PG, write byte, wait for BSY to clear.
     * Reference: RM0368 §3.6 Flash programming
     */
    FLASH->CR = (FLASH->CR & ~FLASH_CR_PSIZE) | FLASH_CR_PG;

    const uint8_t *src  = buf;
    uint8_t       *dest = (uint8_t *)(VAULT_FLASH_BASE + off);

    for (size_t i = 0; i < len; i++) {
        *dest++ = *src++;
        flash_wait_busy();
        if (FLASH->SR & (FLASH_SR_PGSERR | FLASH_SR_PGPERR |
                         FLASH_SR_PGAERR | FLASH_SR_WRPERR)) {
            flash_clear_errors();
            FLASH->CR &= ~FLASH_CR_PG;
            flash_lock();
            return -1;
        }
    }

    FLASH->CR &= ~FLASH_CR_PG;
    flash_lock();
    return 0;
}

int kbv_plat_flash_erase(void)
{
    /*
     * Erases ONLY Sector 5 (0x08020000, 128 KB) — the vault sector.
     * The vault uses only the first 16 KB (990 bytes of data); the rest
     * of the 128 KB sector is erased but left unused.
     *
     * STM32F401xC flash layout (RM0368 Table 4):
     *   Sector 0: 0x08000000  16 KB  \
     *   Sector 1: 0x08004000  16 KB   | firmware (flash0 + flash1 EEPROM)
     *   Sector 2: 0x08008000  16 KB  ┐
     *   Sector 3: 0x0800C000  16 KB  │ firmware (flash2, capped at 96 KB)
     *   Sector 4: 0x08010000  64 KB  ┘
     *   Sector 5: 0x08020000 128 KB  ← vault (ONLY this sector is erased here)
     *
     * RM0368 §3.6.3 sector erase sequence:
     *   1. Wait for BSY = 0
     *   2. Set SER = 1 and SNB[3:0] = target sector number in FLASH_CR
     *   3. Set STRT = 1 in FLASH_CR (separate write — do NOT combine with step 2)
     *   4. Wait for BSY = 0
     *
     * STRT MUST be set in a separate write after SER/SNB are already in FLASH_CR.
     * Writing SER, SNB, and STRT simultaneously in one assignment can trigger a
     * mass erase (FLASH_CR_MER behaviour) on STM32F4 due to the controller
     * sampling the CR state at STRT assertion. Always use two writes.
     *
     * PSIZE = 10b (32-bit parallelism) for VDD = 3.3V per RM0368 §3.6.1.
     * FLASH_CR_SNB_Pos = 3; sector 3 encodes as (3U << 3) = 0x18 in SNB[4:0].
     */
    flash_unlock();
    flash_wait_busy();
    flash_clear_errors();

    /* Step 2: configure sector erase — do NOT set STRT yet */
    FLASH->CR = FLASH_CR_SER
              | (VAULT_FLASH_SECTOR << FLASH_CR_SNB_Pos)  /* SNB = 5 */
              | (2U << FLASH_CR_PSIZE_Pos);               /* 32-bit, VDD=3.3V */

    /* Step 3: start erase in a separate write as required by RM0368 §3.6.3 */
    FLASH->CR |= FLASH_CR_STRT;

    /* Step 4: wait for erase to complete */
    flash_wait_busy();
    flash_clear_errors();

    FLASH->CR &= ~(FLASH_CR_SER | FLASH_CR_SNB | FLASH_CR_PSIZE | FLASH_CR_STRT);
    flash_lock();
    return 0;
}

/* ── Timer ───────────────────────────────────────────────────────────────── */

uint32_t kbv_plat_time_ms(void)
{
    return timer_read32();
}

/* ── Entropy ─────────────────────────────────────────────────────────────── */

uint16_t kbv_plat_entropy_bits(void)
{
    return rng_entropy_bits();
}
