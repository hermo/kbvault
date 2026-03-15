#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include "kbv_platform.h"

#define VAULT_FILE  "vault.bin"
#define VAULT_SIZE  16384

static int vault_ensure(void)
{
    FILE *f = fopen(VAULT_FILE, "rb");
    if (f) {
        fclose(f);
        return 0;
    }
    f = fopen(VAULT_FILE, "wb");
    if (!f) return -1;
    uint8_t buf[256];
    memset(buf, 0xFF, sizeof(buf));
    size_t remaining = VAULT_SIZE;
    while (remaining > 0) {
        size_t chunk = remaining < sizeof(buf) ? remaining : sizeof(buf);
        if (fwrite(buf, 1, chunk, f) != chunk) {
            fclose(f);
            return -1;
        }
        remaining -= chunk;
    }
    fclose(f);
    return 0;
}

void kbv_plat_get_uid(uint8_t out[12])
{
    const uint8_t fake_uid[12] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C
    };
    memcpy(out, fake_uid, 12);
}

void kbv_plat_random(uint8_t *buf, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return;
    (void)fread(buf, 1, len, f);
    fclose(f);
}

int kbv_plat_flash_read(uint32_t off, uint8_t *buf, size_t len)
{
    if (vault_ensure() != 0) return -1;
    FILE *f = fopen(VAULT_FILE, "rb");
    if (!f) return -1;
    if (fseek(f, (long)off, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    if (fread(buf, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

int kbv_plat_flash_write(uint32_t off, const uint8_t *buf, size_t len)
{
    if (vault_ensure() != 0) return -1;

    /* NOR flash semantics: read existing bytes, check for 0->1 bit flips,
     * then AND new data into existing bytes before writing back. */
    uint8_t existing[1024];
    if (len > sizeof(existing)) {
        fprintf(stderr, "kbv_plat_flash_write: len %zu exceeds internal buffer\n", len);
        return -1;
    }

    FILE *f = fopen(VAULT_FILE, "r+b");
    if (!f) return -1;

    /* Read existing bytes */
    if (fseek(f, (long)off, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    if (fread(existing, 1, len, f) != len) {
        fclose(f);
        return -1;
    }

    /* Check for NOR violations (0->1 bit flips) and AND bytes */
    for (size_t i = 0; i < len; i++) {
        if (buf[i] & ~existing[i]) {
            fprintf(stderr,
                "kbv_plat_flash_write: NOR violation at offset %lu+%zu: "
                "existing=0x%02X new=0x%02X (bits %02X cannot be set)\n",
                (unsigned long)off, i, existing[i], buf[i],
                (unsigned)(buf[i] & ~existing[i]));
            fclose(f);
            return -1;
        }
        existing[i] &= buf[i];
    }

    /* Write ANDed result back */
    if (fseek(f, (long)off, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    if (fwrite(existing, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

int kbv_plat_flash_erase(void)
{
    FILE *f = fopen(VAULT_FILE, "wb");
    if (!f) return -1;
    uint8_t buf[256];
    memset(buf, 0xFF, sizeof(buf));
    size_t remaining = VAULT_SIZE;
    while (remaining > 0) {
        size_t chunk = remaining < sizeof(buf) ? remaining : sizeof(buf);
        if (fwrite(buf, 1, chunk, f) != chunk) {
            fclose(f);
            return -1;
        }
        remaining -= chunk;
    }
    fclose(f);
    return 0;
}

/* Injectable entropy mock for testing. Default 0xFFFF (fully seeded).
 * Set to a value < KBV_MIN_ENTROPY_BITS to test the entropy guard. */
uint16_t g_mock_entropy_bits = 0xFFFF;

uint16_t kbv_plat_entropy_bits(void)
{
    return g_mock_entropy_bits;
}

/* Injectable time mock for testing. Default 0 (disabled).
 * When non-zero, kbv_plat_time_ms() returns this value instead of real time.
 * Use to simulate idle timeout without actually waiting. */
uint32_t g_mock_time_ms = 0;

uint32_t kbv_plat_time_ms(void)
{
    if (g_mock_time_ms != 0)
        return g_mock_time_ms;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u);
}
