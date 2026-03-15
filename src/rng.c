/*
 * rng.c — STM32F401xC entropy collection for KBVault
 *
 * Uses three entropy sources:
 *   1. ADC internal channels (CH16 Temp + CH17 Vrefint): 512 samples at boot
 *   2. DWT cycle counter jitter: stirred during ADC collection + each keypress
 *   3. Keystroke timing: delta of DWT->CYCCNT between keypresses
 *
 * All entropy feeds hxcrypt's hx_csprng_t (ChaCha20-BLAKE2s DRBG).
 */

#include "hal.h"          /* ChibiOS HAL — brings in STM32 CMSIS headers */
#include "timer.h"        /* QMK timer_read32() */
#include "hxcrypt.h"
#include "rng.h"

/* ── CSPRNG state ─────────────────────────────────────────────────────────── */

static hx_csprng_t g_rng;
static uint16_t    g_entropy_bits = 0;

/* ── DWT helpers ──────────────────────────────────────────────────────────── */

static void dwt_enable(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CTRL        |= DWT_CTRL_CYCCNTENA_Msk;
    DWT->CYCCNT       = 0;
}

static uint32_t dwt_read(void)
{
    return DWT->CYCCNT;
}

/* ── ADC entropy collection ───────────────────────────────────────────────── */

/*
 * Single blocking ADC conversion on the given channel (16 or 17).
 * Returns the 12-bit result.
 *
 * Register references: STM32F4 Reference Manual RM0368 §11.
 */
static uint16_t adc_sample(uint8_t channel)
{
    /* Channel selection */
    ADC1->SQR3 = channel;

    /* Sample time: 480 cycles (bits 111) for CH16/CH17 as required by RM0368 §11.3.3 */
    if (channel == 16)
        ADC1->SMPR1 = (7U << 18);  /* bits [20:18] = CH16 */
    else
        ADC1->SMPR1 = (7U << 21);  /* bits [23:21] = CH17 */

    ADC1->SR    = 0;                       /* Clear status */
    ADC1->CR2  |= ADC_CR2_SWSTART;        /* Software start */
    while (!(ADC1->SR & ADC_SR_EOC));      /* Wait for end-of-conversion */

    return (uint16_t)(ADC1->DR & 0xFFF);
}

static void adc_setup(void)
{
    /* Enable ADC1 clock */
    RCC->APB2ENR |= RCC_APB2ENR_ADC1EN;

    /* Enable internal temp sensor + Vrefint */
    ADC->CCR |= ADC_CCR_TSVREFE;

    /* Power on ADC1; single conversion, 12-bit right-aligned (defaults) */
    ADC1->CR1 = 0;
    ADC1->CR2 = ADC_CR2_ADON;

    /* Wait ≥10 µs for ADC stabilisation (RM0368 §11.3.6).
     * At 84 MHz, 1000 NOPs ≈ 12 µs. */
    for (volatile uint32_t i = 0; i < 1000; i++)
        __asm__ volatile("nop");
}

static void adc_teardown(void)
{
    ADC1->CR2           = 0;                         /* Power off ADC1 */
    ADC->CCR           &= ~ADC_CCR_TSVREFE;          /* Disable internal channels */
    RCC->APB2ENR       &= ~RCC_APB2ENR_ADC1EN;      /* Gate clock */
}

/*
 * Collect 512 ADC samples (alternating CH16/CH17) and stir their noise
 * bytes into the entropy pool. Also stirs DWT readings for mixing.
 *
 * Takes ~11 ms at 21 MHz ADC clock (512 × 480 cycles / 21 MHz).
 */
static void adc_collect_entropy(void)
{
    adc_setup();

    for (int i = 0; i < 512; i++) {
        uint8_t ch = (i & 1) ? 17 : 16;
        uint16_t s = adc_sample(ch);

        /* Use bottom 2 LSBs of each sample (~1-2 bits real entropy per sample) */
        uint8_t noise = (uint8_t)(s & 0x03);
        hx_csprng_stir(&g_rng, &noise, 1);
        if (g_entropy_bits < 65000u) g_entropy_bits = (uint16_t)(g_entropy_bits + 2u);

        /* Stir DWT reading for cross-source mixing */
        uint32_t cyc = dwt_read();
        hx_csprng_stir(&g_rng, (uint8_t *)&cyc, 4);
    }

    adc_teardown();
}

/* ── Public API ───────────────────────────────────────────────────────────── */

void rng_init(void)
{
    hx_csprng_init(&g_rng);

    /* Source 1: Enable DWT cycle counter */
    dwt_enable();

    /* Source 2: ADC thermal/shot noise from internal channels */
    adc_collect_entropy();

    /* Stir in QMK timer and DWT for nonce uniqueness */
    uint32_t t = timer_read32();
    hx_csprng_stir(&g_rng, (uint8_t *)&t, 4);
    uint32_t cyc = dwt_read();
    hx_csprng_stir(&g_rng, (uint8_t *)&cyc, 4);

    /* Seed the DRBG — ADC collection should have produced ≥256 bits_stirred.
     * If seeding fails (insufficient entropy), reset the counter so the entropy
     * guard in write_slot() blocks any slot writes until entropy is sufficient. */
    if (hx_csprng_seed(&g_rng) != 0)
        g_entropy_bits = 0;
}

void rng_feed_keypress(void)
{
    static uint32_t last_cyc = 0;
    uint32_t now   = dwt_read();
    uint32_t delta = now - last_cyc;
    last_cyc       = now;

    /* Feed all 32 bits of inter-keypress delta into the pool */
    hx_csprng_stir(&g_rng, (uint8_t *)&delta, 4);
    if (g_entropy_bits < 65000u) g_entropy_bits = (uint16_t)(g_entropy_bits + 4u);
}

uint16_t rng_entropy_bits(void)
{
    return g_entropy_bits;
}

void rng_bytes(uint8_t *out, size_t len)
{
    /* If not seeded, do a best-effort seed with whatever entropy has been stirred.
     * If seeding still fails (insufficient entropy), zero the output buffer and
     * return — the entropy guard in write_slot() provides the second line of
     * defence and will block any slot write until entropy is sufficient. */
    if (!g_rng.seeded) {
        if (hx_csprng_seed(&g_rng) != 0) {
            hx_explicit_zero(out, len);
            return;
        }
    }
    hx_csprng_bytes(&g_rng, out, len);
}
