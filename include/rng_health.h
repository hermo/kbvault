#pragma once
#include <stdint.h>

/*
 * ADC health: counts how often a channel's 12-bit sample differs from its
 * previous sample.  A stuck or dead ADC yields ~0 changes; a working one
 * yields hundreds.  The count (not a fixed credit per sample) is the entropy
 * estimate, so a broken ADC cannot satisfy the KBV_MIN_ENTROPY_BITS gate.
 * Pure C so it is host-testable (see test/test_rng_health.c).
 */
typedef struct {
    uint16_t last[2];   /* previous sample per channel, 0xFFFF = none yet */
    uint16_t changes;
} rng_adc_health_t;

static inline void rng_adc_health_init(rng_adc_health_t *h)
{
    h->last[0] = h->last[1] = 0xFFFFu;
    h->changes = 0;
}

static inline void rng_adc_health_add(rng_adc_health_t *h, uint8_t ch_idx, uint16_t sample)
{
    if (sample != h->last[ch_idx] && h->changes < 0xFFFFu) h->changes++;
    h->last[ch_idx] = sample;
}
