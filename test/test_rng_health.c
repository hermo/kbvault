/* test_rng_health.c — a stuck ADC must not earn entropy credit. */
#include <stdio.h>
#include "rng_health.h"

int main(void) {
    rng_adc_health_t h;
    int fail = 0;

    rng_adc_health_init(&h);
    for (int i = 0; i < 512; i++) rng_adc_health_add(&h, i & 1, 1234);
    if (h.changes > 2) { fprintf(stderr, "FAIL: stuck ADC credited %u\n", h.changes); fail++; }

    rng_adc_health_init(&h);
    for (int i = 0; i < 512; i++) rng_adc_health_add(&h, i & 1, (uint16_t)(1000 + ((i >> 1) & 1)));
    if (h.changes < 256) { fprintf(stderr, "FAIL: toggling ADC credited only %u\n", h.changes); fail++; }

    printf(fail ? "rng health: %d failed\n" : "rng health: ok\n", fail);
    return fail ? 1 : 0;
}
