/* test_master_policy.c — REQ-MASTER with the default KBV_MIN_MASTER_LEN (12). */
#include <stdio.h>
#include <string.h>
#include "kbv.h"
#include "kbv_platform.h"

static char g_out[1024];
static void out_cb(const char *s) { strncat(g_out, s, sizeof(g_out) - strlen(g_out) - 1); }
static void type_cb(const char *p, size_t n) { (void)p; (void)n; }

static int g_fail;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

static void feed(kbv_ctx_t *c, const char *s) { while (*s) kbv_feed_char(c, *s++); }

int main(void) {
    kbv_ctx_t ctx;
    kbv_plat_flash_erase();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    kbv_login(&ctx);

    feed(&ctx, "elevenchars"); /* 11 */
    kbv_feed_char(&ctx, '\r');
    CHECK(kbv_get_state(&ctx) == KBV_STATE_AUTHING);
    CHECK(strstr(g_out, "too short") != NULL);

    feed(&ctx, "twelvechars!"); /* 12 */
    kbv_feed_char(&ctx, '\r');
    CHECK(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED);

    /* change-master: short rejected, long accepted into the confirm step */
    kbv_enter_menu(&ctx);
    g_out[0] = '\0';
    feed(&ctx, "sp");
    feed(&ctx, "elevenchars\r");
    CHECK(strstr(g_out, "too short") != NULL);
    g_out[0] = '\0';
    kbv_feed_char(&ctx, 'p');
    feed(&ctx, "anotherlong12\r");
    CHECK(strstr(g_out, "confirm?") != NULL);

    printf(g_fail ? "master policy: %d failed\n" : "master policy: ok\n", g_fail);
    return g_fail ? 1 : 0;
}
