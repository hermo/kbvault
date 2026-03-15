/*
 * test_vault.c — KBVault vault logic test suite
 *
 * Standalone C test file. No external test framework.
 * Build and run via: make test (from project root)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "kbv.h"
#include "hxcrypt.h"
#include "kbv_platform.h"
#include "kbv_charmap_keycodes.h"
#include "kbv_charmap.h"

/* ── Test infrastructure ────────────────────────────────────────────────── */

static int g_pass = 0, g_fail = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, msg); \
        g_fail++; \
    } else { \
        g_pass++; \
    } \
} while(0)

#define TEST(name) static void name(void)

/* Output callback — collects output into a buffer */
#define OUT_BUF_SIZE 4096
static char g_out[OUT_BUF_SIZE];
static size_t g_out_len;

static void out_cb(const char *s) {
    size_t n = strlen(s);
    if (g_out_len + n < OUT_BUF_SIZE - 1) {
        memcpy(g_out + g_out_len, s, n);
        g_out_len += n;
        g_out[g_out_len] = '\0';
    }
}

/* Password type callback — stores last typed password */
static char g_typed[KBV_MAX_PWD_LEN + 1];
static size_t g_typed_len;

static void type_cb(const char *pwd, size_t len) {
    g_typed_len = len < KBV_MAX_PWD_LEN ? len : KBV_MAX_PWD_LEN;
    memcpy(g_typed, pwd, g_typed_len);
    g_typed[g_typed_len] = '\0';
}

static void reset_output(void) {
    memset(g_out, 0, sizeof(g_out));
    g_out_len = 0;
}

static void reset_typed(void) {
    memset(g_typed, 0, sizeof(g_typed));
    g_typed_len = 0;
}

/* Feed a C string character by character to kbv_feed_char */
static void feed_str(kbv_ctx_t *ctx, const char *s) {
    while (*s) kbv_feed_char(ctx, *s++);
}

/* Event callback — records the last event fired */
static kbv_event_t g_last_event;
static int g_event_count;
static int g_wiped_fired;
static int g_entropy_low_fired;

static void event_cb(kbv_event_t ev) {
    g_last_event = ev;
    g_event_count++;
    if (ev == KBV_EVENT_WIPED)       g_wiped_fired = 1;
    if (ev == KBV_EVENT_ENTROPY_LOW) g_entropy_low_fired = 1;
}

static void reset_events(void) {
    g_last_event        = (kbv_event_t)-1;
    g_event_count       = 0;
    g_wiped_fired       = 0;
    g_entropy_low_fired = 0;
}

/*
 * Injectable mocks from the POSIX platform (kbv_platform_posix.c).
 * g_mock_entropy_bits: default 0xFFFF (fully seeded); set < 256 for entropy guard.
 * g_mock_time_ms: default 0 (use real time); set non-zero to override kbv_plat_time_ms().
 */
extern uint16_t g_mock_entropy_bits;
extern uint32_t g_mock_time_ms;

/* Fresh vault for each test: erase flash, create new kbv_ctx_t, init */
static void fresh_vault(kbv_ctx_t *ctx) {
    kbv_plat_flash_erase();
    reset_output();
    reset_typed();
    kbv_init(ctx, out_cb, type_cb, NULL);
}

/*
 * Set up a vault with a known master password and return unlocked ctx.
 * After this call, state == KBV_STATE_UNLOCKED (transparent).
 */
static void setup_vault(kbv_ctx_t *ctx, const char *master_pwd) {
    fresh_vault(ctx);
    /* kbv_init() stays LOCKED; press login hotkey to start new-vault setup */
    kbv_login(ctx);
    reset_output();
    feed_str(ctx, master_pwd);
    kbv_feed_char(ctx, '\r');
    /* should be UNLOCKED now (transparent) */
}

/* Enter MENU from UNLOCKED state */
static void enter_menu(kbv_ctx_t *ctx) {
    kbv_enter_menu(ctx);
}

/* ── Tests ──────────────────────────────────────────────────────────────── */

TEST(test_init_fresh_vault) {
    kbv_ctx_t ctx;
    fresh_vault(&ctx);

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "fresh vault should start LOCKED (invisible on boot)");
    ASSERT(kbv_is_active(&ctx) == 0,
           "fresh vault should not be active on boot");
    ASSERT(strstr(g_out, "new vault") == NULL,
           "fresh vault should not output anything on boot");

    /* Pressing KBV_LOGIN should trigger new-vault setup */
    kbv_login(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_AUTHING,
           "after kbv_login on fresh flash, should be AUTHING");
    ASSERT(kbv_is_active(&ctx) == 1,
           "should be active (AUTHING) after kbv_login");
    ASSERT(strstr(g_out, "new vault") != NULL,
           "kbv_login on fresh flash should output 'new vault'");
}

TEST(test_first_time_setup) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "testpass");

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "after entering master password, state should be UNLOCKED");
    ASSERT(kbv_is_active(&ctx) == 0,
           "is_active should return 0 when UNLOCKED (transparent)");
    ASSERT(strstr(g_out, "ok\n") != NULL,
           "new vault setup should output 'ok\\n'");
}

TEST(test_wrong_password) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "correct");
    kbv_lock(&ctx);

    /* Re-init with the same flash (vault persists) */
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "after re-init with existing vault, state should be LOCKED");

    kbv_login(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_AUTHING,
           "after login, state should be AUTHING");

    feed_str(&ctx, "wrongpass");
    kbv_feed_char(&ctx, '\r');

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "after wrong password, state should be LOCKED");
}

TEST(test_correct_password) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "correct");
    kbv_lock(&ctx);

    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "after re-init with existing vault, state should be LOCKED");

    kbv_login(&ctx);
    feed_str(&ctx, "correct");
    kbv_feed_char(&ctx, '\r');

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "after correct password, state should be UNLOCKED");
}

TEST(test_encrypt_decrypt_roundtrip) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "masterkey");

    /* Enter menu and edit slot 1: 'e','1', then "secret\r" */
    enter_menu(&ctx);
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    feed_str(&ctx, "secret\r");

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_MENU,
           "after editing slot 1, should still be in MENU");
    ASSERT(ctx.slot_flags & 0x01,
           "slot 1 flag should be set after edit");

    /* Exit to UNLOCKED */
    kbv_feed_char(&ctx, 'q');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "after 'q', should be UNLOCKED");

    /* Lock and re-init */
    kbv_lock(&ctx);
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    kbv_login(&ctx);
    feed_str(&ctx, "masterkey");
    kbv_feed_char(&ctx, '\r');

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "should unlock after re-init with correct password");

    /* Type slot 0 (0-based) via kbv_type_slot */
    reset_typed();
    kbv_type_slot(&ctx, 0);

    ASSERT(strcmp(g_typed, "secret") == 0,
           "typed password should be 'secret'");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "vault should stay UNLOCKED after kbv_type_slot");
}

TEST(test_mac_rejection) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "masterkey");

    /* Enter menu and edit slot 1 */
    enter_menu(&ctx);
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    feed_str(&ctx, "topsecret\r");
    kbv_feed_char(&ctx, 'q');  /* exit to UNLOCKED */

    /* Corrupt one byte in the ciphertext area of slot 0 (slot index 0).
     * Slot base = KBV_HDR_SIZE + 0 * KBV_SLOT_SIZE = 120.
     * CT offset from slot base = KBV_SLOT_OFF_CT = 0x0D = 13.
     * Corrupt byte at: 120 + 13 = 133.
     */
    uint32_t corrupt_off = KBV_HDR_SIZE + KBV_SLOT_OFF_CT;
    uint8_t bad_byte = 0x00;  /* NOR-compliant: only clears bits (1->0) */
    kbv_plat_flash_write(corrupt_off, &bad_byte, 1);

    /* Lock and re-init */
    kbv_lock(&ctx);
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    kbv_login(&ctx);
    feed_str(&ctx, "masterkey");
    kbv_feed_char(&ctx, '\r');

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "should unlock after re-init");

    /* Try to type slot 0 (corrupt) via kbv_type_slot */
    reset_typed();
    kbv_type_slot(&ctx, 0);

    ASSERT(g_typed_len == 0,
           "type_cb should NOT be called when MAC verification fails");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "vault should stay UNLOCKED on MAC failure");
}

TEST(test_slot_list) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "masterkey");

    /* Enter menu, add to slot 1 */
    enter_menu(&ctx);
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    feed_str(&ctx, "pw1\r");

    /* Add to slot 3 */
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '3');
    feed_str(&ctx, "pw3\r");

    /* List slots */
    reset_output();
    kbv_feed_char(&ctx, 'l');

    ASSERT(strstr(g_out, "1:*") != NULL, "slot 1 should be occupied ('*')");
    ASSERT(strstr(g_out, "2:.") != NULL, "slot 2 should be empty ('.')");
    ASSERT(strstr(g_out, "3:*") != NULL, "slot 3 should be occupied ('*')");
    ASSERT(strstr(g_out, "4:.") != NULL, "slot 4 should be empty ('.')");
    ASSERT(strstr(g_out, "5:.") != NULL, "slot 5 should be empty ('.')");
}

TEST(test_delete_slot) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "masterkey");

    /* Enter menu, add to slot 2 */
    enter_menu(&ctx);
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '2');
    feed_str(&ctx, "pw2\r");

    ASSERT(ctx.slot_flags & 0x02, "slot 2 flag should be set after edit");

    /* Delete slot 2: 'd', '2', 'y' */
    kbv_feed_char(&ctx, 'd');
    kbv_feed_char(&ctx, '2');
    kbv_feed_char(&ctx, 'y');

    ASSERT(!(ctx.slot_flags & 0x02), "slot 2 flag should be clear after delete");

    /* List: slot 2 should show '.' */
    reset_output();
    kbv_feed_char(&ctx, 'l');
    ASSERT(strstr(g_out, "2:.") != NULL, "slot 2 should be empty after delete");
}

TEST(test_state_machine_transitions) {
    kbv_ctx_t ctx;
    /* Setup to get a valid vault on flash, then lock */
    setup_vault(&ctx, "statepass");
    kbv_lock(&ctx);

    /* Re-init: should be LOCKED */
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "initial state after re-init should be LOCKED");
    ASSERT(kbv_is_active(&ctx) == 0,
           "is_active should return 0 when LOCKED");

    /* Login: LOCKED -> AUTHING */
    kbv_login(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_AUTHING,
           "after login, state should be AUTHING");
    ASSERT(kbv_is_active(&ctx) == 1,
           "is_active should return 1 when AUTHING");

    /* Use mock time so we can control lockout */
    g_mock_time_ms = 100000;

    /* Wrong password -> LOCKED */
    feed_str(&ctx, "badpass");
    kbv_feed_char(&ctx, '\r');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "after wrong password, should be LOCKED");

    /* Advance past 1s lockout */
    g_mock_time_ms = 102000;

    /* Login again -> AUTHING */
    kbv_login(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_AUTHING,
           "second login should go to AUTHING again");

    /* Correct password -> UNLOCKED */
    feed_str(&ctx, "statepass");
    kbv_feed_char(&ctx, '\r');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "after correct password, should be UNLOCKED");
    ASSERT(kbv_is_active(&ctx) == 0,
           "is_active should return 0 when UNLOCKED (transparent)");

    /* Enter menu -> MENU */
    kbv_enter_menu(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_MENU,
           "after kbv_enter_menu, should be in MENU");
    ASSERT(kbv_is_active(&ctx) == 1,
           "is_active should return 1 when in MENU");

    /* 's' -> settings sub-state (still MENU) */
    kbv_feed_char(&ctx, 's');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_MENU,
           "after 's', should still be in MENU (settings is a sub-state)");
    ASSERT(kbv_is_active(&ctx) == 1,
           "is_active should return 1 in settings sub-state");

    /* 'b' -> back to MENU cmd_state 0 (still MENU) */
    kbv_feed_char(&ctx, 'b');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_MENU,
           "after 'b' in settings, should still be in MENU");

    /* 'q' -> UNLOCKED (not LOCKED!) */
    kbv_feed_char(&ctx, 'q');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "after 'q' in MENU, should be UNLOCKED");
    ASSERT(kbv_is_active(&ctx) == 0,
           "is_active should return 0 after 'q' (UNLOCKED)");

    /* kbv_lock -> LOCKED */
    kbv_lock(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "after kbv_lock, should be LOCKED");
    ASSERT(kbv_is_active(&ctx) == 0,
           "is_active should return 0 after kbv_lock");

    g_mock_time_ms = 0;  /* restore real time */
}

TEST(test_change_master_password) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "oldpass");

    /* Enter menu and add a password to slot 1 */
    enter_menu(&ctx);
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    feed_str(&ctx, "slotpw\r");

    /* Go to settings and change master password: 's','p', new pw, confirm */
    kbv_feed_char(&ctx, 's');  /* -> settings sub-state (still MENU) */
    kbv_feed_char(&ctx, 'p');  /* change password sub-command */
    feed_str(&ctx, "newpass\r"); /* new password */
    feed_str(&ctx, "newpass\r"); /* confirm */

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_MENU,
           "after changing password, should remain in MENU (cmd_state reset to 0)");

    /* Exit menu to UNLOCKED, then lock */
    kbv_feed_char(&ctx, 'q');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "after 'q', should be UNLOCKED");
    kbv_lock(&ctx);

    /* Re-init: try old password — should fail */
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    kbv_login(&ctx);
    feed_str(&ctx, "oldpass");
    kbv_feed_char(&ctx, '\r');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "old password should be rejected after master password change");

    /* Re-init: try new password — should succeed */
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    kbv_login(&ctx);
    feed_str(&ctx, "newpass");
    kbv_feed_char(&ctx, '\r');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "new password should unlock the vault");

    /* Type slot 0 via kbv_type_slot — should get original slot password */
    reset_typed();
    kbv_type_slot(&ctx, 0);
    ASSERT(strcmp(g_typed, "slotpw") == 0,
           "slot 1 password should survive master password change");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "should stay UNLOCKED after kbv_type_slot");
}

TEST(test_settings_duress) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "master");

    /* Enter menu, set duress password: 's','d', enter + confirm */
    enter_menu(&ctx);
    kbv_feed_char(&ctx, 's');    /* -> settings sub-state (still MENU) */
    kbv_feed_char(&ctx, 'd');    /* change duress sub-command */
    feed_str(&ctx, "duress\r");  /* new duress password */
    feed_str(&ctx, "duress\r");  /* confirm */

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_MENU,
           "after setting duress password, should be in MENU");

    /* Exit to UNLOCKED and lock */
    kbv_feed_char(&ctx, 'q');
    kbv_lock(&ctx);

    /* Re-init and authenticate with duress password */
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    kbv_login(&ctx);
    reset_output();  /* clear the login output (none expected but be safe) */
    feed_str(&ctx, "duress");
    kbv_feed_char(&ctx, '\r');

    /* Duress: vault should be LOCKED and flash erased — output should NOT have "kbv: " */
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "duress password should lock the vault (wipe)");
    ASSERT(strstr(g_out, "kbv: ") == NULL,
           "duress path should not output 'kbv: '");

    /* After duress, flash is erased: re-init stays LOCKED; login triggers new vault */
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "after duress wipe, re-init should be LOCKED");
    kbv_login(&ctx);
    ASSERT(strstr(g_out, "new vault") != NULL,
           "after duress wipe, kbv_login should show 'new vault'");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_AUTHING,
           "after duress wipe, kbv_login should be in AUTHING");
}

TEST(test_settings_clear) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "clearme");

    /* Enter menu, go to settings, clear vault: 's', 'c', 'y' */
    enter_menu(&ctx);
    kbv_feed_char(&ctx, 's');
    kbv_feed_char(&ctx, 'c');
    kbv_feed_char(&ctx, 'y');

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "after clear confirm 'y', vault should be LOCKED");

    /* Re-init stays LOCKED; login triggers new vault setup */
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "after clear, re-init should be LOCKED");
    kbv_login(&ctx);
    ASSERT(strstr(g_out, "new vault") != NULL,
           "after clear, kbv_login should show 'new vault'");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_AUTHING,
           "after clear, kbv_login should be in AUTHING");
}

TEST(test_memory_zero_on_lock) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "memtest");

    /* PRK and enc_key should be populated while unlocked */
    int prk_nonzero = 0;
    for (size_t i = 0; i < sizeof(ctx.prk); i++) {
        if (ctx.prk[i] != 0) { prk_nonzero = 1; break; }
    }
    ASSERT(prk_nonzero, "PRK should be non-zero while vault is unlocked");

    kbv_lock(&ctx);

    /* After lock, prk and enc_key should all be zero */
    int prk_zero = 1;
    for (size_t i = 0; i < sizeof(ctx.prk); i++) {
        if (ctx.prk[i] != 0) { prk_zero = 0; break; }
    }
    ASSERT(prk_zero, "PRK should be zeroed after kbv_lock()");

    int enc_key_zero = 1;
    for (size_t i = 0; i < sizeof(ctx.enc_key); i++) {
        if (((uint8_t *)ctx.enc_key)[i] != 0) { enc_key_zero = 0; break; }
    }
    ASSERT(enc_key_zero, "enc_key should be zeroed after kbv_lock()");

    int mac_key_zero = 1;
    for (size_t i = 0; i < sizeof(ctx.mac_key); i++) {
        if (((uint8_t *)ctx.mac_key)[i] != 0) { mac_key_zero = 0; break; }
    }
    ASSERT(mac_key_zero, "mac_key should be zeroed after kbv_lock()");
}

TEST(test_kbv_type_slot) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "master");

    /* Enter menu and store a password in slot 2 (index 1) */
    kbv_enter_menu(&ctx);
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '2');
    feed_str(&ctx, "mypassword\r");
    kbv_feed_char(&ctx, 'q');  /* exit to UNLOCKED */

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "should be UNLOCKED after q");

    /* Type slot via hotkey path */
    reset_typed();
    kbv_type_slot(&ctx, 1);  /* slot index 1 = slot 2 */

    ASSERT(g_typed_len > 0, "type_cb should have been called");
    ASSERT(strcmp(g_typed, "mypassword") == 0, "typed password should match");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "should stay UNLOCKED after type_slot");

    /* type_slot on empty slot should do nothing */
    reset_typed();
    kbv_type_slot(&ctx, 4);  /* slot 5, empty */
    ASSERT(g_typed_len == 0, "empty slot should not call type_cb");
}

TEST(test_menu_type_stays_in_menu) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "master");

    /* Enter menu and store in slot 1 */
    kbv_enter_menu(&ctx);
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    feed_str(&ctx, "pw\r");

    /* Type slot 1 from within menu by pressing '1' */
    reset_typed();
    kbv_feed_char(&ctx, '1');

    ASSERT(g_typed_len > 0, "type_cb should be called");
    ASSERT(strcmp(g_typed, "pw") == 0, "typed password should match");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_MENU,
           "should stay in MENU after typing slot");
}

TEST(test_delete_then_readd) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "master");

    /* Enter menu, write "firstpw" to slot 1 */
    enter_menu(&ctx);
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    feed_str(&ctx, "firstpw\r");

    /* Delete slot 1 */
    kbv_feed_char(&ctx, 'd');
    kbv_feed_char(&ctx, '1');
    kbv_feed_char(&ctx, 'y');

    ASSERT(!(ctx.slot_flags & 0x01), "slot 1 flag should be clear after delete");

    /* Write "secondpw" to slot 1 again */
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    feed_str(&ctx, "secondpw\r");

    ASSERT(ctx.slot_flags & 0x01, "slot 1 flag should be set after re-add");

    /* Exit menu, lock */
    kbv_feed_char(&ctx, 'q');
    kbv_lock(&ctx);

    /* Re-init: unlock with "master" */
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    kbv_login(&ctx);
    feed_str(&ctx, "master");
    kbv_feed_char(&ctx, '\r');

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "should be UNLOCKED after re-init with correct password");

    /* Type slot 0 (0-based index for slot 1) */
    reset_typed();
    kbv_type_slot(&ctx, 0);

    ASSERT(strcmp(g_typed, "secondpw") == 0,
           "typed password should be 'secondpw' after delete-then-readd");
}

TEST(test_change_master_password_full_vault) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "oldpass");

    /* Fill all 5 slots */
    enter_menu(&ctx);
    kbv_feed_char(&ctx, 'e'); kbv_feed_char(&ctx, '1'); feed_str(&ctx, "pw1\r");
    kbv_feed_char(&ctx, 'e'); kbv_feed_char(&ctx, '2'); feed_str(&ctx, "pw2\r");
    kbv_feed_char(&ctx, 'e'); kbv_feed_char(&ctx, '3'); feed_str(&ctx, "pw3\r");
    kbv_feed_char(&ctx, 'e'); kbv_feed_char(&ctx, '4'); feed_str(&ctx, "pw4\r");
    kbv_feed_char(&ctx, 'e'); kbv_feed_char(&ctx, '5'); feed_str(&ctx, "pw5\r");

    ASSERT(ctx.slot_flags == 0x1F, "all 5 slots should be occupied before password change");

    /* Change master password with all slots full */
    kbv_feed_char(&ctx, 's');
    kbv_feed_char(&ctx, 'p');
    feed_str(&ctx, "newpass\r");
    feed_str(&ctx, "newpass\r");

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_MENU,
           "after full-vault password change, should remain in MENU");

    /* Exit to UNLOCKED, then lock */
    kbv_feed_char(&ctx, 'q');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "after 'q', should be UNLOCKED");
    kbv_lock(&ctx);

    /* Re-init, unlock with new password */
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    kbv_login(&ctx);
    feed_str(&ctx, "newpass");
    kbv_feed_char(&ctx, '\r');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "new password should unlock the vault after full-vault rekey");

    /* Verify all 5 slot passwords survived the rekey */
    const char *expected[5] = { "pw1", "pw2", "pw3", "pw4", "pw5" };
    for (int i = 0; i < 5; i++) {
        reset_typed();
        kbv_type_slot(&ctx, (uint8_t)i);
        ASSERT(strcmp(g_typed, expected[i]) == 0,
               "slot password should survive full-vault master password change");
    }

    /* Old password must be rejected */
    kbv_lock(&ctx);
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    kbv_login(&ctx);
    feed_str(&ctx, "oldpass");
    kbv_feed_char(&ctx, '\r');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "old password should be rejected after full-vault master password change");
}

TEST(test_clear_fires_event) {
    kbv_ctx_t ctx;
    kbv_plat_flash_erase();
    reset_output();
    reset_typed();
    reset_events();

    /* Init with event callback registered */
    kbv_init(&ctx, out_cb, type_cb, event_cb);

    /* Set up a valid vault so slot_flags is non-trivially zero later */
    kbv_login(&ctx);
    feed_str(&ctx, "testpass");
    kbv_feed_char(&ctx, '\r');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "vault should be UNLOCKED before kbv_clear");

    reset_events();
    kbv_clear(&ctx);

    ASSERT(g_wiped_fired,
           "KBV_EVENT_WIPED should be fired by kbv_clear()");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "state should be LOCKED after kbv_clear()");
    ASSERT(ctx.slot_flags == 0,
           "slot_flags should be 0 after kbv_clear()");
}

TEST(test_kbv_clear_reinit) {
    kbv_ctx_t ctx;
    kbv_plat_flash_erase();
    reset_output();
    reset_typed();

    /* Set up a valid vault */
    kbv_init(&ctx, out_cb, type_cb, NULL);
    kbv_login(&ctx);
    feed_str(&ctx, "testpass");
    kbv_feed_char(&ctx, '\r');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "vault should be UNLOCKED before kbv_clear");

    /* Wipe the vault */
    kbv_clear(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "state should be LOCKED after kbv_clear()");

    /* Re-init — flash is erased, so it should look like fresh flash */
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "after kbv_clear + re-init, state should be LOCKED");

    /* kbv_login() should trigger new-vault setup (magic absent) */
    kbv_login(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_AUTHING,
           "after kbv_clear + re-init + login, should be AUTHING");
    ASSERT(strstr(g_out, "new vault") != NULL,
           "after kbv_clear, kbv_login should show 'new vault' (fresh flash)");
}

/*
 * Injectable entropy level from the POSIX platform mock (kbvault-sku).
 * Default is 0xFFFF (fully seeded). Drop below KBV_MIN_ENTROPY_BITS (256)
 * to trigger the entropy guard in write_slot().
 */
extern uint16_t g_mock_entropy_bits;

/*
 * Injectable time mock from the POSIX platform mock (kbvault-sle).
 * Default is 0 (disabled). When non-zero, kbv_plat_time_ms() returns this
 * value instead of real monotonic time. Use to simulate idle timeout.
 */
extern uint32_t g_mock_time_ms;

TEST(test_entropy_guard_blocks_write) {
    kbv_ctx_t ctx;
    kbv_plat_flash_erase();
    reset_output();
    reset_typed();
    reset_events();

    /* Set up a vault with the event-tracking callback */
    kbv_init(&ctx, out_cb, type_cb, event_cb);
    kbv_login(&ctx);
    feed_str(&ctx, "master\r");

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "entropy guard test: vault should be UNLOCKED after setup");

    kbv_enter_menu(&ctx);
    uint8_t flags_before = ctx.slot_flags;
    reset_events();

    /* Inject low entropy — below KBV_MIN_ENTROPY_BITS (256) */
    g_mock_entropy_bits = 100;

    /* Attempt to write slot 1: 'e', '1', password, Enter */
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    feed_str(&ctx, "secret\r");

    /* Restore entropy to full before any further vault operations */
    g_mock_entropy_bits = 0xFFFF;

    ASSERT(g_entropy_low_fired,
           "entropy guard: KBV_EVENT_ENTROPY_LOW must be fired when entropy is low");
    ASSERT(ctx.slot_flags == flags_before,
           "entropy guard: slot_flags must be unchanged when entropy is low");
    ASSERT(!(ctx.slot_flags & 0x01),
           "entropy guard: slot 1 must remain empty when entropy is low");
}

TEST(test_password_with_spaces) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "master");

    /* Enter menu, edit slot 1 with a password containing spaces */
    kbv_enter_menu(&ctx);
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    feed_str(&ctx, "test password entry\r");

    /* Type slot 1 from menu — spaces must be preserved */
    reset_typed();
    kbv_feed_char(&ctx, '1');

    ASSERT(g_typed_len == 19,
           "typed password length should be 19 (including spaces)");
    ASSERT(strcmp(g_typed, "test password entry") == 0,
           "typed password should preserve spaces: 'test password entry'");

    /* Slot 2: leading space */
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '2');
    feed_str(&ctx, " leadingspace\r");

    reset_typed();
    kbv_feed_char(&ctx, '2');
    ASSERT(strcmp(g_typed, " leadingspace") == 0,
           "leading space must be preserved");

    /* Slot 3: trailing space */
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '3');
    feed_str(&ctx, "trailingspace \r");

    reset_typed();
    kbv_feed_char(&ctx, '3');
    ASSERT(strcmp(g_typed, "trailingspace ") == 0,
           "trailing space must be preserved");

    /* Slot 4: consecutive spaces */
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '4');
    feed_str(&ctx, "a  b   c\r");

    reset_typed();
    kbv_feed_char(&ctx, '4');
    ASSERT(strcmp(g_typed, "a  b   c") == 0,
           "consecutive spaces must be preserved");

    /* Verify round-trip: lock, re-init, unlock, type slot 1 */
    kbv_feed_char(&ctx, 'q');  /* exit menu → UNLOCKED */
    kbv_lock(&ctx);
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    kbv_login(&ctx);
    feed_str(&ctx, "master\r");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "should unlock after re-init");

    reset_typed();
    kbv_type_slot(&ctx, 0);
    ASSERT(strcmp(g_typed, "test password entry") == 0,
           "spaces must survive encrypt/flash/decrypt round-trip");
}

/* ── Task 1: kbvault-sle — idle timeout via injectable time mock ─────────── */

TEST(test_idle_timeout) {
    kbv_ctx_t ctx;

    /* Set a base mock time so kbv_init sets last_activity_ms to this value */
    g_mock_time_ms = 1000;

    /* setup_vault calls kbv_init (records last_activity_ms = 1000) and
     * then authenticates, leaving vault UNLOCKED */
    setup_vault(&ctx, "idlepass");

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "idle timeout test: vault should be UNLOCKED after setup");

    /* Advance time beyond KBV_IDLE_TIMEOUT_MS (120*60*1000 = 7200000 ms) */
    g_mock_time_ms = 1000 + 7200001u;

    /* kbv_tick() should detect the elapsed time and lock */
    kbv_tick(&ctx);

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "idle timeout: vault should be LOCKED after KBV_IDLE_TIMEOUT_MS elapses");

    /* Restore mock time */
    g_mock_time_ms = 0;
}

/* ── Task 2: kbvault-j2o — input edge case tests ────────────────────────── */

TEST(test_backspace_in_password) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "master");

    enter_menu(&ctx);
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');

    /* Type "abc", backspace (deletes 'c'), then "d\r" → result should be "abd" */
    feed_str(&ctx, "abc");
    kbv_feed_char(&ctx, '\b');
    feed_str(&ctx, "d\r");

    /* Type slot 1 from menu and verify */
    reset_typed();
    kbv_feed_char(&ctx, '1');

    ASSERT(strcmp(g_typed, "abd") == 0,
           "backspace in password: typed password should be 'abd'");
}

TEST(test_input_overflow) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "master");

    enter_menu(&ctx);
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');

    /* Feed 130 'a' characters (exceeds KBV_MAX_PWD_LEN=128), then Enter */
    for (int i = 0; i < 130; i++) {
        kbv_feed_char(&ctx, 'a');
    }
    kbv_feed_char(&ctx, '\r');

    /* Type slot 1 from menu and verify length is capped at 128 */
    reset_typed();
    kbv_feed_char(&ctx, '1');

    ASSERT(g_typed_len == KBV_MAX_PWD_LEN,
           "input overflow: typed password length should be capped at KBV_MAX_PWD_LEN (128)");
}

TEST(test_edit_overwrite_existing_slot) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "master");

    enter_menu(&ctx);

    /* Write "first" to slot 1 */
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    feed_str(&ctx, "first\r");

    /* Overwrite slot 1 with "second" */
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    feed_str(&ctx, "second\r");

    /* Exit menu, lock, re-init, unlock */
    kbv_feed_char(&ctx, 'q');
    kbv_lock(&ctx);
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    kbv_login(&ctx);
    feed_str(&ctx, "master\r");

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "edit overwrite: should be UNLOCKED after re-init");

    /* Type slot 0 (0-based index for slot 1) and verify it contains "second" */
    reset_typed();
    kbv_type_slot(&ctx, 0);

    ASSERT(strcmp(g_typed, "second") == 0,
           "edit overwrite: overwritten slot should contain 'second'");
}

TEST(test_state_guard_noops) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "master");

    /* Vault is UNLOCKED after setup_vault */
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "state guard: should be UNLOCKED after setup");

    /* kbv_login() is a no-op when UNLOCKED */
    kbv_login(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "state guard: kbv_login() should be no-op when UNLOCKED");

    /* Lock the vault */
    kbv_lock(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "state guard: should be LOCKED after kbv_lock()");

    /* kbv_enter_menu() is a no-op when LOCKED */
    kbv_enter_menu(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "state guard: kbv_enter_menu() should be no-op when LOCKED");

    /* kbv_type_slot() is a no-op when LOCKED */
    reset_typed();
    kbv_type_slot(&ctx, 0);
    ASSERT(g_typed_len == 0,
           "state guard: kbv_type_slot() should not type anything when LOCKED");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "state guard: kbv_type_slot() should leave state LOCKED when LOCKED");
}

/* ── Task 3: kbvault-z4i — new vault entropy guard test ─────────────────── */

TEST(test_entropy_guard_on_new_vault) {
    kbv_ctx_t ctx;
    kbv_plat_flash_erase();
    reset_output();
    reset_typed();
    reset_events();

    /* Inject low entropy — below KBV_MIN_ENTROPY_BITS (256) */
    g_mock_entropy_bits = 100;

    /* Init on fresh flash — will detect no vault present */
    kbv_init(&ctx, out_cb, type_cb, event_cb);

    /* Login enters AUTHING with cmd_state=CMDSTATE_NEW_VAULT */
    kbv_login(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_AUTHING,
           "entropy guard new vault: should be AUTHING after login on fresh flash");

    /* Feed password — entropy guard should block new vault commit */
    feed_str(&ctx, "testpass\r");

    /* State should remain LOCKED (not UNLOCKED), entropy_low event should fire */
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "entropy guard new vault: state should be LOCKED (not UNLOCKED) when entropy is low");
    ASSERT(g_entropy_low_fired,
           "entropy guard new vault: KBV_EVENT_ENTROPY_LOW should be fired when entropy is low");

    /* Restore entropy to full */
    g_mock_entropy_bits = 0xFFFF;
}

/* ── UX tests ────────────────────────────────────────────────────────────── */

TEST(test_edit_delete_show_slot_prompt) {
    /*
     * kbvault-0j3: After 'e' and 'd' in cmd_state 0, the menu should emit
     * "slot?\n" so the user knows to press a slot number.
     * Changed from "#?\n" to avoid shell comment interpretation (kbvault-3tp).
     */
    kbv_ctx_t ctx;
    setup_vault(&ctx, "master");
    enter_menu(&ctx);

    /* Press 'e' — should output "slot?\n" */
    reset_output();
    kbv_feed_char(&ctx, 'e');
    ASSERT(strstr(g_out, "slot?\n") != NULL,
           "after 'e', menu should output 'slot?\\n' prompt");

    /* Cancel by pressing a non-slot key, back to cmd_state 0 */
    kbv_feed_char(&ctx, 'x');

    /* Press 'd' — should output "slot?\n" */
    reset_output();
    kbv_feed_char(&ctx, 'd');
    ASSERT(strstr(g_out, "slot?\n") != NULL,
           "after 'd', menu should output 'slot?\\n' prompt");

    /* Cancel */
    kbv_feed_char(&ctx, 'x');
}

TEST(test_menu_quit_outputs_bye) {
    /* kbvault-3tp: 'q' should output "bye\n" so the user knows they exited. */
    kbv_ctx_t ctx;
    setup_vault(&ctx, "master");
    enter_menu(&ctx);

    reset_output();
    kbv_feed_char(&ctx, 'q');
    ASSERT(strstr(g_out, "bye\n") != NULL,
           "after 'q', menu should output 'bye\\n'");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "after 'q', state should be UNLOCKED");
}

TEST(test_menu_type_outputs_ok) {
    /*
     * kbvault-d6m: After typing an occupied slot from within the menu,
     * the menu should output "ok\n" before the "kbv: " prompt.
     */
    kbv_ctx_t ctx;
    setup_vault(&ctx, "master");
    enter_menu(&ctx);

    /* Store a password in slot 1 */
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    feed_str(&ctx, "mypassword\r");

    /* Type slot 1 from menu */
    reset_output();
    reset_typed();
    kbv_feed_char(&ctx, '1');

    ASSERT(strstr(g_out, "ok\n") != NULL,
           "typing occupied slot from menu should output 'ok\\n'");
    ASSERT(strstr(g_out, "kbv: ") != NULL,
           "after ok, menu prompt 'kbv: ' should appear");
    ASSERT(strcmp(g_typed, "mypassword") == 0,
           "typed password should match stored password");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_MENU,
           "should remain in MENU after typing slot");
}

TEST(test_entropy_guard_blocks_rekey) {
    kbv_ctx_t ctx;
    kbv_plat_flash_erase();
    reset_output();
    reset_typed();
    reset_events();

    /* Set up a vault with event callback, store a slot password */
    kbv_init(&ctx, out_cb, type_cb, event_cb);
    kbv_login(&ctx);
    feed_str(&ctx, "oldpass\r");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "rekey entropy guard: vault should be UNLOCKED after setup");

    kbv_enter_menu(&ctx);
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    feed_str(&ctx, "slotpw\r");
    ASSERT(ctx.slot_flags & 0x01,
           "rekey entropy guard: slot 1 should be occupied");

    /* Enter settings, start password change */
    kbv_feed_char(&ctx, 's');
    kbv_feed_char(&ctx, 'p');
    feed_str(&ctx, "newpass\r");  /* new password */

    /* Drop entropy before confirming */
    g_mock_entropy_bits = 100;
    reset_events();
    reset_output();

    feed_str(&ctx, "newpass\r");  /* confirm — should be blocked */

    /* Restore entropy */
    g_mock_entropy_bits = 0xFFFF;

    ASSERT(g_entropy_low_fired,
           "rekey entropy guard: KBV_EVENT_ENTROPY_LOW must fire");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_MENU,
           "rekey entropy guard: should remain in MENU state");
    ASSERT(strstr(g_out, "low entropy") != NULL,
           "rekey entropy guard: output should contain 'low entropy'");

    /* Old password should still work — re-key did not happen */
    kbv_feed_char(&ctx, 'q');  /* exit menu → UNLOCKED */
    kbv_lock(&ctx);
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, event_cb);
    kbv_login(&ctx);
    feed_str(&ctx, "oldpass\r");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "rekey entropy guard: old password must still work after blocked rekey");

    /* Slot data should be intact */
    reset_typed();
    kbv_type_slot(&ctx, 0);
    ASSERT(strcmp(g_typed, "slotpw") == 0,
           "rekey entropy guard: slot password must survive blocked rekey");
}

TEST(test_login_after_clear_without_reinit) {
    kbv_ctx_t ctx;
    kbv_plat_flash_erase();
    reset_output();
    reset_typed();
    reset_events();

    /* Set up a valid vault with a stored password */
    kbv_init(&ctx, out_cb, type_cb, event_cb);
    kbv_login(&ctx);
    feed_str(&ctx, "mypass\r");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "clear-no-reinit: vault should be UNLOCKED after setup");

    /* Store a password in slot 1 */
    kbv_enter_menu(&ctx);
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    feed_str(&ctx, "secret\r");
    kbv_feed_char(&ctx, 'q');  /* exit menu -> UNLOCKED */

    /* Wipe the vault — do NOT call kbv_init() afterward */
    kbv_clear(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "clear-no-reinit: state should be LOCKED after kbv_clear()");

    /* kbv_login() should detect erased flash and enter new-vault setup */
    reset_output();
    kbv_login(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_AUTHING,
           "clear-no-reinit: should be AUTHING after kbv_login()");
    ASSERT(strstr(g_out, "new vault") != NULL,
           "clear-no-reinit: kbv_login() should show 'new vault' without re-init");

    /* Complete the new-vault setup with a new password */
    reset_output();
    feed_str(&ctx, "newpass\r");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "clear-no-reinit: should be UNLOCKED after new vault setup");
    ASSERT(strstr(g_out, "ok\n") != NULL,
           "clear-no-reinit: new vault commit should output 'ok'");

    /* Lock and verify the new password works (without re-init) */
    kbv_lock(&ctx);
    reset_output();
    kbv_login(&ctx);
    ASSERT(strstr(g_out, "new vault") == NULL,
           "clear-no-reinit: second login should NOT show 'new vault'");
    feed_str(&ctx, "newpass\r");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "clear-no-reinit: new password should unlock the vault");
}

TEST(test_settings_clear_without_reinit) {
    kbv_ctx_t ctx;
    kbv_plat_flash_erase();
    reset_output();
    reset_typed();
    reset_events();

    /* Set up a valid vault */
    kbv_init(&ctx, out_cb, type_cb, event_cb);
    kbv_login(&ctx);
    feed_str(&ctx, "mypass\r");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "settings-clear: vault should be UNLOCKED after setup");

    /* Enter menu -> settings -> clear -> 'y' */
    kbv_enter_menu(&ctx);
    kbv_feed_char(&ctx, 's');
    kbv_feed_char(&ctx, 'c');
    kbv_feed_char(&ctx, 'y');

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "settings-clear: should be LOCKED after clear confirm");

    /* kbv_login() should detect erased flash and enter new-vault setup */
    reset_output();
    kbv_login(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_AUTHING,
           "settings-clear: should be AUTHING after kbv_login()");
    ASSERT(strstr(g_out, "new vault") != NULL,
           "settings-clear: kbv_login() should show 'new vault' without re-init");

    /* Complete the new-vault setup */
    reset_output();
    feed_str(&ctx, "freshpass\r");
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "settings-clear: should be UNLOCKED after new vault setup");
}

TEST(test_bruteforce_throttle) {
    kbv_ctx_t ctx;
    setup_vault(&ctx, "correct");
    kbv_lock(&ctx);

    /* Re-init with the persisted vault */
    reset_output();
    reset_typed();
    reset_events();
    kbv_init(&ctx, out_cb, type_cb, event_cb);

    /* Use mock time for deterministic control */
    g_mock_time_ms = 50000;

    /* 1. Enter wrong password — should go LOCKED */
    kbv_login(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_AUTHING,
           "throttle: should be AUTHING after first kbv_login");
    feed_str(&ctx, "wrong");
    kbv_feed_char(&ctx, '\r');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "throttle: should be LOCKED after wrong password");
    ASSERT(ctx.fail_count == 1,
           "throttle: fail_count should be 1 after first failure");

    /* 2. Immediately try kbv_login() — should stay LOCKED (within 1s lockout) */
    g_mock_time_ms = 50500;  /* only 500ms later, lockout is 1000ms */
    kbv_login(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "throttle: kbv_login during lockout should stay LOCKED");

    /* 3. Advance mock time past the 1s lockout */
    g_mock_time_ms = 51500;  /* 1500ms after failure, lockout was 1000ms */
    kbv_login(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_AUTHING,
           "throttle: kbv_login after lockout expires should go AUTHING");

    /* 4. Enter correct password — should unlock and reset fail_count */
    feed_str(&ctx, "correct");
    kbv_feed_char(&ctx, '\r');
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "throttle: correct password should unlock");
    ASSERT(ctx.fail_count == 0,
           "throttle: fail_count should be 0 after successful auth");
    ASSERT(ctx.lockout_until_ms == 0,
           "throttle: lockout_until_ms should be 0 after successful auth");

    /* 5. Verify exponential backoff: two consecutive failures */
    kbv_lock(&ctx);
    reset_output();
    kbv_init(&ctx, out_cb, type_cb, event_cb);

    g_mock_time_ms = 100000;
    kbv_login(&ctx);
    feed_str(&ctx, "wrong1");
    kbv_feed_char(&ctx, '\r');  /* fail_count=1, lockout=1000ms */
    ASSERT(ctx.fail_count == 1, "throttle: fail_count should be 1");

    g_mock_time_ms = 101500;  /* past 1s lockout */
    kbv_login(&ctx);
    feed_str(&ctx, "wrong2");
    kbv_feed_char(&ctx, '\r');  /* fail_count=2, lockout=2000ms */
    ASSERT(ctx.fail_count == 2, "throttle: fail_count should be 2");

    /* Within 2s lockout window — should be rejected */
    g_mock_time_ms = 102500;  /* only 1s after second failure */
    kbv_login(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_LOCKED,
           "throttle: should stay LOCKED within 2s lockout");

    /* Past 2s lockout — should allow login */
    g_mock_time_ms = 104000;  /* 2.5s after second failure */
    kbv_login(&ctx);
    ASSERT(kbv_get_state(&ctx) == KBV_STATE_AUTHING,
           "throttle: should go AUTHING after 2s lockout expires");

    /* Clean up */
    feed_str(&ctx, "correct");
    kbv_feed_char(&ctx, '\r');
    g_mock_time_ms = 0;
}

/* ── Charmap tests (Finnish ISO keycode → ASCII) ───────────────────────── */

TEST(test_charmap_lowercase) {
    /* a–z: KC_A..KC_Z unshifted */
    for (uint16_t kc = KC_A; kc <= KC_Z; kc++) {
        char expected = (char)('a' + (kc - KC_A));
        char got = kbv_keycode_to_char(kc, false);
        if (got != expected) {
            fprintf(stderr, "FAIL: charmap lowercase: KC 0x%02X expected '%c' got '%c'\n",
                    kc, expected, got);
            g_fail++;
        } else {
            g_pass++;
        }
    }
}

TEST(test_charmap_uppercase) {
    /* A–Z: KC_A..KC_Z shifted */
    for (uint16_t kc = KC_A; kc <= KC_Z; kc++) {
        char expected = (char)('A' + (kc - KC_A));
        char got = kbv_keycode_to_char(kc, true);
        if (got != expected) {
            fprintf(stderr, "FAIL: charmap uppercase: KC 0x%02X expected '%c' got '%c'\n",
                    kc, expected, got);
            g_fail++;
        } else {
            g_pass++;
        }
    }
}

TEST(test_charmap_digits) {
    /* 1–9, 0 unshifted */
    const char *digits = "1234567890";
    for (int i = 0; i < 10; i++) {
        uint16_t kc = KC_1 + (uint16_t)i;
        char got = kbv_keycode_to_char(kc, false);
        if (got != digits[i]) {
            fprintf(stderr, "FAIL: charmap digit: KC 0x%02X expected '%c' got '%c'\n",
                    kc, digits[i], got);
            g_fail++;
        } else {
            g_pass++;
        }
    }
}

TEST(test_charmap_shifted_digits_finnish) {
    /* Finnish shifted number row: 1=! 2=" 3=# 4=$ 5=% 6=& 7=/ 8=( 9=) 0== */
    const char *shifted = "!\"#$%&/()=";
    for (int i = 0; i < 10; i++) {
        uint16_t kc = KC_1 + (uint16_t)i;
        char got = kbv_keycode_to_char(kc, true);
        if (got != shifted[i]) {
            fprintf(stderr, "FAIL: charmap shifted digit: KC 0x%02X expected '%c' (0x%02X) got '%c' (0x%02X)\n",
                    kc, shifted[i], (unsigned char)shifted[i], got, (unsigned char)got);
            g_fail++;
        } else {
            g_pass++;
        }
    }
}

TEST(test_charmap_specials_finnish) {
    /* Finnish ISO special keys: unshifted and shifted */
    struct { uint16_t kc; char unshifted; char shifted; } cases[] = {
        { KC_MINS, '+', '?' },
        { KC_SLSH, '-', '_' },
        { KC_DOT,  '.', ':' },
        { KC_COMM, ',', ';' },
        { KC_NUBS, '<', '>' },
        { KC_SPC,  ' ', ' ' },
        { KC_BSPC, '\b', '\b' },
        { KC_ENT,  '\r', '\r' },
    };
    int n = (int)(sizeof(cases) / sizeof(cases[0]));
    for (int i = 0; i < n; i++) {
        char got_u = kbv_keycode_to_char(cases[i].kc, false);
        char got_s = kbv_keycode_to_char(cases[i].kc, true);
        if (got_u != cases[i].unshifted) {
            fprintf(stderr, "FAIL: charmap special unshifted: KC 0x%02X expected 0x%02X got 0x%02X\n",
                    cases[i].kc, (unsigned char)cases[i].unshifted, (unsigned char)got_u);
            g_fail++;
        } else {
            g_pass++;
        }
        if (got_s != cases[i].shifted) {
            fprintf(stderr, "FAIL: charmap special shifted: KC 0x%02X expected 0x%02X got 0x%02X\n",
                    cases[i].kc, (unsigned char)cases[i].shifted, (unsigned char)got_s);
            g_fail++;
        } else {
            g_pass++;
        }
    }
}

TEST(test_charmap_layer_tap_unwrap) {
    /* LT(layer, KC_SPC) should unwrap to KC_SPC */
    uint16_t lt_spc = QK_LAYER_TAP | KC_SPC;  /* e.g. LT(0, KC_SPC) */
    ASSERT(kbv_keycode_to_char(lt_spc, false) == ' ',
           "charmap: LT(x, KC_SPC) unshifted should produce space");
    ASSERT(kbv_keycode_to_char(lt_spc, true) == ' ',
           "charmap: LT(x, KC_SPC) shifted should produce space");

    /* LT(layer, KC_A) should unwrap to KC_A */
    uint16_t lt_a = QK_LAYER_TAP | KC_A;
    ASSERT(kbv_keycode_to_char(lt_a, false) == 'a',
           "charmap: LT(x, KC_A) unshifted should produce 'a'");
    ASSERT(kbv_keycode_to_char(lt_a, true) == 'A',
           "charmap: LT(x, KC_A) shifted should produce 'A'");
}

TEST(test_charmap_mod_tap_unwrap) {
    /* MT(mod, KC_A) should unwrap to KC_A */
    uint16_t mt_a = QK_MOD_TAP | KC_A;
    ASSERT(kbv_keycode_to_char(mt_a, false) == 'a',
           "charmap: MT(x, KC_A) unshifted should produce 'a'");
    ASSERT(kbv_keycode_to_char(mt_a, true) == 'A',
           "charmap: MT(x, KC_A) shifted should produce 'A'");
}

TEST(test_charmap_unknown_returns_zero) {
    /* Unknown keycodes should return 0 */
    ASSERT(kbv_keycode_to_char(0x00, false) == 0,
           "charmap: keycode 0x00 should return 0");
    ASSERT(kbv_keycode_to_char(0xFF, false) == 0,
           "charmap: keycode 0xFF should return 0");
    ASSERT(kbv_keycode_to_char(0x50, false) == 0,
           "charmap: unmapped keycode should return 0");
}

TEST(test_charmap_full_roundtrip) {
    /* Feed every mapped character through the charmap, then through the vault,
     * and verify the stored password matches. */
    kbv_ctx_t ctx;
    setup_vault(&ctx, "master");
    enter_menu(&ctx);

    /* Build a password from every mapped keycode */
    char expected[256];
    int elen = 0;

    /* a–z */
    for (uint16_t kc = KC_A; kc <= KC_Z; kc++) {
        char c = kbv_keycode_to_char(kc, false);
        if (c && c != '\r' && c != '\b') expected[elen++] = c;
    }
    /* A–Z */
    for (uint16_t kc = KC_A; kc <= KC_Z; kc++) {
        char c = kbv_keycode_to_char(kc, true);
        if (c && c != '\r' && c != '\b') expected[elen++] = c;
    }
    /* 0–9 */
    for (uint16_t kc = KC_1; kc <= KC_0; kc++) {
        char c = kbv_keycode_to_char(kc, false);
        if (c && c != '\r' && c != '\b') expected[elen++] = c;
    }
    /* Shifted digits */
    for (uint16_t kc = KC_1; kc <= KC_0; kc++) {
        char c = kbv_keycode_to_char(kc, true);
        if (c && c != '\r' && c != '\b') expected[elen++] = c;
    }
    /* Specials unshifted + shifted */
    uint16_t specials[] = { KC_MINS, KC_SLSH, KC_DOT, KC_COMM, KC_NUBS, KC_SPC };
    for (int i = 0; i < (int)(sizeof(specials)/sizeof(specials[0])); i++) {
        char c = kbv_keycode_to_char(specials[i], false);
        if (c && c != '\r' && c != '\b') expected[elen++] = c;
        c = kbv_keycode_to_char(specials[i], true);
        if (c && c != '\r' && c != '\b') expected[elen++] = c;
    }
    expected[elen] = '\0';

    ASSERT(elen <= KBV_MAX_PWD_LEN,
           "charmap roundtrip: total chars must fit in KBV_MAX_PWD_LEN");

    /* Store via menu edit slot 1 */
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    for (int i = 0; i < elen; i++) {
        kbv_feed_char(&ctx, expected[i]);
    }
    kbv_feed_char(&ctx, '\r');

    /* Exit, lock, re-init, unlock */
    kbv_feed_char(&ctx, 'q');
    kbv_lock(&ctx);
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    kbv_login(&ctx);
    feed_str(&ctx, "master\r");

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "charmap roundtrip: should be UNLOCKED");

    reset_typed();
    kbv_type_slot(&ctx, 0);

    ASSERT((int)g_typed_len == elen,
           "charmap roundtrip: typed length must match");
    ASSERT(memcmp(g_typed, expected, (size_t)elen) == 0,
           "charmap roundtrip: typed password must match exactly");
}

/* ── Vault core tests (char-level, no keycode dependency) ──────────────── */

TEST(test_all_password_chars) {
    /* Verify that all common password characters (base64 charset + specials)
     * survive a full store-lock-unlock-type roundtrip unchanged. */
    kbv_ctx_t ctx;
    setup_vault(&ctx, "master");

    /* base64 charset: A-Z a-z 0-9 + /
     * plus common password specials: !@#$%^&*()-_=[]{}|;:',.<>?`~ "\ */
    const char *test_pwd =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        "!@#$%^&*()-_=[]{}|;:',.<>?`~ \"\\";

    size_t pwd_len = strlen(test_pwd);
    ASSERT(pwd_len <= KBV_MAX_PWD_LEN,
           "all chars: test password must fit in KBV_MAX_PWD_LEN");

    enter_menu(&ctx);

    /* Store in slot 1 */
    kbv_feed_char(&ctx, 'e');
    kbv_feed_char(&ctx, '1');
    feed_str(&ctx, test_pwd);
    kbv_feed_char(&ctx, '\r');

    /* Exit menu, lock, re-init, unlock */
    kbv_feed_char(&ctx, 'q');
    kbv_lock(&ctx);
    reset_output();
    reset_typed();
    kbv_init(&ctx, out_cb, type_cb, NULL);
    kbv_login(&ctx);
    feed_str(&ctx, "master\r");

    ASSERT(kbv_get_state(&ctx) == KBV_STATE_UNLOCKED,
           "all chars: should be UNLOCKED after re-init");

    /* Type slot 0 and verify exact match */
    reset_typed();
    kbv_type_slot(&ctx, 0);

    ASSERT(g_typed_len == pwd_len,
           "all chars: typed length must match stored length");
    ASSERT(memcmp(g_typed, test_pwd, pwd_len) == 0,
           "all chars: typed password must match stored password exactly");
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void) {
    test_init_fresh_vault();
    test_first_time_setup();
    test_wrong_password();
    test_correct_password();
    test_encrypt_decrypt_roundtrip();
    test_mac_rejection();
    test_slot_list();
    test_delete_slot();
    test_state_machine_transitions();
    test_change_master_password();
    test_settings_duress();
    test_settings_clear();
    test_memory_zero_on_lock();
    test_kbv_type_slot();
    test_menu_type_stays_in_menu();
    test_delete_then_readd();
    test_change_master_password_full_vault();
    test_clear_fires_event();
    test_kbv_clear_reinit();
    test_entropy_guard_blocks_write();
    test_password_with_spaces();
    test_idle_timeout();
    test_backspace_in_password();
    test_input_overflow();
    test_edit_overwrite_existing_slot();
    test_state_guard_noops();
    test_entropy_guard_on_new_vault();
    test_edit_delete_show_slot_prompt();
    test_menu_quit_outputs_bye();
    test_menu_type_outputs_ok();
    test_entropy_guard_blocks_rekey();
    test_login_after_clear_without_reinit();
    test_settings_clear_without_reinit();
    test_bruteforce_throttle();
    test_all_password_chars();
    test_charmap_lowercase();
    test_charmap_uppercase();
    test_charmap_digits();
    test_charmap_shifted_digits_finnish();
    test_charmap_specials_finnish();
    test_charmap_layer_tap_unwrap();
    test_charmap_mod_tap_unwrap();
    test_charmap_unknown_returns_zero();
    test_charmap_full_roundtrip();

    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
