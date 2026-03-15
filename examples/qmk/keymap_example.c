/*
 * keymap_example.c — KBVault QMK integration example
 *
 * This example targets the Keychron Q3 Max (STM32F401xC, ISO 88-key layout).
 * Adapt kbv_platform.h implementation and LED indices for your keyboard.
 *
 * This is a stripped-down version of the actual keymap showing only the
 * kbvault integration points. Your keymap will have additional layers,
 * custom keycodes, encoder maps, etc. — those are not shown here.
 *
 * Integration checklist:
 *   [x] Custom keycodes (KBV_LOGIN, KBV_MENU, KBV_LOCK, KBV_PASS_1..5)
 *   [x] Static vault context (g_vault)
 *   [x] output_cb + type_cb + event_cb
 *   [x] keyboard_post_init_user: rng_init() then kbv_init()
 *   [x] process_record_user: hotkeys + feed chars when active
 *   [x] rgb_matrix_indicators_user: state-driven LED colors
 *   [x] housekeeping_task_user: kbv_tick() for idle timeout
 */

#include QMK_KEYBOARD_H
#include "kbv.h"    /* vault API — include path set in rules.mk */
#include "rng.h"    /* entropy accumulator — STM32F401 specific */

/* -------------------------------------------------------------------------
 * Custom keycodes
 *
 * Add these after your last existing custom keycode (SAFE_RANGE or your own
 * last keycode). Place them in your FN layer so they don't conflict with
 * normal typing.
 * ------------------------------------------------------------------------- */
enum kbv_keycodes {
    KBV_LOGIN  = SAFE_RANGE, /* LOCKED -> AUTHING: begin password entry       */
    KBV_MENU,                /* UNLOCKED -> MENU: enter vault management       */
    KBV_LOCK,                /* lock vault immediately, zero key material      */
    KBV_PASS_1,              /* type slot 0 password (0-based index)           */
    KBV_PASS_2,              /* type slot 1 password                           */
    KBV_PASS_3,              /* type slot 2 password                           */
    KBV_PASS_4,              /* type slot 3 password                           */
    KBV_PASS_5,              /* type slot 4 password                           */
};

/* -------------------------------------------------------------------------
 * Vault context
 *
 * Allocate statically — kbv_ctx_t holds key material in SRAM, so it must
 * live for the lifetime of the firmware. Never malloc on MCUs.
 * ------------------------------------------------------------------------- */
static kbv_ctx_t g_vault;

/* -------------------------------------------------------------------------
 * Output callback
 *
 * Called by the vault to send teletype-style UI text (prompts, status
 * messages like "Enter password:", "Password saved.", "Auth failed.").
 * We forward it to the host as HID keystrokes via QMK's send_string().
 *
 * Note: send_string() uses the US ANSI layout mapping. If your host uses
 * a different layout, the output may be garbled for non-ASCII characters.
 * Vault UI messages are ASCII-only so this is fine in practice.
 * ------------------------------------------------------------------------- */
static void vault_output_cb(const char *str) {
    send_string(str);
}

/* -------------------------------------------------------------------------
 * Password typing callback
 *
 * Called when the vault wants to type a stored password as HID keystrokes.
 * The password is delivered as a raw byte string (not null-padded).
 *
 * We use send_char() here which does simple ASCII -> HID mapping. If your
 * stored passwords use non-ASCII characters, you will need a layout-aware
 * send function (e.g. sendstring_finnish.h for Finnish ISO layouts).
 *
 * After this callback returns, the vault stays UNLOCKED and the per-call
 * decryption buffer is zeroed by kbv.c.
 * ------------------------------------------------------------------------- */
static void vault_type_cb(const char *pwd, size_t len) {
    for (size_t i = 0; i < len; i++) {
        send_char(pwd[i]);
    }
}

/* -------------------------------------------------------------------------
 * Event callback (added in kbvault-3lu, see ADR 004)
 *
 * Called by the vault at every significant state transition. Use this to
 * drive RGB feedback animations without polling or accessing ctx internals.
 *
 * The events:
 *   KBV_EVENT_UNLOCKED     — auth succeeded (AUTHING -> UNLOCKED): flash green
 *   KBV_EVENT_AUTH_FAILED  — wrong password (AUTHING -> LOCKED):   flash red
 *   KBV_EVENT_LOCKED       — vault locked (hotkey or idle timeout): dim LEDs
 *   KBV_EVENT_SLOT_TYPED   — password typed successfully:           brief flash
 *   KBV_EVENT_SLOT_EMPTY   — slot hotkey pressed on empty slot:     flash yellow
 *   KBV_EVENT_ENTROPY_LOW  — write refused, need more keypresses:   flash orange
 *
 * This stub just shows the structure. Fill in your preferred RGB effects.
 * The event_cb is optional — pass NULL to kbv_init() if you don't need it.
 * ------------------------------------------------------------------------- */
static void kbv_event_handler(kbv_event_t event) {
    switch (event) {
    case KBV_EVENT_UNLOCKED:
        /* Auth succeeded. Drive a brief green flash here, then
         * rgb_matrix_indicators_user() takes over with the steady green. */
        break;

    case KBV_EVENT_AUTH_FAILED:
        /* Wrong password. Flash red to signal failure.
         * A timer-based flash works well: set a flag and a deadline here,
         * then render red in rgb_matrix_indicators_user() until the deadline. */
        break;

    case KBV_EVENT_LOCKED:
        /* Vault locked (hotkey or idle timeout). Return LEDs to normal. */
        break;

    case KBV_EVENT_SLOT_TYPED:
        /* Password typed successfully. A brief flash or pulse looks nice. */
        break;

    case KBV_EVENT_SLOT_EMPTY:
        /* User hit a slot hotkey but the slot has no password stored.
         * Flash yellow or amber to indicate "nothing here". */
        break;

    case KBV_EVENT_ENTROPY_LOW:
        /* kbv.c refused a slot write because entropy is below the 256-bit
         * minimum (KBV_MIN_ENTROPY_BITS). Tell the user to type more keys.
         * Flash orange. The vault stays in MENU so the user can retry. */
        break;
    }
}

/* -------------------------------------------------------------------------
 * Keymap — only the FN layer KBV keys are shown.
 *
 * KBV_LOGIN, KBV_MENU, KBV_LOCK and KBV_PASS_1..5 should live in your FN
 * layer (or any layer you don't use for normal typing) so they are not
 * accidentally triggered. In the actual Keychron Q3 Max keymap they sit in
 * the top-right cluster of MAC_FN and WIN_FN.
 * ------------------------------------------------------------------------- */
/* (Full keymap omitted — add KBV_* keycodes wherever suits your layout.) */

/* -------------------------------------------------------------------------
 * keycode_to_vault_char
 *
 * Convert a QMK keycode + shift state to the ASCII character that should be
 * fed into the vault. The vault accumulates characters for the master
 * password input and for menu commands.
 *
 * This mapping must match the physical key labels on your keyboard. The
 * example below covers alpha, digit, and a small set of punctuation keys
 * for a Finnish ISO QWERTY layout. Adjust for your layout.
 *
 * Returns 0 for keycodes with no useful vault meaning (modifiers, media
 * keys, etc.) — the caller ignores them.
 * ------------------------------------------------------------------------- */
static char keycode_to_vault_char(uint16_t keycode, bool shifted) {
    /* Unwrap QMK composite keycodes (LT, MT) to their base keycode.
     * Without this, keys like LT(NAV, KC_SPC) would not match the KC_SPC
     * check below, silently dropping spaces from password input. */
    if (IS_QK_LAYER_TAP(keycode) || IS_QK_MOD_TAP(keycode)) {
        keycode = keycode & 0xFF;
    }

    /* Alpha: A-Z same physical positions as US ANSI */
    if (keycode >= KC_A && keycode <= KC_Z) {
        char base = (char)('a' + (keycode - KC_A));
        return shifted ? (char)(base - 32) : base;
    }

    /* Digit row (unshifted) */
    if (!shifted && keycode >= KC_1 && keycode <= KC_0) {
        static const char nums[] = "1234567890";
        return nums[keycode - KC_1];
    }

    /* Enter submits the current input buffer */
    if (keycode == KC_ENT) return '\r';

    /* Space is a valid password character */
    if (keycode == KC_SPC) return ' ';

    /*
     * Finnish ISO punctuation (unshifted).
     * Replace with your layout's mappings if different.
     */
    if (!shifted) {
        switch (keycode) {
        case KC_MINS: return '+';
        case KC_SLSH: return '-';
        case KC_DOT:  return '.';
        case KC_COMM: return ',';
        }
    } else {
        /* Finnish shifted number row: !  "  #  _  %  &  /  (  )  _ */
        if (keycode >= KC_1 && keycode <= KC_0) {
            static const char snums[] = "!\"#\x00%&/()\x00";
            char c = snums[keycode - KC_1];
            return c ? c : 0;
        }
        switch (keycode) {
        case KC_MINS: return '?';
        case KC_SLSH: return '_';
        case KC_DOT:  return ':';
        case KC_COMM: return ';';
        }
    }

    return 0; /* ignore this keycode */
}

/* -------------------------------------------------------------------------
 * keyboard_post_init_user
 *
 * Called once by QMK after the keyboard hardware is ready.
 *
 * IMPORTANT: rng_init() must be called BEFORE kbv_init(). It collects ADC
 * entropy and seeds the CSPRNG; kbv_init() reads flash and may call
 * kbv_plat_random() internally on first-time vault setup.
 *
 * rng_init() takes ~11 ms (512 ADC samples from CH16+CH17). This is fine
 * at boot; do not call it again later.
 * ------------------------------------------------------------------------- */
void keyboard_post_init_user(void) {
    rng_init();  /* ADC entropy + seed CSPRNG — must come first */

    /*
     * kbv_init reads flash:
     *   - If the vault sector has valid magic: loads salt, slot_flags, verify tags.
     *   - If blank or corrupt: formats the sector (erases, writes new header).
     * After kbv_init() returns, the vault is in LOCKED state.
     *
     * The four callbacks:
     *   vault_output_cb  — vault sends text to host (prompts, status)
     *   vault_type_cb    — vault types a stored password as keystrokes
     *   kbv_event_handler — state-transition events for RGB feedback
     *
     * Pass NULL for the event callback if you don't need RGB feedback.
     */
    kbv_init(&g_vault, vault_output_cb, vault_type_cb, kbv_event_handler);
}

/* -------------------------------------------------------------------------
 * process_record_user
 *
 * Called by QMK for every key event (press and release).
 *
 * Three things happen here in order:
 *   1. Feed keystroke timing entropy into the RNG (every event, press + release).
 *   2. Handle vault hotkeys (KBV_*) on press.
 *   3. If the vault is active (AUTHING or MENU), capture the keypress for
 *      the vault instead of forwarding it to the host.
 *
 * Returning false from process_record_user suppresses normal QMK processing
 * (the key is NOT sent to the host). Returning true passes it through.
 * ------------------------------------------------------------------------- */
bool process_record_user(uint16_t keycode, keyrecord_t *record) {
    /*
     * Step 1: Feed keystroke timing into the entropy pool.
     * Do this unconditionally — every keypress (press and release) adds
     * ~4 bits of entropy from the DWT cycle-counter delta.
     */
    rng_feed_keypress();

    if (record->event.pressed) {
        /*
         * Step 2: Vault hotkeys.
         * These are handled first, before the active-capture check below,
         * so they work in any vault state.
         */
        switch (keycode) {
        case KBV_LOGIN:
            /* Start authentication: LOCKED -> AUTHING.
             * No-op if already UNLOCKED or in MENU. */
            kbv_login(&g_vault);
            return false;

        case KBV_MENU:
            /* Enter management menu: UNLOCKED -> MENU.
             * No-op if LOCKED or AUTHING. */
            kbv_enter_menu(&g_vault);
            return false;

        case KBV_LOCK:
            /* Lock vault immediately, zero all key material.
             * Works from any state. */
            kbv_lock(&g_vault);
            return false;

        case KBV_PASS_1: kbv_type_slot(&g_vault, 0); return false;
        case KBV_PASS_2: kbv_type_slot(&g_vault, 1); return false;
        case KBV_PASS_3: kbv_type_slot(&g_vault, 2); return false;
        case KBV_PASS_4: kbv_type_slot(&g_vault, 3); return false;
        case KBV_PASS_5: kbv_type_slot(&g_vault, 4); return false;
            /*
             * kbv_type_slot: if UNLOCKED and slot is occupied, decrypts the
             * password and calls vault_type_cb() to type it as keystrokes.
             * If the slot is empty, fires KBV_EVENT_SLOT_EMPTY. No-op if
             * LOCKED or in MENU.
             */
        }

        /*
         * Step 3: Active key capture.
         *
         * kbv_is_active() returns 1 in AUTHING and MENU states.
         * In those states the vault owns the keyboard — do NOT forward
         * keypresses to the host.
         *
         * Convert the QMK keycode to an ASCII character and feed it to the
         * vault. kbv_feed_char() handles backspace (\b), enter (\r), and
         * printable characters. Unknown characters (return 0 from
         * keycode_to_vault_char) are silently dropped.
         */
        if (kbv_is_active(&g_vault)) {
            bool shifted = (get_mods() & MOD_MASK_SHIFT) != 0;
            char c = keycode_to_vault_char(keycode, shifted);
            if (c != 0) {
                kbv_feed_char(&g_vault, c);
            }
            return false; /* suppress host output while vault is active */
        }
    }

    return true; /* normal QMK processing */
}

/* -------------------------------------------------------------------------
 * rgb_matrix_indicators_user
 *
 * Called by QMK every scan cycle while RGB matrix is active. Use
 * kbv_get_state() to drive per-state LED colors.
 *
 * LED index 51 is the Caps Lock LED on the Keychron Q3 Max ISO 88.
 * Find your keyboard's LED indices in its LED map or via QMK's
 * rgb_matrix_indicators_advanced_user() with position-based lookup.
 *
 * These are the "steady state" colors. Transition animations (e.g. the
 * red flash on auth failure) are better driven from kbv_event_handler
 * using a flag + timer.
 * ------------------------------------------------------------------------- */
bool rgb_matrix_indicators_user(void) {
    switch (kbv_get_state(&g_vault)) {

    case KBV_STATE_AUTHING:
        /*
         * Pulsing amber across all keys: signals that the vault is waiting
         * for the master password. The pulse makes it obvious that key
         * capture is active — normal typing won't reach the host.
         *
         * timer_read() returns milliseconds since boot (uint16_t, wraps at
         * ~65 s but that is fine for a visual effect).
         */
        {
            uint16_t phase = (timer_read() / 2) % 512;
            uint8_t  val   = phase < 256 ? (uint8_t)phase : (uint8_t)(511 - phase);
            rgb_matrix_set_color_all(val, val / 2, 0);  /* R, G, B — amber */
        }
        break;

    case KBV_STATE_UNLOCKED:
        /*
         * Subtle green on the Caps Lock indicator only. The rest of the
         * keyboard is unaffected so normal RGB effects work. The user can
         * glance at Caps Lock to confirm the vault is open.
         */
        rgb_matrix_set_color(51, 0, 255, 0);   /* LED 51 = Caps Lock */
        break;

    case KBV_STATE_MENU:
        /*
         * Blue on Caps Lock: management menu is active. Like AUTHING, key
         * capture is on (kbv_is_active() is true), so keypresses go to the
         * vault, not the host. Blue distinguishes menu from auth.
         */
        rgb_matrix_set_color(51, 0, 0, 255);   /* LED 51 = Caps Lock */
        break;

    case KBV_STATE_LOCKED:
    default:
        /* LOCKED: no vault-specific LED override. Let normal RGB effects run. */
        break;
    }

    return true; /* true = allow other indicator callbacks to also run */
}

/* -------------------------------------------------------------------------
 * housekeeping_task_user
 *
 * Called by QMK in the main loop, after each scan cycle. Use this to run
 * kbv_tick() which checks the idle timeout and locks the vault if the user
 * has been inactive for too long.
 *
 * The idle timeout threshold is configured in kbv.c (KBV_IDLE_TIMEOUT_MS).
 * kbv_tick() is cheap — it just compares kbv_plat_time_ms() to
 * ctx->last_activity_ms and calls kbv_lock() if needed.
 * ------------------------------------------------------------------------- */
void housekeeping_task_user(void) {
    kbv_tick(&g_vault);
}
