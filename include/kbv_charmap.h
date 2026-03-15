/*
 * kbv_charmap.h — QMK keycode-to-ASCII mapping for vault password input.
 *
 * This is the single source of truth for character mapping.
 * The QMK keymap #includes this file; kbvault tests compile against it
 * with a stub header providing keycode constants (no QMK dependency).
 *
 * Layout: Finnish ISO QWERTY.
 */
#pragma once
#include <stdint.h>

#ifndef KBV_CHARMAP_HAVE_QMK
#  include <stdbool.h>
#endif

/*
 * Convert a QMK keycode + shift state to an ASCII character for the vault.
 * Returns 0 for keycodes that don't map to a vault input character.
 *
 * Requires: KC_A..KC_Z, KC_1..KC_0, KC_BSPC, KC_ENT, KC_SPC,
 *           KC_MINS, KC_SLSH, KC_DOT, KC_COMM, KC_NUBS,
 *           IS_QK_LAYER_TAP(), IS_QK_MOD_TAP() — provided by QMK
 *           or by kbv_charmap_keycodes.h for host-side tests.
 */
static inline char kbv_keycode_to_char(uint16_t keycode, bool shifted) {
    /* Unwrap QMK composite keycodes (LT/MT) to their base keycode.
     * e.g. LT(NAV, KC_SPC) → KC_SPC so space is recognised. */
    if (IS_QK_LAYER_TAP(keycode) || IS_QK_MOD_TAP(keycode)) {
        keycode = keycode & 0xFF;
    }

    /* Alpha keys: same physical positions as US ANSI */
    if (keycode >= KC_A && keycode <= KC_Z) {
        char base = (char)('a' + (keycode - KC_A));
        return shifted ? (char)(base - 32) : base;
    }

    /* Digit row (unshifted) */
    if (!shifted) {
        if (keycode >= KC_1 && keycode <= KC_0) {
            /* KC_1..KC_9 = 1..9, KC_0 = 0 */
            static const char nums[] = "1234567890";
            return nums[keycode - KC_1];
        }
    }

    /* Backspace */
    if (keycode == KC_BSPC) return '\b';

    /* Enter */
    if (keycode == KC_ENT) return '\r';

    /* Space */
    if (keycode == KC_SPC) return ' ';

    /* Finnish ISO layout: special characters */
    if (!shifted) {
        switch (keycode) {
            case KC_MINS: return '+';
            case KC_SLSH: return '-';
            case KC_DOT:  return '.';
            case KC_COMM: return ',';
            case KC_NUBS: return '<';
        }
    } else {
        /* Shifted number row on Finnish layout:
         * 1=! 2=" 3=# 4=$ 5=% 6=& 7=/ 8=( 9=) 0== */
        if (keycode >= KC_1 && keycode <= KC_0) {
            static const char snums[] = "!\"#$%&/()=";
            return snums[keycode - KC_1];
        }
        switch (keycode) {
            case KC_MINS: return '?';
            case KC_SLSH: return '_';
            case KC_DOT:  return ':';
            case KC_COMM: return ';';
            case KC_NUBS: return '>';
        }
    }

    return 0;
}
