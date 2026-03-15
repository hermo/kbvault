/*
 * kbv_charmap_keycodes.h — QMK keycode stubs for host-side testing.
 *
 * These values match QMK's keycodes.h (HID usage codes).
 * Only used when compiling kbv_charmap.h outside of QMK.
 */
#pragma once
#include <stdint.h>

/* Basic keycodes (HID usage table) */
#define KC_A     0x04
#define KC_B     0x05
#define KC_C     0x06
#define KC_D     0x07
#define KC_E     0x08
#define KC_F     0x09
#define KC_G     0x0A
#define KC_H     0x0B
#define KC_I     0x0C
#define KC_J     0x0D
#define KC_K     0x0E
#define KC_L     0x0F
#define KC_M     0x10
#define KC_N     0x11
#define KC_O     0x12
#define KC_P     0x13
#define KC_Q     0x14
#define KC_R     0x15
#define KC_S     0x16
#define KC_T     0x17
#define KC_U     0x18
#define KC_V     0x19
#define KC_W     0x1A
#define KC_X     0x1B
#define KC_Y     0x1C
#define KC_Z     0x1D

#define KC_1     0x1E
#define KC_2     0x1F
#define KC_3     0x20
#define KC_4     0x21
#define KC_5     0x22
#define KC_6     0x23
#define KC_7     0x24
#define KC_8     0x25
#define KC_9     0x26
#define KC_0     0x27

#define KC_ENT   0x28
#define KC_BSPC  0x2A
#define KC_SPC   0x2C
#define KC_MINS  0x2D

#define KC_COMM  0x36
#define KC_DOT   0x37
#define KC_SLSH  0x38

#define KC_NUBS  0x64

/* Layer-tap range: 0x4000–0x4FFF */
#define QK_LAYER_TAP      0x4000
#define QK_LAYER_TAP_MAX  0x4FFF
#define IS_QK_LAYER_TAP(code)  ((code) >= QK_LAYER_TAP && (code) <= QK_LAYER_TAP_MAX)

/* Mod-tap range: 0x2000–0x3FFF */
#define QK_MOD_TAP        0x2000
#define QK_MOD_TAP_MAX    0x3FFF
#define IS_QK_MOD_TAP(code)    ((code) >= QK_MOD_TAP && (code) <= QK_MOD_TAP_MAX)
