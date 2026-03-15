#pragma once
#include <stdint.h>
#include <stddef.h>

/* Public configuration constants — safe to read, do not modify */
#define KBV_MAGIC          0x5442564B  /* "KBVT" little-endian */
#define KBV_VERSION        1
#define KBV_MAX_SLOTS      5
#define KBV_MAX_PWD_LEN    128   /* max stored password length */
#define KBV_MAX_MASTER_LEN 64    /* max master/duress password length */

/*
 * Flash layout constants — exposed for platform implementors and tests.
 * Normal integrators (keymap.c) do not need these.
 */
#define KBV_HDR_SIZE       120
#define KBV_SLOT_SIZE      174
#define KBV_FLASH_TOTAL    (KBV_HDR_SIZE + KBV_MAX_SLOTS * KBV_SLOT_SIZE)  /* 990 bytes */

/* Header field offsets */
#define KBV_OFF_MAGIC      0x00
#define KBV_OFF_VERSION    0x04
#define KBV_OFF_SLOT_FLAGS 0x05
#define KBV_OFF_PEPPER     0x08   /* 32 bytes */
#define KBV_OFF_SALT       0x28   /* 16 bytes */
#define KBV_OFF_VERIFY_TAG 0x38   /* 32 bytes */
#define KBV_OFF_DURESS_TAG 0x58   /* 32 bytes */

/* Slot field offsets (from slot base) */
#define KBV_SLOT_OFF_NONCE  0x00  /* 12 bytes */
#define KBV_SLOT_OFF_CTLEN  0x0C  /* 1 byte */
#define KBV_SLOT_OFF_CT     0x0D  /* 128 bytes */
#define KBV_SLOT_OFF_TAG    0x8D  /* 32 bytes */

/* Vault states */
typedef enum {
    KBV_STATE_LOCKED = 0,
    KBV_STATE_AUTHING,
    KBV_STATE_UNLOCKED,   /* transparent: keyboard operates normally, no key capture */
    KBV_STATE_MENU,       /* interactive: key capture for vault management */
} kbv_state_t;

/* Error codes */
#define KBV_OK             0
#define KBV_ERR_CRYPTO    -1
#define KBV_ERR_FLASH     -2
#define KBV_ERR_PARAM     -3
#define KBV_ERR_UNSEEDED  -4

/*
 * Output callback: called when kbv wants to send text to the host.
 * Used for teletype-style UI output (prompts, status messages).
 * str is null-terminated.
 */
typedef void (*kbv_output_cb_t)(const char *str);

/*
 * Password typing callback: called when kbv wants to type a stored password
 * as HID keystrokes. str is null-terminated, max KBV_MAX_PWD_LEN bytes.
 * After this callback returns, the vault locks and keys are zeroed.
 */
typedef void (*kbv_type_cb_t)(const char *pwd, size_t len);

/*
 * Vault events — fired at significant state transitions.
 * Register a handler via kbv_init(); use NULL if not needed.
 */
typedef enum {
    KBV_EVENT_UNLOCKED,      /* auth success: AUTHING -> UNLOCKED        */
    KBV_EVENT_AUTH_FAILED,   /* wrong password: AUTHING -> LOCKED        */
    KBV_EVENT_LOCKED,        /* vault locked (kbv_lock or idle timeout)  */
    KBV_EVENT_SLOT_TYPED,    /* password typed via kbv_type_slot()       */
    KBV_EVENT_SLOT_EMPTY,    /* kbv_type_slot() called on empty slot     */
    KBV_EVENT_ENTROPY_LOW,   /* slot write refused: entropy below threshold */
    KBV_EVENT_WIPED,         /* vault wiped: kbv_clear() called — flash erased, re-init required */
} kbv_event_t;

typedef void (*kbv_event_cb_t)(kbv_event_t event);

/*
 * Vault context — allocate one of these as a static or global variable.
 * All key material lives here in SRAM and is zeroed on lock.
 *
 * The struct is intentionally public so integrators can allocate it without
 * malloc (important on MCUs). Treat all fields below as implementation details
 * — read slot_flags if you need occupancy info, otherwise use the API.
 * Do not modify fields directly; use kbv_* functions.
 */
typedef struct {
    kbv_state_t  state;
    kbv_output_cb_t output_cb;
    kbv_type_cb_t   type_cb;
    kbv_event_cb_t  event_cb;

    /* Active session key material (zeroed on lock) */
    uint8_t  prk[32];
    uint8_t  enc_key[KBV_MAX_SLOTS][32];
    uint8_t  mac_key[KBV_MAX_SLOTS][32];

    /* Cached from flash (not secret).
     * slot_flags: bit N set = slot N occupied (0-based). */
    uint8_t  bound_salt[32];
    uint8_t  slot_flags;

    /* Input accumulator — internal */
    char     input_buf[KBV_MAX_PWD_LEN + 4];
    uint8_t  input_len;

    /* Idle timeout — internal */
    uint32_t last_activity_ms;

    /* Brute-force throttle — internal */
    uint8_t  fail_count;
    uint32_t lockout_until_ms;

    /* Substate for multi-step commands — internal */
    uint8_t  cmd_state;
    uint8_t  cmd_slot;
    char     cmd_buf[KBV_MAX_PWD_LEN + 4];
    uint8_t  cmd_buf_len;
} kbv_ctx_t;

/*
 * Initialize vault. Reads flash, checks magic.
 * Callbacks must be set before calling this.
 */
void kbv_init(kbv_ctx_t *ctx, kbv_output_cb_t output_cb, kbv_type_cb_t type_cb, kbv_event_cb_t event_cb);

/*
 * Feed a character to the vault (from keypress capture).
 * When kbv_is_active() is true, the QMK glue calls this instead of
 * forwarding the keypress to the host.
 */
void kbv_feed_char(kbv_ctx_t *ctx, char c);

/*
 * Periodic tick — call from housekeeping_task_user() or similar.
 * Checks idle timeout and locks if expired.
 */
void kbv_tick(kbv_ctx_t *ctx);

/*
 * Returns 1 if the vault is in an active state (AUTHING or MENU).
 * When active, all keypresses must be routed to kbv_feed_char().
 * Returns 0 when LOCKED or UNLOCKED (transparent pass-through).
 */
int kbv_is_active(const kbv_ctx_t *ctx);

/*
 * Returns current vault state.
 */
kbv_state_t kbv_get_state(const kbv_ctx_t *ctx);

/*
 * Transition LOCKED -> AUTHING. No-op if already UNLOCKED or MENU.
 * Call when vault hotkey is pressed.
 */
void kbv_login(kbv_ctx_t *ctx);

/*
 * Transition UNLOCKED -> MENU. No-op if LOCKED or AUTHING.
 * Call when menu hotkey is pressed.
 */
void kbv_enter_menu(kbv_ctx_t *ctx);

/*
 * If UNLOCKED and slot is occupied: decrypt, type via type_cb, stay UNLOCKED.
 * No-op if LOCKED or in MENU. slot_idx is 0-based.
 */
void kbv_type_slot(kbv_ctx_t *ctx, uint8_t slot_idx);

/*
 * Lock vault immediately, zeroing all key material.
 */
void kbv_lock(kbv_ctx_t *ctx);

/*
 * Erase vault flash sector, zero all key material, fire KBV_EVENT_WIPED.
 * Callable from any state, including LOCKED (no auth required).
 * After this call the vault is in LOCKED state with no valid data in flash.
 * The next kbv_login() will detect the erased flash and enter new-vault setup.
 */
void kbv_clear(kbv_ctx_t *ctx);
