/*
 * kbv.c — KBVault core implementation
 *
 * Covers:
 *   kbvault-8yf  Key derivation and authentication
 *   kbvault-7hs  Per-slot encrypt/decrypt (encrypt-then-MAC)
 *   kbvault-3bw  First-time vault initialization
 *   kbvault-0s6  State machine and command processing
 */

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "kbv.h"
#include "kbv_platform.h"
#include "hxcrypt.h"

/* ── Constants ──────────────────────────────────────────────────────────── */

/* Fire an event if event_cb is registered. */
#define FIRE(ctx, ev) do { if ((ctx)->event_cb) (ctx)->event_cb(ev); } while(0)

#define KBV_IDLE_TIMEOUT_MS   (120u * 60u * 1000u)
#define KBV_MIN_ENTROPY_BITS  256u
#define KBV_VAULT_DATA_SIZE   (KBV_HDR_SIZE + KBV_MAX_SLOTS * KBV_SLOT_SIZE)

/* Special cmd_state value: new vault awaiting initial master password. */
#define CMDSTATE_NEW_VAULT    10u

/* ── File-static storage for new-vault credentials ──────────────────────── */
/*
 * During a fresh-vault init, pepper and salt are generated in kbv_init()
 * and must survive until kbv_feed_char() commits them.  We keep them in
 * a zeroed static struct so they are wiped after use.
 */
static struct {
    uint8_t pepper[32];
    uint8_t salt[16];
    uint8_t valid; /* 1 while holding live credentials */
} s_new_vault;

/*
 * Scratch buffer for vault erase-and-rewrite operations (delete, re-key).
 * Holds up to the full vault data area (header + 5 slots = 990 bytes).
 *
 * SECURITY NOTE (kbvault-bea): During master password re-key (cmd_state 14),
 * this buffer temporarily holds decrypted plaintext passwords for all occupied
 * slots (Steps 1-5, ~11 ms window on STM32F401 @ 84 MHz).
 * (a) Plaintext lives here during Steps 1-5 of the re-key procedure.
 * (b) A warm reset during this window will expose plaintext in SRAM.
 * (c) This is an accepted risk given the ~11 ms window and RDP1 protection
 *     (SRAM is not accessible to debugger under RDP1).
 * (d) Step 6 zero (hx_explicit_zero) is unconditional and not skippable.
 * Outside of re-key, this buffer holds only encrypted bytes or header data.
 */
static uint8_t s_vault_buf[KBV_VAULT_DATA_SIZE];

/* ── Private helpers ────────────────────────────────────────────────────── */

/*
 * Store a 32-bit value as four little-endian bytes.
 */
static void put_le32(uint8_t *buf, uint32_t v)
{
    buf[0] = (uint8_t)(v        & 0xFFu);
    buf[1] = (uint8_t)((v >>  8) & 0xFFu);
    buf[2] = (uint8_t)((v >> 16) & 0xFFu);
    buf[3] = (uint8_t)((v >> 24) & 0xFFu);
}

/*
 * Load a 32-bit little-endian value from four bytes.
 */
static uint32_t get_le32(const uint8_t *buf)
{
    return (uint32_t)buf[0]
         | ((uint32_t)buf[1] <<  8)
         | ((uint32_t)buf[2] << 16)
         | ((uint32_t)buf[3] << 24);
}

/*
 * Compute bound_salt = BLAKE2s(salt[16], key = BLAKE2s(uid[12] || pepper[32])).
 *
 * This binds the derived keys to the specific device UID and the stored
 * per-vault pepper, preventing migration of the vault image to another device.
 */
static void compute_bound_salt(uint8_t bound_salt[32],
                                const uint8_t pepper[32],
                                const uint8_t salt[16])
{
    uint8_t uid[12];
    uint8_t uid_pepper[44];
    uint8_t uid_pepper_key[32];

    kbv_plat_get_uid(uid);

    memcpy(uid_pepper,      uid,    12);
    memcpy(uid_pepper + 12, pepper, 32);

    /* Hash uid||pepper to produce a 32-byte BLAKE2s key */
    hx_blake2s(uid_pepper_key, 32, uid_pepper, 44, NULL, 0);

    /* bound_salt = BLAKE2s(salt, key = uid_pepper_key) */
    hx_blake2s(bound_salt, 32, salt, 16, uid_pepper_key, 32);

    hx_explicit_zero(uid_pepper,     sizeof(uid_pepper));
    hx_explicit_zero(uid_pepper_key, sizeof(uid_pepper_key));
}

/*
 * Derive PRK from password + ctx->bound_salt via PBKDF2-BLAKE2s, then
 * expand into per-slot enc/mac keys via HKDF-Expand-BLAKE2s.
 * All results are stored directly in ctx.
 */
static void derive_prk_and_keys(kbv_ctx_t *ctx,
                                 const char *pwd, uint8_t pwdlen)
{
    uint8_t info[4];

    hx_pbkdf2_blake2s(ctx->prk, 32,
                      pwd, pwdlen,
                      ctx->bound_salt, 32,
                      4096);

    for (int i = 0; i < KBV_MAX_SLOTS; i++) {
        memcpy(info, "enc", 3); info[3] = (uint8_t)i;
        hx_hkdf_expand_blake2s(ctx->enc_key[i], 32, ctx->prk, info, 4);

        memcpy(info, "mac", 3); info[3] = (uint8_t)i;
        hx_hkdf_expand_blake2s(ctx->mac_key[i], 32, ctx->prk, info, 4);
    }
}

/*
 * Write a block of data to flash at the given byte offset.
 */
static void flash_write_field(uint32_t off, const uint8_t *data, size_t len)
{
    kbv_plat_flash_write(off, data, len);
}

/*
 * Write ctx->slot_flags back to its flash position.
 */
static void update_slot_flags(kbv_ctx_t *ctx)
{
    /*
     * NOR flash bit semantics: erased = 1, programmed = 0.
     * We store the inverted slot_flags so that setting a slot (1→occupied)
     * maps to clearing a bit in flash (1→0), which NOR flash allows without
     * an erase cycle.  Clearing a slot requires an erase (handled by
     * delete_slot's full sector rewrite).
     */
    uint8_t raw = (uint8_t)(~ctx->slot_flags);
    flash_write_field(KBV_OFF_SLOT_FLAGS, &raw, 1);
}

/*
 * Encrypt plaintext into flash slot slot_idx.
 *
 * Flash slot layout (relative to slot base address):
 *   +0x00  nonce   (12 bytes, fresh random per write)
 *   +0x0C  ct_len  (1 byte, 1..128)
 *   +0x0D  ct      (128 bytes, zero-padded to capacity)
 *   +0x8D  mac_tag (32 bytes, BLAKE2s(nonce||ct[0..ct_len-1], key=mac_key))
 *
 * Scheme: Encrypt-then-MAC using ChaCha20 + keyed BLAKE2s.
 */
static void write_slot(kbv_ctx_t *ctx,
                        uint8_t slot_idx,
                        const char *pwd, uint8_t pwdlen)
{
    uint32_t slot_base = KBV_HDR_SIZE + (uint32_t)slot_idx * KBV_SLOT_SIZE;

    uint8_t nonce[12];
    uint8_t ct[KBV_MAX_PWD_LEN];
    uint8_t ct_padded[KBV_MAX_PWD_LEN];
    uint8_t mac_input[12 + KBV_MAX_PWD_LEN];
    uint8_t mac_tag[32];

    kbv_plat_random(nonce, 12);

    hx_chacha20_xor(ct, (const uint8_t *)pwd, pwdlen,
                    ctx->enc_key[slot_idx], nonce, 0);

    memset(ct_padded, 0, sizeof(ct_padded));
    memcpy(ct_padded, ct, pwdlen);

    /* MAC covers nonce || ct[0..pwdlen-1] */
    memcpy(mac_input,      nonce, 12);
    memcpy(mac_input + 12, ct,    pwdlen);
    hx_blake2s(mac_tag, 32, mac_input, (size_t)(12 + pwdlen),
               ctx->mac_key[slot_idx], 32);

    /*
     * NOR flash AND semantics: the target slot area must be all 0xFF before
     * we can write arbitrary (random) bytes.  After a delete_slot(), the slot
     * area is zeroed in the snapshot and flushed to flash, leaving 0x00 bytes
     * that cannot be overwritten without an erase.
     *
     * Check whether the slot area is clean.  If any byte is not 0xFF we must
     * snapshot the full vault, erase the sector, and rewrite everything.
     */
    uint8_t slot_sample[12];
    int needs_erase = 0;
    if (kbv_plat_flash_read(slot_base, slot_sample, 12) == 0) {
        for (int si = 0; si < 12; si++) {
            if (slot_sample[si] != 0xFF) { needs_erase = 1; break; }
        }
    }

    if (needs_erase) {
        /* Snapshot the live vault, clear the target slot, erase, rewrite. */
        kbv_plat_flash_read(0, s_vault_buf, KBV_VAULT_DATA_SIZE);
        memset(s_vault_buf + slot_base, 0xFF, KBV_SLOT_SIZE);
        /* Patch in the new slot data */
        memcpy(s_vault_buf + slot_base + KBV_SLOT_OFF_NONCE, nonce,    12);
        s_vault_buf[slot_base + KBV_SLOT_OFF_CTLEN] = pwdlen;
        memcpy(s_vault_buf + slot_base + KBV_SLOT_OFF_CT,    ct_padded, KBV_MAX_PWD_LEN);
        memcpy(s_vault_buf + slot_base + KBV_SLOT_OFF_TAG,   mac_tag,  32);
        /* Update slot_flags in snapshot (NOR-inverted) */
        ctx->slot_flags |= (uint8_t)(1u << slot_idx);
        s_vault_buf[KBV_OFF_SLOT_FLAGS] = (uint8_t)(~ctx->slot_flags);
        kbv_plat_flash_erase();
        kbv_plat_flash_write(0, s_vault_buf, KBV_VAULT_DATA_SIZE);
        hx_explicit_zero(s_vault_buf, KBV_VAULT_DATA_SIZE);
    } else {
        kbv_plat_flash_write(slot_base + KBV_SLOT_OFF_NONCE, nonce,    12);
        kbv_plat_flash_write(slot_base + KBV_SLOT_OFF_CTLEN, &pwdlen,  1);
        kbv_plat_flash_write(slot_base + KBV_SLOT_OFF_CT,    ct_padded, KBV_MAX_PWD_LEN);
        kbv_plat_flash_write(slot_base + KBV_SLOT_OFF_TAG,   mac_tag,  32);
        ctx->slot_flags |= (uint8_t)(1u << slot_idx);
        update_slot_flags(ctx);
    }

    hx_explicit_zero(ct,        sizeof(ct));
    hx_explicit_zero(ct_padded, sizeof(ct_padded));
    hx_explicit_zero(mac_input, sizeof(mac_input));
    hx_explicit_zero(mac_tag,   sizeof(mac_tag));
}

/*
 * Decrypt flash slot slot_idx, verify MAC, and type the plaintext via
 * ctx->type_cb.  Does NOT lock the vault.
 * On MAC failure the plaintext is never exposed.
 */
static void decrypt_and_type(kbv_ctx_t *ctx, uint8_t slot_idx)
{
    uint32_t slot_base = KBV_HDR_SIZE + (uint32_t)slot_idx * KBV_SLOT_SIZE;

    uint8_t nonce[12];
    uint8_t ct_len_byte;
    uint8_t ct[KBV_MAX_PWD_LEN];
    uint8_t stored_tag[32];
    uint8_t computed_tag[32];
    uint8_t mac_input[12 + KBV_MAX_PWD_LEN];
    uint8_t plaintext[KBV_MAX_PWD_LEN + 1];

    kbv_plat_flash_read(slot_base + KBV_SLOT_OFF_NONCE, nonce,        12);
    kbv_plat_flash_read(slot_base + KBV_SLOT_OFF_CTLEN, &ct_len_byte, 1);
    kbv_plat_flash_read(slot_base + KBV_SLOT_OFF_CT,    ct,           KBV_MAX_PWD_LEN);
    kbv_plat_flash_read(slot_base + KBV_SLOT_OFF_TAG,   stored_tag,   32);

    uint8_t ct_len = ct_len_byte;

    if (ct_len == 0 || ct_len > KBV_MAX_PWD_LEN) {
        hx_explicit_zero(ct, sizeof(ct));
        return;
    }

    memcpy(mac_input,      nonce, 12);
    memcpy(mac_input + 12, ct,    ct_len);
    hx_blake2s(computed_tag, 32, mac_input, (size_t)(12 + ct_len),
               ctx->mac_key[slot_idx], 32);

    if (!hx_ct_equal(computed_tag, stored_tag, 32)) {
        hx_explicit_zero(ct,           sizeof(ct));
        hx_explicit_zero(computed_tag, sizeof(computed_tag));
        hx_explicit_zero(mac_input,    sizeof(mac_input));
        return;
    }

    hx_chacha20_xor(plaintext, ct, ct_len,
                    ctx->enc_key[slot_idx], nonce, 0);
    plaintext[ct_len] = '\0';

    ctx->type_cb((const char *)plaintext, ct_len);

    hx_explicit_zero(plaintext,    sizeof(plaintext));
    hx_explicit_zero(ct,           sizeof(ct));
    hx_explicit_zero(computed_tag, sizeof(computed_tag));
    hx_explicit_zero(mac_input,    sizeof(mac_input));
}

/*
 * Delete a slot: erase the flash sector and rewrite all remaining data.
 *
 * NOR flash cannot flip bits from 0→1 without an erase.  Clearing a slot's
 * occupancy bit (previously 0 = occupied in flash) requires a full erase.
 * We snapshot the entire vault area, zero the target slot, then erase and
 * rewrite.  The non-deleted slots are raw encrypted bytes — no key material
 * is exposed.
 */
static void delete_slot(kbv_ctx_t *ctx, uint8_t slot_idx)
{
    /* Snapshot the live vault area */
    kbv_plat_flash_read(0, s_vault_buf, KBV_VAULT_DATA_SIZE);

    /* Zero the deleted slot in the snapshot */
    uint32_t slot_base = KBV_HDR_SIZE + (uint32_t)slot_idx * KBV_SLOT_SIZE;
    memset(s_vault_buf + slot_base, 0, KBV_SLOT_SIZE);

    /* Update slot_flags in memory and in the snapshot (NOR-inverted) */
    ctx->slot_flags &= (uint8_t)~(uint8_t)(1u << slot_idx);
    s_vault_buf[KBV_OFF_SLOT_FLAGS] = (uint8_t)(~ctx->slot_flags);

    /* Erase sector and rewrite */
    kbv_plat_flash_erase();
    kbv_plat_flash_write(0, s_vault_buf, KBV_VAULT_DATA_SIZE);

    hx_explicit_zero(s_vault_buf, KBV_VAULT_DATA_SIZE);
}

/* ── Input accumulation helpers ─────────────────────────────────────────── */

static void input_reset(kbv_ctx_t *ctx)
{
    hx_explicit_zero(ctx->input_buf, sizeof(ctx->input_buf));
    ctx->input_len = 0;
}

static void input_append(kbv_ctx_t *ctx, char c, uint8_t max_len)
{
    if (c == '\b') {
        if (ctx->input_len > 0) {
            ctx->input_buf[--ctx->input_len] = '\0';
        }
        return;
    }
    if (ctx->input_len < max_len) {
        ctx->input_buf[ctx->input_len++] = c;
    }
    /* Silently drop when buffer is full */
}

static int is_enter(char c)
{
    return (c == '\r') || (c == '\n');
}

/* ── AUTHING helpers ────────────────────────────────────────────────────── */

/*
 * Normal unlock attempt: derive keys from the accumulated input and compare
 * verify_tag / duress_tag against flash.
 */
static void authing_try_unlock(kbv_ctx_t *ctx)
{
    uint8_t computed_verify[32];
    uint8_t computed_duress[32];
    uint8_t stored_verify[32];
    uint8_t stored_duress[32];

    derive_prk_and_keys(ctx, ctx->input_buf, ctx->input_len);

    hx_blake2s(computed_verify, 32, "kbv.verify", 10, ctx->prk, 32);

    kbv_plat_flash_read(KBV_OFF_VERIFY_TAG, stored_verify, 32);
    kbv_plat_flash_read(KBV_OFF_DURESS_TAG, stored_duress, 32);

    /* Zero input before any branch so it is never reachable after this */
    hx_explicit_zero(ctx->input_buf, sizeof(ctx->input_buf));
    ctx->input_len = 0;

    if (hx_ct_equal(computed_verify, stored_verify, 32)) {
        ctx->state            = KBV_STATE_UNLOCKED;
        ctx->cmd_state        = 0;
        ctx->last_activity_ms = kbv_plat_time_ms();
        ctx->fail_count       = 0;
        ctx->lockout_until_ms = 0;
        /* No text output — RGB handles visual feedback */
        FIRE(ctx, KBV_EVENT_UNLOCKED);
    } else {
        /* Compute duress tag from the same PRK */
        hx_blake2s(computed_duress, 32, "kbv.duress", 10, ctx->prk, 32);

        if (hx_ct_equal(computed_duress, stored_duress, 32)) {
            /* Duress: wipe flash, then lock (erase first while keys in SRAM) */
            kbv_plat_flash_erase();
            kbv_lock(ctx);           /* zeroes key material, fires KBV_EVENT_LOCKED */
            ctx->slot_flags = 0;     /* reflect erased flash */
        } else {
            /* Wrong password: apply exponential backoff lockout.
             * Delay schedule: 1s, 2s, 4s, 8s, 16s, 30s cap.
             * Formula: min(1000 << (fail_count-1), 30000). */
            if (ctx->fail_count < 255)
                ctx->fail_count++;
            uint8_t shift = ctx->fail_count - 1;
            if (shift > 5) shift = 5;  /* cap shift to avoid overflow */
            uint32_t delay = 1000u << shift;
            if (delay > 30000u) delay = 30000u;
            ctx->lockout_until_ms = kbv_plat_time_ms() + delay;

            FIRE(ctx, KBV_EVENT_AUTH_FAILED);
            kbv_lock(ctx);
        }

        hx_explicit_zero(computed_duress, sizeof(computed_duress));
    }

    hx_explicit_zero(computed_verify, sizeof(computed_verify));
}

/*
 * New-vault commit: write the full 120-byte header and unlock.
 * Called on Enter when cmd_state == CMDSTATE_NEW_VAULT.
 */
static void authing_new_vault_commit(kbv_ctx_t *ctx)
{
    uint8_t verify_tag[32];
    uint8_t hdr[KBV_HDR_SIZE];

    if (kbv_plat_entropy_bits() < KBV_MIN_ENTROPY_BITS) {
        ctx->output_cb("low entropy\n");
        FIRE(ctx, KBV_EVENT_ENTROPY_LOW);
        ctx->state = KBV_STATE_LOCKED;
        hx_explicit_zero(ctx->input_buf, sizeof(ctx->input_buf));
        ctx->input_len = 0;
        return;
    }

    if (ctx->input_len < KBV_MIN_MASTER_LEN) {
        input_reset(ctx);
        ctx->output_cb("too short\npw?\n");
        return;
    }

    derive_prk_and_keys(ctx, ctx->input_buf, ctx->input_len);

    hx_blake2s(verify_tag, 32, "kbv.verify", 10, ctx->prk, 32);

    memset(hdr, 0, sizeof(hdr));

    /* [0x00..0x03] magic, little-endian */
    put_le32(hdr + KBV_OFF_MAGIC, KBV_MAGIC);

    /* [0x04] version */
    hdr[KBV_OFF_VERSION] = KBV_VERSION;

    /* [0x05] slot_flags: NOR-flash inverted; 0xFF = all slots empty (erased) */
    hdr[KBV_OFF_SLOT_FLAGS] = 0xFF;

    /* [0x06..0x07] reserved — already zero */

    /* [0x08..0x27] pepper (32 bytes) */
    memcpy(hdr + KBV_OFF_PEPPER, s_new_vault.pepper, 32);

    /* [0x28..0x37] salt (16 bytes) */
    memcpy(hdr + KBV_OFF_SALT, s_new_vault.salt, 16);

    /* [0x38..0x57] verify_tag (32 bytes) */
    memcpy(hdr + KBV_OFF_VERIFY_TAG, verify_tag, 32);

    /* [0x58..0x77] duress_tag — all zeros (not configured yet) */

    kbv_plat_flash_write(0, hdr, KBV_HDR_SIZE);

    ctx->slot_flags       = 0;
    ctx->state            = KBV_STATE_UNLOCKED;
    ctx->cmd_state        = 0;
    ctx->last_activity_ms = kbv_plat_time_ms();

    hx_explicit_zero(ctx->input_buf, sizeof(ctx->input_buf));
    ctx->input_len = 0;
    hx_explicit_zero(verify_tag, sizeof(verify_tag));
    hx_explicit_zero(hdr, sizeof(hdr));

    /* Wipe the temporary new-vault credentials */
    hx_explicit_zero(&s_new_vault, sizeof(s_new_vault));

    /* Confirm vault creation; vault is now silently UNLOCKED */
    ctx->output_cb("ok\n");
}

/* ── MENU settings sub-state ────────────────────────────────────────────── */
/* cmd_state values 10-19 are used for settings sub-commands within MENU.   */
/* Entry point: cmd_state=10 (set by 's' command in menu_feed cmd_state 0). */

static void settings_feed(kbv_ctx_t *ctx, char c)
{
    switch (ctx->cmd_state) {

    /* ── cmd_state 10: waiting for settings command ─────────────────────── */
    case 10:
        switch (c) {
        case 'p':
            input_reset(ctx);
            ctx->cmd_state = 11;
            ctx->output_cb("new pw?\n");
            break;
        case 'd':
            input_reset(ctx);
            ctx->cmd_state = 12;
            ctx->output_cb("new duress?\n");
            break;
        case 'c':
            ctx->cmd_state = 13;
            ctx->output_cb("c? y/n\n");
            break;
        case 'b':
            /* Back to MENU top-level */
            ctx->cmd_state = 0;
            ctx->output_cb("kbv: ");
            break;
        default:
            break;
        }
        break;

    /* ── cmd_state 11: change master — accumulate new password ──────────── */
    case 11:
        if (is_enter(c)) {
            if (ctx->input_len < KBV_MIN_MASTER_LEN) {
                input_reset(ctx);
                ctx->cmd_state = 10;
                ctx->output_cb("too short\nkbv: ");
                break;
            }
            /* Save to cmd_buf and ask for confirmation */
            memcpy(ctx->cmd_buf, ctx->input_buf, ctx->input_len);
            ctx->cmd_buf_len = ctx->input_len;
            input_reset(ctx);
            ctx->cmd_state = 14;
            ctx->output_cb("confirm?\n");
        } else {
            input_append(ctx, c, KBV_MAX_MASTER_LEN);
        }
        break;

    /* ── cmd_state 14: change master — confirm new password ─────────────── */
    case 14:
        if (is_enter(c)) {
            if (ctx->input_len == ctx->cmd_buf_len &&
                hx_ct_equal(ctx->input_buf, ctx->cmd_buf, ctx->input_len))
            {
                /* Entropy guard: re-key generates fresh nonces via write_slot,
                 * so we need sufficient entropy before proceeding. */
                if (kbv_plat_entropy_bits() < KBV_MIN_ENTROPY_BITS) {
                    ctx->output_cb("low entropy\nkbv: ");
                    FIRE(ctx, KBV_EVENT_ENTROPY_LOW);
                    hx_explicit_zero(ctx->input_buf, sizeof(ctx->input_buf));
                    ctx->input_len = 0;
                    hx_explicit_zero(ctx->cmd_buf, sizeof(ctx->cmd_buf));
                    ctx->cmd_buf_len = 0;
                    ctx->cmd_state = 0;
                    break;
                }

                /*
                 * Re-key all occupied slots under the new master password.
                 *
                 * NOR flash cannot overwrite ciphertext in-place (AND semantics
                 * would corrupt the data).  Strategy:
                 *   1. Decrypt all occupied slots with the CURRENT keys.
                 *      Plaintexts are stored in s_vault_buf (static BSS)
                 *      to avoid a ~640-byte stack allocation that would
                 *      overflow the 1536-byte ChibiOS process stack on MCU.
                 *   2. Derive new PRK + keys from new password.
                 *   3. Build new header in a local hdr[], patch verify_tag.
                 *   4. Erase flash sector; rewrite patched header.
                 *   5. Re-encrypt and write all slots (new keys, pts from s_vault_buf).
                 *   6. Zero s_vault_buf.
                 *
                 * s_vault_buf is safe for pts during step 5: after the full
                 * erase in step 4, every slot area is 0xFF, so write_slot's
                 * needs_erase check returns 0 and write_slot never touches
                 * s_vault_buf itself.
                 */

                /* Zero s_vault_buf before use (in case of stale content) */
                hx_explicit_zero(s_vault_buf, (size_t)KBV_MAX_SLOTS * KBV_MAX_PWD_LEN);

                /*
                 * Step 1 — decrypt all occupied slots into s_vault_buf.
                 * PLAINTEXT WINDOW BEGINS HERE (kbvault-bea): s_vault_buf
                 * now holds live plaintext until Step 6 zeroes it.
                 * A warm reset between Steps 1 and 6 will expose plaintext
                 * in SRAM; accepted risk under RDP1 + ~11 ms window.
                 *
                 * pts is a pointer-to-array view into s_vault_buf so that
                 * pts[i] addresses the i-th KBV_MAX_PWD_LEN-byte block.
                 */
                uint8_t (*pts)[KBV_MAX_PWD_LEN] =
                    (uint8_t (*)[KBV_MAX_PWD_LEN])(void *)s_vault_buf;
                uint8_t pt_lens[KBV_MAX_SLOTS];
                memset(pt_lens, 0, sizeof(pt_lens));

                for (int i = 0; i < KBV_MAX_SLOTS; i++) {
                    if (!(ctx->slot_flags & (uint8_t)(1u << i))) continue;

                    uint32_t slot_base = KBV_HDR_SIZE + (uint32_t)i * KBV_SLOT_SIZE;
                    uint8_t  nonce[12], ct[KBV_MAX_PWD_LEN];
                    uint8_t  ct_len_byte, stored_tag[32], computed_tag[32];
                    uint8_t  mac_in[12 + KBV_MAX_PWD_LEN];

                    kbv_plat_flash_read(slot_base + KBV_SLOT_OFF_NONCE,  nonce,        12);
                    kbv_plat_flash_read(slot_base + KBV_SLOT_OFF_CTLEN, &ct_len_byte,   1);
                    kbv_plat_flash_read(slot_base + KBV_SLOT_OFF_CT,     ct, KBV_MAX_PWD_LEN);
                    kbv_plat_flash_read(slot_base + KBV_SLOT_OFF_TAG,    stored_tag,   32);

                    uint8_t ct_len = ct_len_byte;
                    if (ct_len == 0 || ct_len > KBV_MAX_PWD_LEN) {
                        hx_explicit_zero(ct, sizeof(ct));
                        continue;
                    }

                    memcpy(mac_in,      nonce, 12);
                    memcpy(mac_in + 12, ct,    ct_len);
                    hx_blake2s(computed_tag, 32, mac_in, (size_t)(12 + ct_len),
                               ctx->mac_key[i], 32);

                    if (!hx_ct_equal(computed_tag, stored_tag, 32)) {
                        hx_explicit_zero(ct,           sizeof(ct));
                        hx_explicit_zero(computed_tag, sizeof(computed_tag));
                        hx_explicit_zero(mac_in,       sizeof(mac_in));
                        continue; /* corrupt slot — skip */
                    }

                    hx_chacha20_xor(pts[i], ct, ct_len, ctx->enc_key[i], nonce, 0);
                    pt_lens[i] = ct_len;

                    hx_explicit_zero(nonce,        sizeof(nonce));
                    hx_explicit_zero(ct,           sizeof(ct));
                    hx_explicit_zero(stored_tag,   sizeof(stored_tag));
                    hx_explicit_zero(computed_tag, sizeof(computed_tag));
                    hx_explicit_zero(mac_in,       sizeof(mac_in));
                }

                /* Step 2 — derive new PRK + per-slot keys */
                derive_prk_and_keys(ctx, ctx->cmd_buf, ctx->cmd_buf_len);

                /* Step 3 — build new header in local hdr[], patch verify_tag */
                uint8_t hdr[KBV_HDR_SIZE];
                kbv_plat_flash_read(0, hdr, KBV_HDR_SIZE);
                uint8_t new_verify[32];
                hx_blake2s(new_verify, 32, "kbv.verify", 10, ctx->prk, 32);
                memcpy(hdr + KBV_OFF_VERIFY_TAG, new_verify, 32);
                hdr[KBV_OFF_SLOT_FLAGS] = 0xFF; /* erased; write_slot updates */
                hx_explicit_zero(new_verify, sizeof(new_verify));

                /* Step 4 — erase sector, rewrite patched header */
                kbv_plat_flash_erase();
                kbv_plat_flash_write(0, hdr, KBV_HDR_SIZE);
                hx_explicit_zero(hdr, sizeof(hdr));

                /* Step 5 — re-encrypt all slots with new keys */
                for (int i = 0; i < KBV_MAX_SLOTS; i++) {
                    if (pt_lens[i] == 0) continue;
                    write_slot(ctx, (uint8_t)i, (const char *)pts[i], pt_lens[i]);
                }

                /*
                 * Step 6 — zero the plaintext portion of s_vault_buf.
                 * PLAINTEXT WINDOW ENDS HERE (kbvault-bea).
                 * This zero is unconditional and not skippable.
                 */
                hx_explicit_zero(s_vault_buf, (size_t)KBV_MAX_SLOTS * KBV_MAX_PWD_LEN);
                memset(pt_lens, 0, sizeof(pt_lens));

                ctx->output_cb("ok\nkbv: ");
                ctx->cmd_state = 0;
            } else {
                ctx->output_cb("mismatch\nkbv: ");
                ctx->cmd_state = 0;
            }

            hx_explicit_zero(ctx->input_buf, sizeof(ctx->input_buf));
            ctx->input_len = 0;
            hx_explicit_zero(ctx->cmd_buf,   sizeof(ctx->cmd_buf));
            ctx->cmd_buf_len = 0;
        } else {
            input_append(ctx, c, KBV_MAX_MASTER_LEN);
        }
        break;

    /* ── cmd_state 12: change duress — accumulate new duress password ───── */
    case 12:
        if (is_enter(c)) {
            memcpy(ctx->cmd_buf, ctx->input_buf, ctx->input_len);
            ctx->cmd_buf_len = ctx->input_len;
            input_reset(ctx);
            ctx->cmd_state = 15;
            ctx->output_cb("confirm?\n");
        } else {
            input_append(ctx, c, KBV_MAX_MASTER_LEN);
        }
        break;

    /* ── cmd_state 15: change duress — confirm ──────────────────────────── */
    case 15:
        if (is_enter(c)) {
            if (ctx->input_len == ctx->cmd_buf_len &&
                hx_ct_equal(ctx->input_buf, ctx->cmd_buf, ctx->input_len))
            {
                uint8_t duress_prk[32];
                uint8_t duress_tag[32];

                hx_pbkdf2_blake2s(duress_prk, 32,
                                  ctx->cmd_buf, ctx->cmd_buf_len,
                                  ctx->bound_salt, 32,
                                  4096);
                hx_blake2s(duress_tag, 32, "kbv.duress", 10, duress_prk, 32);

                /*
                 * NOR flash AND semantics: the duress_tag field is initially
                 * written as all-zeros (not configured) and cannot be
                 * overwritten in-place with arbitrary bytes.  Snapshot the
                 * full vault, patch in the duress_tag, erase, and rewrite.
                 */
                kbv_plat_flash_read(0, s_vault_buf, KBV_VAULT_DATA_SIZE);
                memcpy(s_vault_buf + KBV_OFF_DURESS_TAG, duress_tag, 32);
                kbv_plat_flash_erase();
                kbv_plat_flash_write(0, s_vault_buf, KBV_VAULT_DATA_SIZE);
                hx_explicit_zero(s_vault_buf, KBV_VAULT_DATA_SIZE);

                hx_explicit_zero(duress_prk, sizeof(duress_prk));
                hx_explicit_zero(duress_tag, sizeof(duress_tag));

                ctx->output_cb("ok\nkbv: ");
                ctx->cmd_state = 0;
            } else {
                ctx->output_cb("mismatch\nkbv: ");
                ctx->cmd_state = 0;
            }

            hx_explicit_zero(ctx->input_buf, sizeof(ctx->input_buf));
            ctx->input_len = 0;
            hx_explicit_zero(ctx->cmd_buf,   sizeof(ctx->cmd_buf));
            ctx->cmd_buf_len = 0;
        } else {
            input_append(ctx, c, KBV_MAX_MASTER_LEN);
        }
        break;

    /* ── cmd_state 13: clear vault — awaiting y/n ──────────────────────── */
    case 13:
        if (c == 'y') {
            kbv_plat_flash_erase();
            kbv_lock(ctx);           /* zeroes key material, fires KBV_EVENT_LOCKED */
            ctx->slot_flags = 0;     /* reflect erased flash */
            /* No text output — RGB handles feedback */
        } else if (c == 'n') {
            ctx->output_cb("n\nkbv: ");
            ctx->cmd_state = 0;
        }
        /* else: ignore */
        break;

    default:
        ctx->cmd_state = 0;
        break;
    }
}

/* ── Small helpers ──────────────────────────────────────────────────────── */

/* Format a uint16_t as decimal into buf; returns pointer past last digit. */
static char *fmt_u16(char *p, uint16_t n)
{
    char tmp[5];
    uint8_t d = 0;
    if (n == 0) { *p++ = '0'; return p; }
    while (n) { tmp[d++] = (char)('0' + (uint8_t)(n % 10u)); n = (uint16_t)(n / 10u); }
    while (d) *p++ = tmp[--d];
    return p;
}

/* ── MENU state ─────────────────────────────────────────────────────────── */
/* cmd_state 0-9: top-level menu commands.                                  */
/* cmd_state 10+: settings sub-commands (dispatched to settings_feed).      */

static void menu_feed(kbv_ctx_t *ctx, char c)
{
    /* Delegate settings sub-states to settings_feed */
    if (ctx->cmd_state >= 10) {
        settings_feed(ctx, c);
        return;
    }

    switch (ctx->cmd_state) {

    /* ── cmd_state 0: waiting for command ──────────────────────────────── */
    case 0:
        switch (c) {
        case 'l': {
            /* "1:X 2:X 3:X 4:X 5:X\n" */
            char line[24];
            char *p = line;
            for (int i = 0; i < KBV_MAX_SLOTS; i++) {
                if (i > 0) *p++ = ' ';
                *p++ = (char)('1' + i);
                *p++ = ':';
                *p++ = (ctx->slot_flags & (uint8_t)(1u << i)) ? '*' : '.';
            }
            *p++ = '\n';
            *p   = '\0';
            ctx->output_cb(line);
            ctx->output_cb("kbv: ");
            break;
        }
        case '1': case '2': case '3': case '4': case '5': {
            uint8_t idx = (uint8_t)(c - '1');
            if (ctx->slot_flags & (uint8_t)(1u << idx)) {
                decrypt_and_type(ctx, idx);
                ctx->output_cb("ok\n");
            } else {
                ctx->output_cb("empty\n");
            }
            ctx->output_cb("kbv: ");
            break;
        }
        case 's':
            ctx->cmd_state = 10;
            ctx->output_cb("p=pass d=duress c=clear b=back\nkbv: ");
            break;
        case 'q':
            ctx->output_cb("bye\n");
            ctx->state     = KBV_STATE_UNLOCKED;
            ctx->cmd_state = 0;
            break;
        case 'h':
            ctx->output_cb("l=list e=edit d=del s=set i=info q=exit h=help\nkbv: ");
            break;
        case 'i': {
            /* "ent:NNNNb 1:X 2:X 3:X 4:X 5:X\n" — max 31 chars + NUL */
            char line[32];
            char *p = line;
            *p++ = 'e'; *p++ = 'n'; *p++ = 't'; *p++ = ':';
            p = fmt_u16(p, kbv_plat_entropy_bits());
            *p++ = 'b'; *p++ = ' ';
            for (int i = 0; i < KBV_MAX_SLOTS; i++) {
                if (i) *p++ = ' ';
                *p++ = (char)('1' + i);
                *p++ = ':';
                *p++ = (ctx->slot_flags & (uint8_t)(1u << i)) ? '*' : '.';
            }
            *p++ = '\n';
            *p   = '\0';
            ctx->output_cb(line);
            ctx->output_cb("kbv: ");
            break;
        }
        case 'e':
            ctx->cmd_state = 1;
            ctx->output_cb("slot?\n");
            break;
        case 'd':
            ctx->cmd_state = 2;
            ctx->output_cb("slot?\n");
            break;
        default:
            break;
        }
        break;

    /* ── cmd_state 1: edit — waiting for slot digit ─────────────────────── */
    case 1:
        if (c >= '1' && c <= '5') {
            ctx->cmd_slot  = (uint8_t)(c - '1');
            ctx->cmd_state = 3;
            input_reset(ctx);
            ctx->output_cb("pw?\n");
        } else {
            ctx->cmd_state = 0;
        }
        break;

    /* ── cmd_state 2: delete — waiting for slot digit ───────────────────── */
    case 2:
        if (c >= '1' && c <= '5') {
            ctx->cmd_slot  = (uint8_t)(c - '1');
            ctx->cmd_state = 4;
            char msg[9];
            msg[0] = 'd';
            msg[1] = c;
            msg[2] = '?';
            msg[3] = ' ';
            msg[4] = 'y';
            msg[5] = '/';
            msg[6] = 'n';
            msg[7] = '\n';
            msg[8] = '\0';
            ctx->output_cb(msg);
        } else {
            ctx->cmd_state = 0;
        }
        break;

    /* ── cmd_state 3: edit — accumulating new password for slot ────────── */
    case 3:
        if (is_enter(c)) {
            if (ctx->input_len > 0) {
                if (kbv_plat_entropy_bits() >= KBV_MIN_ENTROPY_BITS) {
                    write_slot(ctx, ctx->cmd_slot,
                               ctx->input_buf, ctx->input_len);
                    ctx->output_cb("ok\nkbv: ");
                } else {
                    ctx->output_cb("low entropy\nkbv: ");
                    FIRE(ctx, KBV_EVENT_ENTROPY_LOW);
                }
            } else {
                ctx->output_cb("kbv: ");
            }
            input_reset(ctx);
            ctx->cmd_state = 0;
        } else {
            input_append(ctx, c, KBV_MAX_PWD_LEN);
        }
        break;

    /* ── cmd_state 4: delete — awaiting y/n ────────────────────────────── */
    case 4:
        if (c == 'y') {
            delete_slot(ctx, ctx->cmd_slot);
            ctx->cmd_state = 0;
            ctx->output_cb("ok\nkbv: ");
        } else if (c == 'n') {
            ctx->cmd_state = 0;
            ctx->output_cb("n\nkbv: ");
        }
        /* else: ignore */
        break;

    default:
        ctx->cmd_state = 0;
        break;
    }
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void kbv_init(kbv_ctx_t *ctx,
              kbv_output_cb_t output_cb,
              kbv_type_cb_t   type_cb,
              kbv_event_cb_t  event_cb)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->output_cb = output_cb;
    ctx->type_cb   = type_cb;
    ctx->event_cb  = event_cb;

    uint8_t magic_buf[4];
    kbv_plat_flash_read(KBV_OFF_MAGIC, magic_buf, 4);

    if (get_le32(magic_buf) == KBV_MAGIC) {
        /* Existing vault */
        uint8_t pepper[32];
        uint8_t salt[16];

        /* Slot flags are stored NOR-inverted: 0 = occupied, 1 = empty */
        uint8_t raw_flags;
        kbv_plat_flash_read(KBV_OFF_SLOT_FLAGS, &raw_flags, 1);
        ctx->slot_flags = (uint8_t)(~raw_flags);
        kbv_plat_flash_read(KBV_OFF_PEPPER,     pepper, 32);
        kbv_plat_flash_read(KBV_OFF_SALT,       salt,   16);

        compute_bound_salt(ctx->bound_salt, pepper, salt);

        hx_explicit_zero(pepper, sizeof(pepper));
        hx_explicit_zero(salt,   sizeof(salt));

        ctx->state            = KBV_STATE_LOCKED;
        ctx->last_activity_ms = kbv_plat_time_ms();
    } else {
        /*
         * Fresh flash — generate per-vault credentials but stay LOCKED.
         * The new-vault prompt is shown only when the user explicitly
         * presses KBV_LOGIN, so the keyboard looks normal to bystanders.
         */
        kbv_plat_random(s_new_vault.pepper, 32);
        kbv_plat_random(s_new_vault.salt,   16);
        s_new_vault.valid = 1;

        compute_bound_salt(ctx->bound_salt,
                           s_new_vault.pepper, s_new_vault.salt);

        ctx->state            = KBV_STATE_LOCKED;
        ctx->last_activity_ms = kbv_plat_time_ms();
    }
}

void kbv_login(kbv_ctx_t *ctx)
{
    if (ctx->state != KBV_STATE_LOCKED) return;

    /* Brute-force throttle: silently ignore login during lockout window.
     * lockout_until_ms is an absolute deadline set after each failed auth.
     * The rare 49-day timer wraparound is accepted (device unlikely to run
     * that long without replug). */
    if (ctx->fail_count > 0 && kbv_plat_time_ms() < ctx->lockout_until_ms)
        return;

    input_reset(ctx);
    ctx->state            = KBV_STATE_AUTHING;
    ctx->last_activity_ms = kbv_plat_time_ms();

    if (!s_new_vault.valid) {
        /*
         * Check whether flash still has a valid vault header.  After
         * kbv_clear() or the settings-clear path, flash is erased (all
         * 0xFF) but s_new_vault.valid is 0 because kbv_init() is not
         * re-called.  Detect this and bootstrap a fresh new-vault setup
         * so the user does not need to re-plug the keyboard.
         */
        uint8_t magic_buf[4];
        kbv_plat_flash_read(KBV_OFF_MAGIC, magic_buf, 4);

        if (get_le32(magic_buf) != KBV_MAGIC) {
            /* Flash is erased — generate fresh pepper/salt */
            kbv_plat_random(s_new_vault.pepper, 32);
            kbv_plat_random(s_new_vault.salt,   16);
            s_new_vault.valid = 1;

            compute_bound_salt(ctx->bound_salt,
                               s_new_vault.pepper, s_new_vault.salt);
        }
    }

    if (s_new_vault.valid) {
        /* First-time setup: prompt only shown on explicit login */
        ctx->cmd_state = CMDSTATE_NEW_VAULT;
        ctx->output_cb("new vault\npw?\n");
    } else {
        ctx->cmd_state = 0;
        /* RGB handles visual feedback — no text output */
    }
}

void kbv_enter_menu(kbv_ctx_t *ctx)
{
    if (ctx->state != KBV_STATE_UNLOCKED) return;

    ctx->cmd_state        = 0;
    ctx->state            = KBV_STATE_MENU;
    ctx->last_activity_ms = kbv_plat_time_ms();
    ctx->output_cb("l=list e=edit d=del s=settings i=info q=exit\nkbv: ");
}

void kbv_type_slot(kbv_ctx_t *ctx, uint8_t slot_idx)
{
    if (ctx->state != KBV_STATE_UNLOCKED) return;
    if (slot_idx >= KBV_MAX_SLOTS) return;
    if (!(ctx->slot_flags & (uint8_t)(1u << slot_idx))) {
        FIRE(ctx, KBV_EVENT_SLOT_EMPTY);
        return;
    }
    decrypt_and_type(ctx, slot_idx);
    FIRE(ctx, KBV_EVENT_SLOT_TYPED);
    /* Stays UNLOCKED — no lock after typing */
}

void kbv_feed_char(kbv_ctx_t *ctx, char c)
{
    if (ctx->state == KBV_STATE_LOCKED) return;
    if (ctx->state == KBV_STATE_UNLOCKED) return; /* transparent: no key capture */

    ctx->last_activity_ms = kbv_plat_time_ms();

    switch (ctx->state) {

    case KBV_STATE_AUTHING:
        if (ctx->cmd_state == CMDSTATE_NEW_VAULT) {
            if (is_enter(c)) {
                authing_new_vault_commit(ctx);
            } else {
                input_append(ctx, c, KBV_MAX_MASTER_LEN);
            }
        } else {
            if (is_enter(c)) {
                authing_try_unlock(ctx);
            } else {
                input_append(ctx, c, KBV_MAX_MASTER_LEN);
            }
        }
        break;

    case KBV_STATE_MENU:
        menu_feed(ctx, c);
        break;

    default:
        break;
    }
}

void kbv_tick(kbv_ctx_t *ctx)
{
    if (ctx->state != KBV_STATE_LOCKED) {
        if ((kbv_plat_time_ms() - ctx->last_activity_ms) > KBV_IDLE_TIMEOUT_MS) {
            kbv_lock(ctx);
        }
    }
}

int kbv_is_active(const kbv_ctx_t *ctx)
{
    return ctx->state == KBV_STATE_AUTHING || ctx->state == KBV_STATE_MENU;
}

kbv_state_t kbv_get_state(const kbv_ctx_t *ctx)
{
    return ctx->state;
}

void kbv_lock(kbv_ctx_t *ctx)
{
    FIRE(ctx, KBV_EVENT_LOCKED);
    hx_explicit_zero(ctx->prk,       sizeof(ctx->prk));
    hx_explicit_zero(ctx->enc_key,   sizeof(ctx->enc_key));
    hx_explicit_zero(ctx->mac_key,   sizeof(ctx->mac_key));
    hx_explicit_zero(ctx->input_buf, sizeof(ctx->input_buf));
    hx_explicit_zero(ctx->cmd_buf,   sizeof(ctx->cmd_buf));
    ctx->input_len   = 0;
    ctx->cmd_buf_len = 0;
    ctx->cmd_state   = 0;
    ctx->state       = KBV_STATE_LOCKED;
}

void kbv_clear(kbv_ctx_t *ctx)
{
    kbv_plat_flash_erase();
    kbv_lock(ctx);           /* zeroes key material, fires KBV_EVENT_LOCKED */
    ctx->slot_flags = 0;     /* reflect erased flash */
    FIRE(ctx, KBV_EVENT_WIPED);
}
