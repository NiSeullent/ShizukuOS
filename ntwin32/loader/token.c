/* SPDX-License-Identifier: GPL-2.0-only
 * A primary token for the current process. SID bytes follow the documented
 * TOKEN_USER and TOKEN_MANDATORY_LABEL layouts. Unknown classes fail.
 */
#include "token.h"
#define TOKEN_SLOTS 8u
#define TOKEN_BASE 0x4800u
static struct { int live; uint32_t access; } tokens[TOKEN_SLOTS];
static int token_slot(uint32_t handle) {
    uint32_t slot = handle - TOKEN_BASE;
    if (handle < TOKEN_BASE || slot >= TOKEN_SLOTS || !tokens[slot].live) return -1;
    return (int)slot;
}
int ntw_token_owns(uint32_t handle) { return token_slot(handle) >= 0; }
int ntw_token_open(uint32_t access, uint32_t *handle, uint32_t *error) {
    uint32_t slot;
    if (!error || !handle) return 0;
    *handle = 0;
    if (!access) { *error = 5; return 0; }
    for (slot = 0; slot < TOKEN_SLOTS; ++slot) if (!tokens[slot].live) break;
    if (slot == TOKEN_SLOTS) { *error = 8; return 0; }
    tokens[slot].live = 1;
    tokens[slot].access = access;
    *handle = TOKEN_BASE + slot;
    *error = 0;
    return 1;
}
int ntw_token_close(uint32_t handle, uint32_t *error) {
    int slot = token_slot(handle);
    if (slot < 0) { if (error) *error = 6; return 0; }
    tokens[slot].live = 0;
    if (error) *error = 0;
    return 1;
}
static void put_sid(uint8_t *out, uint8_t count, uint32_t authority, const uint32_t *subs) {
    uint32_t i;
    out[0] = 1;
    out[1] = count;
    out[2] = 0;
    out[3] = 0;
    out[4] = 0;
    out[5] = 0;
    out[6] = 0;
    out[7] = (uint8_t)authority;
    for (i = 0; i < count; ++i) {
        out[8 + i * 4] = (uint8_t)subs[i];
        out[9 + i * 4] = (uint8_t)(subs[i] >> 8);
        out[10 + i * 4] = (uint8_t)(subs[i] >> 16);
        out[11 + i * 4] = (uint8_t)(subs[i] >> 24);
    }
}
static uint32_t sid_bytes(uint8_t count) { return 8u + (uint32_t)count * 4u; }
int ntw_token_info(uint32_t handle, uint32_t klass, void *buffer, uint32_t bytes, uint32_t *needed, uint32_t *error) {
    uint8_t *out = buffer;
    uint32_t user[4] = {21, 1, 1, 1000};
    uint32_t medium[1] = {8192};
    uint32_t need = 0, sid_at = 0, sid_n = 0;
    const uint32_t *subs = 0;
    uint8_t count = 0;
    uint32_t authority = 5;
    if (!error) return 0;
    if (token_slot(handle) < 0) { *error = 6; return 0; }
    if (klass == 1u || klass == 4u || klass == 5u) {
        count = 4;
        subs = user;
        if (klass == 5u) user[3] = 513;
        sid_at = 8;
        sid_n = sid_bytes(count);
        need = sid_at + sid_n;
    } else if (klass == 25u) {
        count = 1;
        authority = 16;
        subs = medium;
        sid_at = 8;
        sid_n = sid_bytes(count);
        need = sid_at + sid_n;
    } else if (klass == 8u || klass == 12u || klass == 18u || klass == 20u) {
        need = 4;
    } else {
        *error = 87;
        return 0;
    }
    if (needed) *needed = need;
    if (bytes < need) { *error = 122; return 0; }
    if (!out) { *error = 87; return 0; }
    {
        uint32_t i;
        for (i = 0; i < need; ++i) out[i] = 0;
    }
    if (sid_n) {
        *(uint32_t *)out = (uint32_t)(unsigned long)(out + sid_at);
        put_sid(out + sid_at, count, authority, subs);
    } else if (klass == 8u) {
        *(uint32_t *)out = 1;
    } else if (klass == 18u) {
        *(uint32_t *)out = 1;
    } else if (klass == 20u) {
        *(uint32_t *)out = 0;
    }
    *error = 0;
    return 1;
}
