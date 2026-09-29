/* SPDX-License-Identifier: GPL-2.0-only
 * SDDL revision 1. Layout follows the public relative security descriptor
 * and ACCESS_ALLOWED_ACE / SYSTEM_MANDATORY_LABEL_ACE records. This file
 * does not copy the Wine or ReactOS converter.
 */
#include "sddl.h"

static void wr16(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

typedef struct sid_rec {
    uint8_t nsub;
    uint32_t auth;
    uint32_t sub[15];
} sid_rec;

static int take_u32(const uint16_t **pp, uint32_t *out) {
    const uint16_t *p = *pp;
    uint32_t value = 0;
    if (*p < '0' || *p > '9') return 0;
    while (*p >= '0' && *p <= '9') {
        uint32_t digit = (uint32_t)(*p - '0');
        if (value > 429496729u || (value == 429496729u && digit > 5u)) return 0;
        value = value * 10u + digit;
        ++p;
    }
    *pp = p;
    *out = value;
    return 1;
}

static int literal_sid(const uint16_t **pp, sid_rec *sid) {
    const uint16_t *p = *pp;
    uint32_t revision, auth, sub;
    if (p[0] != 'S' || p[1] != '-') return 0;
    p += 2;
    if (!take_u32(&p, &revision) || revision != 1u || *p != '-') return -1;
    ++p;
    if (!take_u32(&p, &auth) || auth > 0xffffu) return -1;
    sid->auth = auth;
    sid->nsub = 0;
    while (*p == '-') {
        ++p;
        if (!take_u32(&p, &sub) || sid->nsub == 15) return -1;
        sid->sub[sid->nsub++] = sub;
    }
    *pp = p;
    return 1;
}

static int alias_sid(uint16_t a, uint16_t b, sid_rec *sid) {
    uint32_t auth = 5, nsub = 1, sub0 = 0, sub1 = 0;
    int two = 0;
    if (a == 'W' && b == 'D') { auth = 1; sub0 = 0; }
    else if (a == 'C' && b == 'O') { auth = 3; sub0 = 0; }
    else if (a == 'C' && b == 'G') { auth = 3; sub0 = 1; }
    else if (a == 'O' && b == 'W') { auth = 3; sub0 = 4; }
    else if (a == 'N' && b == 'U') sub0 = 2;
    else if (a == 'I' && b == 'U') sub0 = 4;
    else if (a == 'S' && b == 'U') sub0 = 6;
    else if (a == 'A' && b == 'N') sub0 = 7;
    else if (a == 'A' && b == 'U') sub0 = 11;
    else if (a == 'R' && b == 'C') sub0 = 12;
    else if (a == 'S' && b == 'Y') sub0 = 18;
    else if (a == 'L' && b == 'S') sub0 = 19;
    else if (a == 'N' && b == 'S') sub0 = 20;
    else if (a == 'B' && b == 'A') { two = 1; sub0 = 32; sub1 = 544; }
    else if (a == 'B' && b == 'U') { two = 1; sub0 = 32; sub1 = 545; }
    else if (a == 'B' && b == 'G') { two = 1; sub0 = 32; sub1 = 546; }
    else return 0;
    sid->auth = auth;
    sid->nsub = (uint8_t)(two ? 2 : nsub);
    sid->sub[0] = sub0;
    sid->sub[1] = sub1;
    return 1;
}

static int parse_sid(const uint16_t **pp, sid_rec *sid, uint32_t *error) {
    const uint16_t *p = *pp;
    int literal;
    uint16_t a, b;
    if (!p[0]) { *error = NTW_SDDL_PARAM; return 0; }
    literal = literal_sid(&p, sid);
    if (literal == 1) { *pp = p; return 1; }
    if (literal < 0) { *error = NTW_SDDL_PARAM; return 0; }
    a = p[0];
    b = p[1];
    if (!b || b == ':' || a == '(' || a == ')') { *error = NTW_SDDL_PARAM; return 0; }
    if (!alias_sid(a, b, sid)) { *error = NTW_SDDL_NONE_MAPPED; return 0; }
    *pp = p + 2;
    return 1;
}

static int emit_sid(uint8_t *dst, uint32_t cap, uint32_t at, const sid_rec *sid, uint32_t *end) {
    uint32_t size = 8u + 4u * sid->nsub, i;
    if (at + size > cap) return 0;
    dst[at] = 1;
    dst[at + 1] = sid->nsub;
    dst[at + 2] = 0;
    dst[at + 3] = 0;
    dst[at + 4] = 0;
    dst[at + 5] = 0;
    dst[at + 6] = (uint8_t)(sid->auth >> 8);
    dst[at + 7] = (uint8_t)sid->auth;
    for (i = 0; i < sid->nsub; ++i) wr32(dst + at + 8 + i * 4, sid->sub[i]);
    *end = at + size;
    return 1;
}

static int right_bit(uint16_t a, uint16_t b, uint32_t *bit) {
    if (a == 'G' && b == 'A') *bit = 0x10000000u;
    else if (a == 'G' && b == 'R') *bit = 0x80000000u;
    else if (a == 'G' && b == 'W') *bit = 0x40000000u;
    else if (a == 'G' && b == 'X') *bit = 0x20000000u;
    else if (a == 'R' && b == 'C') *bit = 0x00020000u;
    else if (a == 'S' && b == 'D') *bit = 0x00010000u;
    else if (a == 'W' && b == 'D') *bit = 0x00040000u;
    else if (a == 'W' && b == 'O') *bit = 0x00080000u;
    else if (a == 'C' && b == 'C') *bit = 0x00000001u;
    else if (a == 'D' && b == 'C') *bit = 0x00000002u;
    else if (a == 'L' && b == 'C') *bit = 0x00000004u;
    else if (a == 'S' && b == 'W') *bit = 0x00000008u;
    else if (a == 'R' && b == 'P') *bit = 0x00000010u;
    else if (a == 'W' && b == 'P') *bit = 0x00000020u;
    else if (a == 'L' && b == 'O') *bit = 0x00000080u;
    else if (a == 'C' && b == 'R') *bit = 0x00000100u;
    else if (a == 'F' && b == 'A') *bit = 0x001f01ffu;
    else if (a == 'F' && b == 'R') *bit = 0x00120089u;
    else if (a == 'F' && b == 'W') *bit = 0x00120116u;
    else if (a == 'F' && b == 'X') *bit = 0x001200a0u;
    else if (a == 'N' && b == 'W') *bit = 0x00000001u;
    else if (a == 'N' && b == 'R') *bit = 0x00000002u;
    else if (a == 'N' && b == 'X') *bit = 0x00000004u;
    else return 0;
    return 1;
}

static int hex_rights(const uint16_t *p, uint32_t len, uint32_t *mask) {
    uint32_t i, value = 0;
    if (len >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { p += 2; len -= 2; }
    if (!len || len > 8) return 0;
    for (i = 0; i < len; ++i) {
        uint16_t c = p[i];
        uint32_t digit;
        if (c >= '0' && c <= '9') digit = (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') digit = (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') digit = (uint32_t)(c - 'A' + 10);
        else return 0;
        value = (value << 4) | digit;
    }
    *mask = value;
    return 1;
}

static int parse_rights(const uint16_t *p, uint32_t len, uint32_t *mask) {
    uint32_t i, bits = 0;
    if (!len) { *mask = 0; return 1; }
    if ((len & 1u) == 0) {
        int codes = 1;
        for (i = 0; i < len; i += 2) {
            uint32_t bit = 0;
            if (!right_bit(p[i], p[i + 1], &bit)) { codes = 0; break; }
            bits |= bit;
        }
        if (codes) { *mask = bits; return 1; }
    }
    return hex_rights(p, len, mask);
}

static int flag_bit(uint16_t a, uint16_t b, uint32_t *bit) {
    if (a == 'O' && b == 'I') *bit = 0x01u;
    else if (a == 'C' && b == 'I') *bit = 0x02u;
    else if (a == 'N' && b == 'P') *bit = 0x04u;
    else if (a == 'I' && b == 'O') *bit = 0x08u;
    else if (a == 'I' && b == 'D') *bit = 0x10u;
    else if (a == 'S' && b == 'A') *bit = 0x40u;
    else if (a == 'F' && b == 'A') *bit = 0x80u;
    else return 0;
    return 1;
}

static int parse_ace_flags(const uint16_t *p, uint32_t len, uint32_t *flags) {
    uint32_t i, bits = 0;
    if (!len) { *flags = 0; return 1; }
    if (len & 1u) return 0;
    for (i = 0; i < len; i += 2) {
        uint32_t bit = 0;
        if (!flag_bit(p[i], p[i + 1], &bit)) return 0;
        bits |= bit;
    }
    *flags = bits;
    return 1;
}

static int parse_ace(const uint16_t **pp, uint8_t *dst, uint32_t cap, uint32_t *at, uint32_t *count, uint32_t *error) {
    const uint16_t *p = *pp, *field[6], *start;
    uint32_t len[6], n = 0, mask = 0, flags = 0, ace_at, sid_end = 0;
    uint8_t type;
    sid_rec sid;
    if (*p != '(') { *error = NTW_SDDL_PARAM; return 0; }
    ++p;
    start = p;
    while (*p && *p != ')') {
        if (*p == ';') {
            if (n >= 5) { *error = NTW_SDDL_PARAM; return 0; }
            field[n] = start;
            len[n] = (uint32_t)(p - start);
            ++n;
            start = p + 1;
        }
        ++p;
    }
    if (*p != ')' || n != 5) { *error = NTW_SDDL_PARAM; return 0; }
    field[5] = start;
    len[5] = (uint32_t)(p - start);
    ++p;
    if (len[0] == 1 && field[0][0] == 'A') type = 0;
    else if (len[0] == 1 && field[0][0] == 'D') type = 1;
    else if (len[0] == 2 && field[0][0] == 'M' && field[0][1] == 'L') type = 0x11;
    else { *error = NTW_SDDL_PARAM; return 0; }
    if (len[3] || len[4]) { *error = NTW_SDDL_PARAM; return 0; }
    if (!parse_ace_flags(field[1], len[1], &flags) || !parse_rights(field[2], len[2], &mask)) {
        *error = NTW_SDDL_PARAM;
        return 0;
    }
    start = field[5];
    if (!parse_sid(&start, &sid, error) || start != field[5] + len[5]) {
        if (!*error) *error = NTW_SDDL_PARAM;
        return 0;
    }
    ace_at = *at;
    if (ace_at + 8 > cap || !emit_sid(dst, cap, ace_at + 8, &sid, &sid_end)) {
        *error = NTW_SDDL_PARAM;
        return 0;
    }
    dst[ace_at] = type;
    dst[ace_at + 1] = (uint8_t)flags;
    wr16(dst + ace_at + 2, sid_end - ace_at);
    wr32(dst + ace_at + 4, mask);
    *at = sid_end;
    *count += 1u;
    *pp = p;
    return 1;
}

static int next_part(const uint16_t *p) {
    return p[0] && p[1] == ':';
}

static int parse_acl_flags(const uint16_t **pp, uint16_t *control, int sacl, uint32_t *error) {
    const uint16_t *p = *pp;
    while (*p && *p != '(' && !next_part(p)) {
        if (*p == 'P') {
            *control = (uint16_t)(*control | (sacl ? 0x2000u : 0x1000u));
            ++p;
            continue;
        }
        if (p[0] == 'A' && p[1] == 'R') {
            *control = (uint16_t)(*control | (sacl ? 0x0200u : 0x0100u));
            p += 2;
            continue;
        }
        if (p[0] == 'A' && p[1] == 'I') {
            *control = (uint16_t)(*control | (sacl ? 0x0800u : 0x0400u));
            p += 2;
            continue;
        }
        *error = NTW_SDDL_PARAM;
        return 0;
    }
    *pp = p;
    return 1;
}

int ntw_sddl_build(const uint16_t *text, uint32_t revision, uint8_t *dst, uint32_t cap,
                   uint32_t *bytes, uint32_t *error) {
    const uint16_t *p = text;
    uint32_t at = 20, i;
    uint32_t owner = 0, group = 0, sacl = 0, dacl = 0;
    uint16_t control = 0x8000;
    int saw_d = 0, saw_s = 0, saw_o = 0, saw_g = 0;
    if (error) *error = 0;
    if (!text || !text[0] || !bytes) {
        if (error) *error = NTW_SDDL_PARAM;
        return 0;
    }
    if (revision != 1u) {
        if (error) *error = NTW_SDDL_REVISION;
        return 0;
    }
    if (cap < 20) {
        if (error) *error = NTW_SDDL_PARAM;
        return 0;
    }
    for (i = 0; i < cap; ++i) dst[i] = 0;
    while (*p) {
        uint32_t err = 0;
        if (p[0] == 'O' && p[1] == ':') {
            sid_rec sid;
            if (saw_o) { if (error) *error = NTW_SDDL_PARAM; return 0; }
            p += 2;
            if (!parse_sid(&p, &sid, &err) || !emit_sid(dst, cap, at, &sid, &at)) {
                if (error) *error = err ? err : NTW_SDDL_PARAM;
                return 0;
            }
            owner = at - (8u + 4u * sid.nsub);
            saw_o = 1;
            continue;
        }
        if (p[0] == 'G' && p[1] == ':') {
            sid_rec sid;
            if (saw_g) { if (error) *error = NTW_SDDL_PARAM; return 0; }
            p += 2;
            if (!parse_sid(&p, &sid, &err) || !emit_sid(dst, cap, at, &sid, &at)) {
                if (error) *error = err ? err : NTW_SDDL_PARAM;
                return 0;
            }
            group = at - (8u + 4u * sid.nsub);
            saw_g = 1;
            continue;
        }
        if ((p[0] == 'D' || p[0] == 'S') && p[1] == ':') {
            int sacl_part = p[0] == 'S';
            uint32_t acl_at, count = 0, offset;
            if (sacl_part ? saw_s : saw_d) { if (error) *error = NTW_SDDL_PARAM; return 0; }
            p += 2;
            if (!parse_acl_flags(&p, &control, sacl_part, &err)) {
                if (error) *error = err;
                return 0;
            }
            if (at + 8 > cap) { if (error) *error = NTW_SDDL_PARAM; return 0; }
            acl_at = at;
            at += 8;
            while (*p == '(') {
                if (!parse_ace(&p, dst, cap, &at, &count, &err)) {
                    if (error) *error = err ? err : NTW_SDDL_PARAM;
                    return 0;
                }
            }
            dst[acl_at] = 2;
            dst[acl_at + 1] = 0;
            wr16(dst + acl_at + 2, at - acl_at);
            wr16(dst + acl_at + 4, count);
            wr16(dst + acl_at + 6, 0);
            offset = acl_at;
            if (sacl_part) { sacl = offset; saw_s = 1; control = (uint16_t)(control | 0x10u); }
            else { dacl = offset; saw_d = 1; control = (uint16_t)(control | 0x4u); }
            continue;
        }
        if (error) *error = NTW_SDDL_PARAM;
        return 0;
    }
    dst[0] = 1;
    dst[1] = 0;
    wr16(dst + 2, control);
    wr32(dst + 4, owner);
    wr32(dst + 8, group);
    wr32(dst + 12, sacl);
    wr32(dst + 16, dacl);
    *bytes = at;
    return 1;
}

int ntw_explicit_access(uint8_t *out, const uint16_t *name, uint32_t perms, uint32_t mode,
                        uint32_t inherit, uint32_t *error) {
    if (!out || !name || !name[0] || mode > 6u) {
        if (error) *error = NTW_SDDL_PARAM;
        return 0;
    }
    wr32(out + 0, perms);
    wr32(out + 4, mode);
    wr32(out + 8, inherit);
    wr32(out + 12, 0);
    wr32(out + 16, 0);
    wr32(out + 20, 1u);
    wr32(out + 24, 0);
    wr32(out + 28, (uint32_t)(unsigned long)name);
    if (error) *error = 0;
    return 1;
}

int ntw_merge_grant(const uint8_t *old, uint32_t old_bytes, const uint16_t *name, uint32_t perms,
                    uint32_t inherit, uint8_t *dst, uint32_t cap, uint32_t *bytes, uint32_t *error) {
    const uint16_t *sid_text = name;
    sid_rec sid;
    uint32_t err = 0, sid_end = 0, dacl, dacl_size, dacl_count, at, control;
    uint8_t ace[80];
    uint32_t ace_bytes;
    if (!name || !name[0] || !dst || !bytes) {
        if (error) *error = NTW_SDDL_PARAM;
        return 0;
    }
    if (inherit & ~0x0fu) {
        if (error) *error = NTW_SDDL_PARAM;
        return 0;
    }
    if (!parse_sid(&sid_text, &sid, &err) || sid_text[0]) {
        if (error) *error = err ? err : NTW_SDDL_PARAM;
        return 0;
    }
    if (!emit_sid(ace, sizeof ace, 8, &sid, &sid_end)) {
        if (error) *error = NTW_SDDL_PARAM;
        return 0;
    }
    ace[0] = 0;
    ace[1] = (uint8_t)inherit;
    wr16(ace + 2, sid_end);
    wr32(ace + 4, perms);
    ace_bytes = sid_end;
    if (!old || old_bytes < 20 || old[0] != 1 || (rd16(old + 2) & 0x8000u) == 0) {
        if (error) *error = NTW_SDDL_PARAM;
        return 0;
    }
    dacl = rd32(old + 16);
    if (dacl && (dacl < 20 || dacl + 8 > old_bytes)) {
        if (error) *error = NTW_SDDL_PARAM;
        return 0;
    }
    dacl_size = dacl ? rd16(old + dacl + 2) : 0;
    dacl_count = dacl ? rd16(old + dacl + 4) : 0;
    if (dacl && (dacl_size < 8u || dacl + dacl_size > old_bytes)) {
        if (error) *error = NTW_SDDL_PARAM;
        return 0;
    }
    {
        uint32_t extra = dacl ? ace_bytes : 8u + ace_bytes;
        uint32_t tail_at = dacl ? dacl + dacl_size : old_bytes;
        uint32_t tail = old_bytes - tail_at;
        uint32_t sacl_off = rd32(old + 12);
        uint32_t owner_off = rd32(old + 4);
        uint32_t group_off = rd32(old + 8);
        if (old_bytes + extra > cap) {
            if (error) *error = NTW_SDDL_PARAM;
            return 0;
        }
        for (at = 0; at < tail_at; ++at) dst[at] = old[at];
        if (!dacl) {
            dacl = old_bytes;
            dst[dacl] = 2;
            dst[dacl + 1] = 0;
            wr16(dst + dacl + 2, 8 + ace_bytes);
            wr16(dst + dacl + 4, 1);
            wr16(dst + dacl + 6, 0);
            for (at = 0; at < ace_bytes; ++at) dst[dacl + 8 + at] = ace[at];
            tail_at = dacl + 8;
        } else {
            wr16(dst + dacl + 2, dacl_size + ace_bytes);
            wr16(dst + dacl + 4, dacl_count + 1u);
        }
        for (at = 0; at < ace_bytes; ++at) dst[tail_at + at] = ace[at];
        for (at = 0; at < tail; ++at) dst[tail_at + ace_bytes + at] = old[tail_at + at];
        if (sacl_off >= tail_at) sacl_off += ace_bytes;
        if (owner_off >= tail_at) owner_off += ace_bytes;
        if (group_off >= tail_at) group_off += ace_bytes;
        wr32(dst + 4, owner_off);
        wr32(dst + 8, group_off);
        wr32(dst + 12, sacl_off);
        at = old_bytes + extra;
    }
    control = rd16(dst + 2);
    control |= 0x8004u;
    wr16(dst + 2, control);
    wr32(dst + 16, dacl);
    *bytes = at;
    if (error) *error = 0;
    return 1;
}
