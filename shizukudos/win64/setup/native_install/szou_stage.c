/* SPDX-License-Identifier: GPL-2.0-only
 * SZOU v1 relocation/staging/cold-boot commit. See szou_stage.h for the
 * protocol. Freestanding C99 plus the tree's SHA-256 core.
 */
#include "szou_stage.h"
#include "../../../accounts/sha256.h"
#include <string.h>

static void st_wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static void st_wr64(uint8_t *p, uint64_t v) { st_wr32(p, (uint32_t)v); st_wr32(p + 4, (uint32_t)(v >> 32)); }
static uint32_t st_rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint64_t st_rd64(const uint8_t *p) { return (uint64_t)st_rd32(p) | ((uint64_t)st_rd32(p + 4) << 32); }
static char st_up(char c) { return (c >= 'a' && c <= 'z') ? (char)(c - 32) : c; }

/* Marker header layout (640 bytes), followed by the verbatim entry table. */
#define MK_VERSION 0x08u
#define MK_COUNT   0x0Cu
#define MK_TOTAL   0x10u
#define MK_TSHA    0x18u
#define MK_TROOT   0x38u
#define MK_SROOT   0x13Cu
#define MK_RSVD    0x240u
#define MK_NCOUNT  0x240u   /* v2: SZLN record count */
#define MK_SHA     0x260u

static int sink_ok(const szou_sink_ops_t *s)
{
    return s && s->alloc && s->free && s->mkdir && s->rmdir && s->create && s->open && s->read &&
           s->write && s->close && s->rename_replace && s->remove && s->set_attr && s->flush;
}

static int field_check(const char *s, int single)
{
    uint8_t f[SZOU_PATH_FIELD];
    size_t n = 0;
    memset(f, 0, sizeof f);
    while (s[n]) { if (n >= SZOU_PATH_MAX) return SZOU_E_PATH; f[n] = (uint8_t)s[n]; n++; }
    if (single) { size_t i; for (i = 0; i < n; i++) if (s[i] == '\\') return SZOU_E_PATH; }
    return szou_validate_path(f);
}

int szou_plan_path(const szou_plan_opts_t *o, const char *rel, int staged, char out[SZOU_PATH_FIELD])
{
    const char *root;
    size_t a = 0, b = 0;
    if (!o || !rel || !out) return SZOU_E_ARG;
    root = staged ? o->stage_root : o->target_root;
    if (!root) return SZOU_E_ARG;
    while (root[a]) a++;
    while (rel[b]) b++;
    if (a + (a ? 1 : 0) + b > SZOU_PATH_MAX) return SZOU_E_PATH;
    memcpy(out, root, a);
    if (a) out[a++] = '\\';
    memcpy(out + a, rel, b);
    memset(out + a + b, 0, SZOU_PATH_FIELD - a - b);
    return SZOU_OK;
}

/* Case-insensitive compare of the first path component of p with name. */
static int first_comp_is(const char *p, const char *name)
{
    size_t i = 0;
    for (; p[i] && p[i] != '\\'; i++)
        if (!name[i] || st_up(p[i]) != st_up(name[i])) return 0;
    return name[i] == 0;
}

int szou_plan_check(const szou_plan_opts_t *o, const szou_entry_t *e, uint32_t count)
{
    char tmp[SZOU_PATH_FIELD];
    uint32_t i;
    int rc;
    if (!o || !o->stage_root || !o->target_root || !e || !count) return SZOU_E_ARG;
    if ((rc = field_check(o->stage_root, 1)) != SZOU_OK) return rc;
    if (o->target_root[0] && (rc = field_check(o->target_root, 0)) != SZOU_OK) return rc;
    if (first_comp_is(o->target_root, o->stage_root)) return SZOU_E_CONFLICT;
    for (i = 0; i < count; i++) {
        if ((rc = szou_plan_path(o, e[i].path, 0, tmp)) != SZOU_OK) return rc;
        if ((rc = szou_plan_path(o, e[i].path, 1, tmp)) != SZOU_OK) return rc;
        if (!o->target_root[0] &&
            (first_comp_is(e[i].path, o->stage_root) || first_comp_is(e[i].path, SZOU_MARKER_NAME) ||
             first_comp_is(e[i].path, SZOU_MARKER_TMP)))
            return SZOU_E_CONFLICT;
    }
    return SZOU_OK;
}

/* mkdir every parent directory of path (not path itself). */
static int make_parents(const szou_sink_ops_t *s, const char *path, uint32_t *created)
{
    char t[SZOU_PATH_FIELD];
    size_t k;
    for (k = 0; path[k]; k++) {
        int rc;
        if (path[k] != '\\') continue;
        memcpy(t, path, k);
        t[k] = 0;
        rc = s->mkdir(s->ctx, t);
        if (rc == 0) { if (created) (*created)++; }
        else if (rc != SZOU_E_EXISTS) return rc < 0 ? rc : SZOU_E_IO;
    }
    return SZOU_OK;
}

static int make_root(const szou_sink_ops_t *s, const char *troot, uint32_t *created)
{
    char t[SZOU_PATH_FIELD + 2];
    size_t n = strlen(troot);
    if (!n) return SZOU_OK;
    memcpy(t, troot, n); t[n] = '\\'; t[n + 1] = 'X'; t[n + 2] = 0;
    return make_parents(s, t, created);
}

int szou_plan_check_names(const szou_plan_opts_t *o, const szou_name_t *n, uint32_t count)
{
    char tmp[SZOU_PATH_FIELD];
    uint32_t i;
    int rc;
    if (!o || !o->target_root || !o->stage_root || (count && !n)) return SZOU_E_ARG;
    for (i = 0; i < count; i++) {
        if ((rc = szou_plan_path(o, n[i].path, 0, tmp)) != SZOU_OK) return rc;
        if (!o->target_root[0] &&
            (first_comp_is(n[i].path, o->stage_root) || first_comp_is(n[i].path, SZOU_MARKER_NAME) ||
             first_comp_is(n[i].path, SZOU_MARKER_TMP)))
            return SZOU_E_CONFLICT;
    }
    return SZOU_OK;
}

static int depth_of(const char *p) { int d = 1; for (; *p; p++) if (*p == '\\') d++; return d; }

/* Remove stage directories deepest-first; missing is fine. */
static int remove_stage_dirs(const szou_plan_opts_t *o, const szou_entry_t *e, uint32_t count,
                             const szou_sink_ops_t *s, int best_effort)
{
    char sp[SZOU_PATH_FIELD];
    int maxd = 0, d, rc;
    uint32_t i;
    for (i = 0; i < count; i++) { int x = depth_of(e[i].path); if (x > maxd) maxd = x; }
    for (d = maxd; d >= 2; d--) {               /* directory with (d-1) components under stage_root */
        for (i = 0; i < count; i++) {
            size_t k, seen = 0;
            if (depth_of(e[i].path) < d) continue;
            if (szou_plan_path(o, e[i].path, 1, sp) != SZOU_OK) return SZOU_E_PATH;
            for (k = 0; sp[k]; k++)
                if (sp[k] == '\\' && ++seen == (size_t)d) { sp[k] = 0; break; }
            rc = s->rmdir(s->ctx, sp);
            /* abort path: a refused/never-created dir must not strand the stage root */
            if (rc != 0 && rc != SZOU_ABSENT && !best_effort) return rc < 0 ? rc : SZOU_E_IO;
        }
    }
    rc = s->rmdir(s->ctx, o->stage_root);
    return (rc == 0 || rc == SZOU_ABSENT) ? SZOU_OK : (rc < 0 ? rc : SZOU_E_IO);
}

static int hash_file(const szou_sink_ops_t *s, const char *path, uint64_t expect_size,
                     const uint8_t want[32], uint8_t *buf, uint32_t bb, uint64_t *read_bytes)
{
    sha256_ctx sc;
    uint8_t dig[32];
    void *f = 0;
    uint64_t size = 0, done = 0;
    int rc = s->open(s->ctx, path, &f, &size), crc;
    if (rc != 0) return rc;
    if (size != expect_size) { s->close(s->ctx, f); return SZOU_E_STATE; }
    sha256_init(&sc);
    while (done < size) {
        uint32_t n = (size - done) < bb ? (uint32_t)(size - done) : bb;
        if ((rc = s->read(s->ctx, f, done, buf, n)) != 0) { s->close(s->ctx, f); return SZOU_E_IO; }
        sha256_update(&sc, buf, n);
        done += n;
    }
    crc = s->close(s->ctx, f);
    if (crc != 0) return SZOU_E_IO;
    if (read_bytes) *read_bytes += done;
    sha256_final(&sc, dig);
    return memcmp(dig, want, 32) == 0 ? SZOU_OK : SZOU_E_SHA;
}

static void abort_stage(const szou_plan_opts_t *o, const szou_entry_t *e, uint32_t upto,
                        const szou_sink_ops_t *s, uint32_t count)
{
    char sp[SZOU_PATH_FIELD];
    uint32_t i;
    /* Same backend cleanup of our own staged files; result is already a failure. */
    for (i = 0; i <= upto && i < count; i++)
        if (szou_plan_path(o, e[i].path, 1, sp) == SZOU_OK) (void)s->remove(s->ctx, sp);
    (void)remove_stage_dirs(o, e, count, s, 1);
    (void)s->flush(s->ctx);
}

static int write_all(const szou_sink_ops_t *s, void *f, uint64_t off, const uint8_t *p, size_t n)
{
    while (n) {
        uint32_t c = n > 0x10000u ? 0x10000u : (uint32_t)n;
        if (s->write(s->ctx, f, off, p, c) != 0) return SZOU_E_IO;
        off += c; p += c; n -= c;
    }
    return SZOU_OK;
}

int szou_stage(const szou_plan_opts_t *o, const szou_header_t *h, const szou_entry_t *e,
               szou_read_fn rd, void *rd_ctx, const szou_sink_ops_t *s,
               uint8_t *buf, uint32_t bb, szou_stage_result_t *res)
{
    return szou_stage_named(o, h, e, 0, 0, rd, rd_ctx, s, buf, bb, res);
}

int szou_stage_named(const szou_plan_opts_t *o, const szou_header_t *h, const szou_entry_t *e,
                     const szou_name_t *names, uint32_t nn,
                     szou_read_fn rd, void *rd_ctx, const szou_sink_ops_t *s,
                     uint8_t *buf, uint32_t bb, szou_stage_result_t *res)
{
    uint64_t names_off;
    char sp[SZOU_PATH_FIELD];
    uint8_t mk[SZOU_MARKER_BYTES];
    sha256_ctx sc;
    uint32_t i;
    int rc;
    void *f = 0;
    uint64_t msz = 0;
    if (!res) return SZOU_E_ARG;
    memset(res, 0, sizeof *res);
    res->failed_index = -1;
    if (!sink_ok(s)) return SZOU_E_NO_AUTHORITY;
    if (!o || !h || !e || !rd || !buf || bb < 512) return SZOU_E_ARG;
    if (h->version == SZOU_VERSION_NAMES) {
        if (!names || !nn) return SZOU_E_VERSION;            /* never drop LFN/dir metadata */
        if (!s->mkdir_named || !s->rename_named) return SZOU_E_UNSUPPORTED;
    } else if (h->version != SZOU_VERSION || names || nn) {
        return SZOU_E_ARG;
    }
    if ((rc = szou_plan_check(o, e, h->entry_count)) != SZOU_OK) return rc;
    if ((rc = szou_plan_check_names(o, names, nn)) != SZOU_OK) return rc;
    names_off = SZOU_MARKER_BYTES + (uint64_t)h->entry_count * SZOU_ENTRY_BYTES;

    rc = s->open(s->ctx, SZOU_MARKER_NAME, &f, &msz);
    if (rc == 0) { s->close(s->ctx, f); return SZOU_E_STATE; }   /* pending commit must finish first */
    if (rc != SZOU_ABSENT) return rc < 0 ? rc : SZOU_E_IO;
    rc = s->mkdir(s->ctx, o->stage_root);
    if (rc == SZOU_E_EXISTS) return SZOU_E_STATE;                 /* stale stage; do not mix */
    if (rc != 0) return rc < 0 ? rc : SZOU_E_IO;
    res->dirs_created++;

    for (i = 0; i < h->entry_count; i++) {
        uint64_t done = 0;
        uint8_t dig[32];
        res->failed_index = (int)i;
        if ((rc = szou_plan_path(o, e[i].path, 1, sp)) != SZOU_OK) goto fail;
        if ((rc = make_parents(s, sp, &res->dirs_created)) != SZOU_OK) goto fail;
        if ((rc = s->create(s->ctx, sp, e[i].size, &f)) != 0) { rc = rc < 0 ? rc : SZOU_E_IO; goto fail; }
        sha256_init(&sc);
        while (done < e[i].size) {
            uint32_t n = (e[i].size - done) < bb ? (uint32_t)(e[i].size - done) : bb;
            if (rd(rd_ctx, h->payload_offset + e[i].payload_offset + done, buf, n) != 0) { rc = SZOU_E_IO; break; }
            sha256_update(&sc, buf, n);
            if (s->write(s->ctx, f, done, buf, n) != 0) { rc = SZOU_E_IO; break; }
            done += n;
        }
        if (s->close(s->ctx, f) != 0 && rc == 0) rc = SZOU_E_IO;
        if (rc != 0) goto fail;
        res->bytes_written += done;
        sha256_final(&sc, dig);
        if (memcmp(dig, e[i].sha256, 32) != 0) { rc = SZOU_E_SHA; goto fail; }
        res->files_staged++;
    }
    if (s->flush(s->ctx) != 0) { rc = SZOU_E_IO; goto fail; }
    for (i = 0; i < h->entry_count; i++) {   /* actual readback after flush */
        res->failed_index = (int)i;
        szou_plan_path(o, e[i].path, 1, sp);
        if ((rc = hash_file(s, sp, e[i].size, e[i].sha256, buf, bb, &res->bytes_read_back)) != 0) {
            if (rc > 0) rc = SZOU_E_STATE;
            goto fail;
        }
    }
    res->failed_index = -1;

    /* Marker: header + verbatim entry table rebuilt from validated entries. */
    memset(mk, 0, sizeof mk);
    memcpy(mk, SZOU_MARKER_MAGIC, 8);
    st_wr32(mk + MK_VERSION, h->version);
    st_wr32(mk + MK_NCOUNT, nn);
    st_wr32(mk + MK_COUNT, h->entry_count);
    st_wr64(mk + MK_TOTAL, h->total_payload_bytes);
    memcpy(mk + MK_TSHA, h->entries_sha256, 32);
    memcpy(mk + MK_TROOT, o->target_root, strlen(o->target_root));
    memcpy(mk + MK_SROOT, o->stage_root, strlen(o->stage_root));
    sha256_init(&sc);
    sha256_update(&sc, mk, MK_SHA);
    sha256_final(&sc, mk + MK_SHA);
    rc = s->remove(s->ctx, SZOU_MARKER_TMP);
    if (rc != 0 && rc != SZOU_ABSENT) { rc = SZOU_E_IO; goto fail_all; }
    if ((rc = s->create(s->ctx, SZOU_MARKER_TMP,
                        names_off + (nn ? SZLN_HEADER_BYTES + (uint64_t)nn * SZLN_RECORD_BYTES : 0), &f)) != 0) {
        rc = SZOU_E_IO; goto fail_all;
    }
    rc = write_all(s, f, 0, mk, SZOU_MARKER_BYTES);
    for (i = 0; rc == 0 && i < h->entry_count; i++) {
        uint8_t r[SZOU_ENTRY_BYTES];
        memset(r, 0, sizeof r);
        memcpy(r, e[i].path, SZOU_PATH_FIELD);
        st_wr32(r + 260, e[i].attributes);
        st_wr64(r + 264, e[i].size);
        st_wr64(r + 272, e[i].payload_offset);
        memcpy(r + 280, e[i].sha256, 32);
        rc = write_all(s, f, SZOU_MARKER_BYTES + (uint64_t)i * SZOU_ENTRY_BYTES, r, sizeof r);
    }
    if (rc == 0 && nn) {                       /* SZLN header + canonical records */
        uint8_t nr[SZLN_RECORD_BYTES], nhd[SZLN_HEADER_BYTES];
        sha256_init(&sc);
        for (i = 0; i < nn; i++) { szou_name_serialize(&names[i], nr); sha256_update(&sc, nr, sizeof nr); }
        memset(nhd, 0, sizeof nhd);
        memcpy(nhd, "SZLN", 4);
        nhd[4] = SZLN_VERSION; nhd[6] = SZLN_HEADER_BYTES;
        st_wr32(nhd + 8, nn);
        sha256_final(&sc, nhd + 16);
        rc = write_all(s, f, names_off, nhd, sizeof nhd);
        for (i = 0; rc == 0 && i < nn; i++) {
            szou_name_serialize(&names[i], nr);
            rc = write_all(s, f, names_off + SZLN_HEADER_BYTES + (uint64_t)i * SZLN_RECORD_BYTES, nr, sizeof nr);
        }
    }
    if (s->close(s->ctx, f) != 0 && rc == 0) rc = SZOU_E_IO;
    if (rc == 0 && s->flush(s->ctx) != 0) rc = SZOU_E_IO;
    if (rc == 0 && s->rename_replace(s->ctx, SZOU_MARKER_TMP, SZOU_MARKER_NAME) != 0) rc = SZOU_E_IO;
    if (rc != 0) { (void)s->remove(s->ctx, SZOU_MARKER_TMP); goto fail_all; }
    /* After the rename the marker may be durable; never abort-delete staged files now. */
    if (s->flush(s->ctx) != 0) return SZOU_E_IO;
    res->marker_written = 1;
    return SZOU_OK;
fail_all:
    i = h->entry_count - 1;
fail:
    abort_stage(o, e, i, s, h->entry_count);
    return rc;
}

int szou_commit_pending(const szou_sink_ops_t *s, uint8_t *buf, uint32_t bb, szou_stage_result_t *res)
{
    uint8_t mk[SZOU_MARKER_BYTES], dig[32];
    char troot[SZOU_PATH_FIELD], sroot[SZOU_PATH_FIELD], sp[SZOU_PATH_FIELD], fp[SZOU_PATH_FIELD];
    szou_plan_opts_t o;
    szou_header_t h;
    sha256_ctx sc;
    void *f = 0, *mem = 0;
    uint8_t *table;
    szou_entry_t *e;
    uint32_t *order, *scratch = 0, count, i, nn = 0, ver;
    uint64_t msz = 0, done, names_off;
    size_t tb, need, rb = 0;
    szou_name_t *names = 0;
    uint8_t *raw = 0;
    szou_names_header_t nh;
    int rc;
    if (!res) return SZOU_E_ARG;
    memset(res, 0, sizeof *res);
    res->failed_index = -1;
    if (!sink_ok(s)) return SZOU_E_NO_AUTHORITY;
    if (!buf || bb < 512) return SZOU_E_ARG;
    rc = s->open(s->ctx, SZOU_MARKER_NAME, &f, &msz);
    if (rc == SZOU_ABSENT) return SZOU_ABSENT;
    if (rc != 0) return rc < 0 ? rc : SZOU_E_IO;
    if (msz < SZOU_MARKER_BYTES || s->read(s->ctx, f, 0, mk, SZOU_MARKER_BYTES) != 0) { s->close(s->ctx, f); return SZOU_E_STATE; }
    sha256_init(&sc);
    sha256_update(&sc, mk, MK_SHA);
    sha256_final(&sc, dig);
    count = st_rd32(mk + MK_COUNT);
    ver = st_rd32(mk + MK_VERSION);
    nn = ver == SZOU_VERSION_NAMES ? st_rd32(mk + MK_NCOUNT) : 0;
    names_off = SZOU_MARKER_BYTES + (uint64_t)count * SZOU_ENTRY_BYTES;
    if (memcmp(mk, SZOU_MARKER_MAGIC, 8) || (ver != SZOU_VERSION && ver != SZOU_VERSION_NAMES) ||
        memcmp(dig, mk + MK_SHA, 32) || count == 0 || count > SZOU_MAX_ENTRIES ||
        (ver == SZOU_VERSION_NAMES && (nn == 0 || nn > SZOU_MAX_ENTRIES)) ||
        msz != names_off + (nn ? SZLN_HEADER_BYTES + (uint64_t)nn * SZLN_RECORD_BYTES : 0) ||
        mk[MK_TROOT + SZOU_PATH_MAX] || mk[MK_SROOT + SZOU_PATH_MAX]) {
        s->close(s->ctx, f);
        return SZOU_E_STATE;
    }
    memcpy(troot, mk + MK_TROOT, SZOU_PATH_FIELD);
    memcpy(sroot, mk + MK_SROOT, SZOU_PATH_FIELD);
    memset(&h, 0, sizeof h);
    h.version = (uint16_t)ver;
    h.names_offset = nn ? names_off : 0;
    h.entry_count = count;
    h.total_payload_bytes = st_rd64(mk + MK_TOTAL);
    memcpy(h.entries_sha256, mk + MK_TSHA, 32);
    tb = (size_t)count * SZOU_ENTRY_BYTES;
    rb = (size_t)nn * SZLN_RECORD_BYTES;
    need = (size_t)count * sizeof(szou_entry_t) + (size_t)nn * sizeof(szou_name_t) + (size_t)count * sizeof(uint32_t) +
           (nn ? SZOU_NAMES_SCRATCH(count, nn) * sizeof(uint32_t) : 0) + tb + rb + SZLN_HEADER_BYTES;
    mem = s->alloc(s->ctx, need);
    if (!mem) { s->close(s->ctx, f); return SZOU_E_NOMEM; }
    e = (szou_entry_t *)mem;
    names = (szou_name_t *)((uint8_t *)mem + (size_t)count * sizeof(szou_entry_t));
    order = (uint32_t *)((uint8_t *)names + (size_t)nn * sizeof(szou_name_t));
    scratch = order + count;
    table = (uint8_t *)(scratch + (nn ? SZOU_NAMES_SCRATCH(count, nn) : 0));
    raw = table + tb;
    for (done = 0; done < tb;) {
        uint32_t n = (tb - done) > 0x10000u ? 0x10000u : (uint32_t)(tb - done);
        if (s->read(s->ctx, f, SZOU_MARKER_BYTES + done, table + done, n) != 0) { rc = SZOU_E_IO; break; }
        done += n;
    }
    for (done = 0; rc == 0 && nn && done < rb + SZLN_HEADER_BYTES;) {   /* SZLN header + records */
        uint32_t n = (rb + SZLN_HEADER_BYTES - done) > 0x10000u ? 0x10000u : (uint32_t)(rb + SZLN_HEADER_BYTES - done);
        if (s->read(s->ctx, f, names_off + done, raw + done, n) != 0) { rc = SZOU_E_IO; break; }
        done += n;
    }
    if (s->close(s->ctx, f) != 0 && rc == 0) rc = SZOU_E_IO;
    if (rc != 0) goto out;
    if ((rc = szou_parse_table(&h, table, tb, e, order)) != SZOU_OK) { rc = SZOU_E_STATE; goto out; }
    o.target_root = troot;
    o.stage_root = sroot;
    if ((rc = szou_plan_check(&o, e, count)) != SZOU_OK) { rc = SZOU_E_STATE; goto out; }
    if (nn) {
        if (szou_parse_names_header(&h, raw, msz, &nh) != SZOU_OK || nh.record_count != nn ||
            szou_parse_names(&h, &nh, raw + SZLN_HEADER_BYTES, rb, e, order, names, scratch) != SZOU_OK ||
            szou_plan_check_names(&o, names, nn) != SZOU_OK) { rc = SZOU_E_STATE; goto out; }
        if (!s->mkdir_named || !s->rename_named) { rc = SZOU_E_UNSUPPORTED; goto out; }
        /* Directories first (records sorted: parents precede children), with
         * their LFN chain and attributes; includes empty directories. */
        if ((rc = make_root(s, troot, &res->dirs_created)) != SZOU_OK) goto out;
        for (i = 0; i < nn; i++) {
            if (names[i].kind != SZLN_KIND_DIR) continue;
            szou_plan_path(&o, names[i].path, 0, fp);
            rc = s->mkdir_named(s->ctx, fp, names[i].units ? names[i].name : 0, names[i].units, names[i].attributes);
            if (rc == 0) res->dirs_created++;
            else if (rc != SZOU_E_EXISTS) { rc = rc < 0 ? rc : SZOU_E_IO; goto out; }
        }
    }

    for (i = 0; i < count; i++) {
        uint64_t sz = 0;
        res->failed_index = (int)i;
        szou_plan_path(&o, e[i].path, 1, sp);
        szou_plan_path(&o, e[i].path, 0, fp);
        rc = s->open(s->ctx, sp, &f, &sz);
        if (rc == 0) {
            if (s->close(s->ctx, f) != 0) { rc = SZOU_E_IO; goto out; }
            if (nn) {
                const szou_name_t *ln = szou_names_find(names, nn, e[i].path);
                if (ln && ln->kind != SZLN_KIND_FILE) { rc = SZOU_E_STATE; goto out; }
                rc = s->rename_named(s->ctx, sp, fp, ln ? ln->name : 0, ln ? ln->units : 0);
                if (rc != 0) { rc = rc < 0 ? rc : SZOU_E_IO; goto out; }
            } else {
                if ((rc = make_parents(s, fp, &res->dirs_created)) != SZOU_OK) goto out;
                if (s->rename_replace(s->ctx, sp, fp) != 0) { rc = SZOU_E_IO; goto out; }
            }
            res->files_committed++;
        } else if (rc == SZOU_ABSENT) {
            /* Already moved by an interrupted earlier commit: prove it by content. */
            rc = hash_file(s, fp, e[i].size, e[i].sha256, buf, bb, &res->bytes_read_back);
            if (rc != 0) { rc = SZOU_E_STATE; goto out; }
            res->files_already_final++;
        } else {
            rc = rc < 0 ? rc : SZOU_E_IO;
            goto out;
        }
        if (s->set_attr(s->ctx, fp, e[i].attributes) != 0) { rc = SZOU_E_IO; goto out; }
    }
    res->failed_index = -1;
    if ((rc = s->flush(s->ctx)) != 0) { rc = SZOU_E_IO; goto out; }
    if ((rc = remove_stage_dirs(&o, e, count, s, 0)) != SZOU_OK) goto out;
    if (s->flush(s->ctx) != 0) { rc = SZOU_E_IO; goto out; }
    rc = s->remove(s->ctx, SZOU_MARKER_NAME);
    if (rc != 0) { rc = rc < 0 ? rc : SZOU_E_IO; goto out; }
    if (s->flush(s->ctx) != 0) { rc = SZOU_E_IO; goto out; }
    res->committed = 1;
    rc = SZOU_OK;
out:
    s->free(s->ctx, mem);
    return rc;
}
