/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP installer core (portable; see plat.h).
 *
 * Installed disk (docs/shizukudos10/INSTALLER.md):
 *   LBA 0      protective MBR with the legacy BIOS boot code (payload GPTMBR.BIN, install/gptmbr.asm)
 *   LBA 1..33  primary GPT; the backup GPT at the end of the disk
 *   p1         EFI System Partition, FAT32: the host-built esp.img written sector by sector (payload ESP.SIM)
 *   p2         ShizukuFS v1 (ext4 format) system volume: \SHZ\SYS64, \SHZ\DRIVERS, \SHZ\SETUP\log, \Users
 *   p3         optional empty FAT32 volume for the user's own Windows 98 (nothing is bundled)
 * Order of the destructive phase: wipe the old partition tables, write + verify p1, format/populate + verify p2,
 * format p3, write + verify the new partition tables, write the install log. A disk is left with a partition table
 * only if every earlier step verified.
 */
#include "plat.h"
#include "gpt.h"
#include "sfsw.h"
#include "fat32fmt.h"
#include "textparse.h"
#include <stdarg.h>
#include <string.h>
#ifdef _WIN32
int shz_vsnprintf(char *buf, size_t cap, const char *fmt, va_list ap);          /* win64/crt/shzcrt.c */
#define setup_vsnprintf shz_vsnprintf
#else
#include <stdio.h>
#define setup_vsnprintf vsnprintf
#endif

#define SETUP_VERSION "SHZSETUP 1.0"
#define MANIFEST_SCHEMA "shizukudos-install-manifest/1"
#define IOBUF (1u << 20)
#define LOG_CAP (256u * 1024u)
#define MIB 1048576ull
#define MIN_SYSTEM_MIB 64ull
#define SIMG_MAGIC "SHZSIMG1"

typedef struct config {
    int power;
    char select[24], serial[32], name[16];
    uint64_t size_mib, min_mib, system_mib, win98_mib;
    int allow_nonempty, win98_hybrid, bios_boot_code;
    char hostname[64], drivers[256], seed[80];
} config_t;

typedef struct arc_entry { const char *path; uint64_t off, size; } arc_entry_t;

typedef struct ctx {
    const plat_t *P;
    char *log;
    size_t log_len;
    config_t cfg;
    char *answer_text, *manifest_text;
    uint64_t answer_len, manifest_len;
    ini_t ini;
    json_t man;
    char payload[200];
    uint8_t *buf, *buf2;
    unsigned disk;
    plat_disk_t di;
    uint32_t ss;
    uint64_t pfirst[3], plast[3];
    int nparts;
    uint8_t disk_guid[16], part_guid[3][16], fs_uuid[16];
    uint32_t mbr_sig, fat_id;
    uint8_t mbr_code[440];
    int have_mbr_code;
    void *arc;                                  /* SYSTEM.ARC handle */
    arc_entry_t *arc_e;
    uint32_t arc_n;
    char *arc_names;
    char fail[160];
    uint64_t started;
    uint64_t files_ok, bytes_ok;
} ctx_t;

static int sncmp(const char *a, const char *b, size_t n)                 /* the Win64 CRT has no strncmp */
{
    while (n && *a && *a == *b) { ++a; ++b; --n; }
    return n ? (unsigned char)*a - (unsigned char)*b : 0;
}

/* ---------------------------------------------------------------- output and log */
static void emit(ctx_t *C, const char *text)
{
    size_t n = strlen(text);
    C->P->out(C->P->ctx, text);
    if (C->log && C->log_len + n < LOG_CAP) {
        memcpy(C->log + C->log_len, text, n);
        C->log_len += n;
    }
}

static void log_only(ctx_t *C, const char *text)
{
    const size_t n = strlen(text);
    if (C->log && C->log_len + n < LOG_CAP) {
        memcpy(C->log + C->log_len, text, n);
        C->log_len += n;
    }
}

static void say(ctx_t *C, const char *fmt, ...)
{
    char line[400];
    va_list ap;
    va_start(ap, fmt);
    setup_vsnprintf(line, sizeof line - 1, fmt, ap);
    va_end(ap);
    emit(C, "SHZSETUP: ");
    emit(C, line);
    emit(C, "\n");
}

static int failf(ctx_t *C, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    setup_vsnprintf(C->fail, sizeof C->fail, fmt, ap);
    va_end(ap);
    say(C, "ERROR: %s", C->fail);
    return -1;
}

static void hex(const uint8_t *d, size_t n, char *out)
{
    static const char h[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; ++i) { out[2 * i] = h[d[i] >> 4]; out[2 * i + 1] = h[d[i] & 15]; }
    out[2 * n] = 0;
}

static void iso_time(uint64_t t, char out[24])
{
    /* days -> civil date (proleptic Gregorian), Howard Hinnant's algorithm */
    int64_t z = (int64_t)(t / 86400) + 719468, era, doe, yoe, y, doy, mp, d, m;
    const uint64_t s = t % 86400;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = z - era * 146097;
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = yoe + era * 400;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    y += m <= 2;
    out[0] = (char)('0' + (y / 1000) % 10); out[1] = (char)('0' + (y / 100) % 10);
    out[2] = (char)('0' + (y / 10) % 10); out[3] = (char)('0' + y % 10); out[4] = '-';
    out[5] = (char)('0' + m / 10); out[6] = (char)('0' + m % 10); out[7] = '-';
    out[8] = (char)('0' + d / 10); out[9] = (char)('0' + d % 10); out[10] = 'T';
    out[11] = (char)('0' + s / 36000); out[12] = (char)('0' + (s / 3600) % 10); out[13] = ':';
    out[14] = (char)('0' + (s % 3600) / 600); out[15] = (char)('0' + (s % 600) / 60); out[16] = ':';
    out[17] = (char)('0' + (s % 60) / 10); out[18] = (char)('0' + s % 10); out[19] = 'Z'; out[20] = 0;
}

/* ---------------------------------------------------------------- files */
static void join(ctx_t *C, const char *name, char *out, size_t cap)
{
    size_t a = strlen(C->payload), b = strlen(name);
    if (a + b + 2 > cap) { out[0] = 0; return; }
    memcpy(out, C->payload, a);
    out[a] = '/';
    memcpy(out + a + 1, name, b + 1);
}

static int load_file(ctx_t *C, const char *path, char **text, uint64_t *len)
{
    void *h;
    uint64_t size;
    if (C->P->file_open(C->P->ctx, path, &h, &size)) return failf(C, "cannot open %s", path);
    if (size > 16 * MIB) { C->P->file_close(C->P->ctx, h); return failf(C, "%s is too large", path); }
    *text = C->P->alloc(C->P->ctx, (size_t)size + 1);
    if (!*text || (size && C->P->file_read(C->P->ctx, h, 0, *text, (uint32_t)size))) {
        C->P->file_close(C->P->ctx, h);
        return failf(C, "cannot read %s", path);
    }
    C->P->file_close(C->P->ctx, h);
    *len = size;
    return 0;
}

static int unhex_sha(const char *s, uint8_t out[32])
{
    int i;
    for (i = 0; i < 64; ++i) {
        const char c = s[i];
        const int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
        if (v < 0) return -1;
        if (i & 1) out[i / 2] |= (uint8_t)v; else out[i / 2] = (uint8_t)(v << 4);
    }
    return s[64] ? -1 : 0;
}

/* ---------------------------------------------------------------- answer file */
static const char *const known_keys[] = {
    "Setup:Schema", "Setup:Confirm", "Setup:Reboot",
    "Target:Select", "Target:SizeMiB", "Target:Serial", "Target:Name", "Target:MinSizeMiB", "Target:AllowNonEmpty",
    "Layout:SystemMiB", "Layout:Win98MiB", "Layout:Win98HybridMBR", "Layout:BiosBootCode",
    "System:Hostname", "System:GuidSeed", "Drivers:Install", 0};

static int is_known(const char *section, const char *key)
{
    int i;
    for (i = 0; known_keys[i]; ++i) {
        const char *k = known_keys[i], *colon = k;
        char sec[16];
        while (*colon != ':') ++colon;
        memcpy(sec, k, (size_t)(colon - k));
        sec[colon - k] = 0;
        if (text_ieq(sec, section) && text_ieq(colon + 1, key)) return 1;
    }
    return 0;
}

static int parse_u64(const char *s, uint64_t *out)
{
    uint64_t v = 0;
    if (!s || !*s) return -1;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9' || v > 0xffffffffffffull) return -1;
        v = v * 10 + (uint64_t)(*s - '0');
    }
    *out = v;
    return 0;
}

static int yesno(const char *v, int dflt, int *out)
{
    if (!v || !*v) { *out = dflt; return 0; }
    if (text_ieq(v, "yes") || text_ieq(v, "true") || text_ieq(v, "1")) { *out = 1; return 0; }
    if (text_ieq(v, "no") || text_ieq(v, "false") || text_ieq(v, "0")) { *out = 0; return 0; }
    return -1;
}

static void copy_str(char *dst, size_t cap, const char *src)
{
    size_t n = src ? strlen(src) : 0;
    if (n >= cap) n = cap - 1;
    if (n) memcpy(dst, src, n);
    dst[n] = 0;
}

static int read_answer(ctx_t *C, const char *path)
{
    config_t *c = &C->cfg;
    char err[96];
    const char *v;
    unsigned i;
    if (load_file(C, path, &C->answer_text, &C->answer_len)) return -1;
    if (ini_parse(C->P, C->answer_text, (size_t)C->answer_len, &C->ini, err, sizeof err))
        return failf(C, "answer file %s: %s", path, err);
    for (i = 0; i < C->ini.count; ++i)
        if (!is_known(C->ini.e[i].section, C->ini.e[i].key))
            say(C, "warning: answer file line %u: unknown key [%s] %s (ignored)", C->ini.e[i].line, C->ini.e[i].section,
                C->ini.e[i].key);
    v = ini_get(&C->ini, "Setup", "Schema");
    if (!v || strcmp(v, "1")) return failf(C, "answer file: [Setup] Schema=1 is required");
    v = ini_get(&C->ini, "Setup", "Confirm");
    if (!v || strcmp(v, "ERASE-TARGET"))
        return failf(C, "answer file: [Setup] Confirm=ERASE-TARGET is required (the target disk is erased)");
    v = ini_get(&C->ini, "Setup", "Reboot");
    if (!v || !*v || text_ieq(v, "shutdown")) c->power = SETUP_POWER_SHUTDOWN;
    else if (text_ieq(v, "reboot")) c->power = SETUP_POWER_REBOOT;
    else if (text_ieq(v, "none")) c->power = SETUP_POWER_NONE;
    else return failf(C, "answer file: Reboot=%s (none|shutdown|reboot)", v);
    copy_str(c->select, sizeof c->select, ini_get(&C->ini, "Target", "Select"));
    if (!c->select[0]) copy_str(c->select, sizeof c->select, "first");
    if (!text_ieq(c->select, "first") && !text_ieq(c->select, "first-nvme") && !text_ieq(c->select, "first-ahci") &&
        !text_ieq(c->select, "first-mmc") && !text_ieq(c->select, "first-ram") && !text_ieq(c->select, "largest") &&
        !text_ieq(c->select, "smallest") && !text_ieq(c->select, "size") && !text_ieq(c->select, "serial") &&
        !text_ieq(c->select, "name"))
        return failf(C, "answer file: Select=%s is not a known selector", c->select);
    copy_str(c->serial, sizeof c->serial, ini_get(&C->ini, "Target", "Serial"));
    copy_str(c->name, sizeof c->name, ini_get(&C->ini, "Target", "Name"));
    if (text_ieq(c->select, "size") && parse_u64(ini_get(&C->ini, "Target", "SizeMiB"), &c->size_mib))
        return failf(C, "answer file: Select=size needs SizeMiB=<MiB>");
    if (text_ieq(c->select, "serial") && !c->serial[0]) return failf(C, "answer file: Select=serial needs Serial=");
    if (text_ieq(c->select, "name") && !c->name[0]) return failf(C, "answer file: Select=name needs Name=");
    v = ini_get(&C->ini, "Target", "MinSizeMiB");
    if (v && *v && parse_u64(v, &c->min_mib)) return failf(C, "answer file: MinSizeMiB=%s", v);
    if (yesno(ini_get(&C->ini, "Target", "AllowNonEmpty"), 0, &c->allow_nonempty)) return failf(C, "answer file: AllowNonEmpty");
    v = ini_get(&C->ini, "Layout", "SystemMiB");
    if (v && *v && parse_u64(v, &c->system_mib)) return failf(C, "answer file: SystemMiB=%s", v);
    v = ini_get(&C->ini, "Layout", "Win98MiB");
    if (v && *v && parse_u64(v, &c->win98_mib)) return failf(C, "answer file: Win98MiB=%s", v);
    if (c->system_mib && c->system_mib < MIN_SYSTEM_MIB) return failf(C, "answer file: SystemMiB must be >= %llu", MIN_SYSTEM_MIB);
    if (c->win98_mib && c->win98_mib < 64) return failf(C, "answer file: Win98MiB must be 0 or >= 64 (FAT32 minimum)");
    if (yesno(ini_get(&C->ini, "Layout", "Win98HybridMBR"), 0, &c->win98_hybrid)) return failf(C, "answer file: Win98HybridMBR");
    if (yesno(ini_get(&C->ini, "Layout", "BiosBootCode"), 1, &c->bios_boot_code)) return failf(C, "answer file: BiosBootCode");
    copy_str(c->hostname, sizeof c->hostname, ini_get(&C->ini, "System", "Hostname"));
    if (!c->hostname[0]) copy_str(c->hostname, sizeof c->hostname, "SHIZUKU");
    for (i = 0; c->hostname[i]; ++i) {
        const char h = c->hostname[i];
        if (!((h >= 'a' && h <= 'z') || (h >= 'A' && h <= 'Z') || (h >= '0' && h <= '9') || (h == '-' && i)))
            return failf(C, "answer file: Hostname=%s (letters, digits, '-')", c->hostname);
    }
    copy_str(c->seed, sizeof c->seed, ini_get(&C->ini, "System", "GuidSeed"));
    copy_str(c->drivers, sizeof c->drivers, ini_get(&C->ini, "Drivers", "Install"));
    if (!c->drivers[0]) copy_str(c->drivers, sizeof c->drivers, "all");
    say(C, "answer file %s: Select=%s Reboot=%s SystemMiB=%llu Win98MiB=%llu Hostname=%s Drivers=%s", path, c->select,
        c->power == SETUP_POWER_REBOOT ? "reboot" : c->power == SETUP_POWER_SHUTDOWN ? "shutdown" : "none",
        (unsigned long long)c->system_mib, (unsigned long long)c->win98_mib, c->hostname, c->drivers);
    return 0;
}

/* ---------------------------------------------------------------- manifest */
static int package_selected(ctx_t *C, const char *pkg)
{
    const char *d = C->cfg.drivers;
    const size_t n = pkg ? strlen(pkg) : 0;
    if (!pkg || !strcmp(pkg, "base")) return 1;
    if (sncmp(pkg, "driver-", 7)) return 0;
    if (text_ieq(d, "all")) return 1;
    if (text_ieq(d, "none")) return 0;
    while (*d) {                                    /* comma list of driver names without the "driver-" prefix */
        const char *s;
        size_t k;
        while (*d == ',' || *d == ' ') ++d;
        s = d;
        while (*d && *d != ',' && *d != ' ') ++d;
        k = (size_t)(d - s);
        if (k && k == n - 7 && !sncmp(s, pkg + 7, k)) return 1;
    }
    return 0;
}

static int read_manifest(ctx_t *C)
{
    char path[240], err[96];
    const jnode_t *root, *esp, *sys, *list, *x;
    const char *s;
    uint64_t v;
    uint8_t sha[32];
    join(C, "manifest.json", path, sizeof path);
    if (load_file(C, path, &C->manifest_text, &C->manifest_len)) return -1;
    if (json_parse(C->P, C->manifest_text, (size_t)C->manifest_len, &C->man, err, sizeof err))
        return failf(C, "manifest.json: %s", err);
    root = C->man.root;
    s = json_str(root, "schema");
    if (!s || strcmp(s, MANIFEST_SCHEMA)) return failf(C, "manifest.json: schema is not %s", MANIFEST_SCHEMA);
    esp = json_get(root, "esp");
    sys = json_get(root, "system");
    if (!esp || !sys) return failf(C, "manifest.json: esp and system sections are required");
    if (!json_str(esp, "image") || json_u64(esp, "bytes", &v) || !v || v % MIB || !json_str(esp, "sha256") ||
        unhex_sha(json_str(esp, "sha256"), sha))
        return failf(C, "manifest.json: esp needs image, bytes (MiB multiple) and sha256");
    if (!json_str(sys, "archive")) return failf(C, "manifest.json: system.archive missing");
    list = json_get(sys, "files");
    if (!list || list->type != J_ARR) return failf(C, "manifest.json: system.files missing");
    for (x = list->kid; x; x = x->next)
        if (!json_str(x, "path") || json_str(x, "path")[0] != '/' || json_u64(x, "bytes", &v) || !json_str(x, "sha256") ||
            unhex_sha(json_str(x, "sha256"), sha))
            return failf(C, "manifest.json: malformed system.files entry");
    list = json_get(sys, "dirs");
    if (!list || list->type != J_ARR) return failf(C, "manifest.json: system.dirs missing");
    for (x = list->kid; x; x = x->next)
        if (!json_str(x, "path") || json_str(x, "path")[0] != '/') return failf(C, "manifest.json: malformed system.dirs entry");
    say(C, "manifest: %s, %s", json_str(root, "product") ? json_str(root, "product") : "(no product)", MANIFEST_SCHEMA);
    return 0;
}

/* ---------------------------------------------------------------- disks */
static int disk_rw(ctx_t *C, int write, uint64_t lba, uint64_t count, void *buf)
{
    uint8_t *p = buf;
    const uint32_t max = C->P->max_io_sectors ? C->P->max_io_sectors : 128;
    while (count) {
        const uint32_t n = count < max ? (uint32_t)count : max;
        const int st = write ? C->P->disk_write(C->P->ctx, C->disk, lba, n, p) : C->P->disk_read(C->P->ctx, C->disk, lba, n, p);
        if (st) return failf(C, "%s error on %s at LBA %llu (%u sectors)", write ? "write" : "read", C->di.name,
                             (unsigned long long)lba, n);
        lba += n;
        count -= n;
        p += (size_t)n * C->ss;
    }
    return 0;
}

static int starts_with(const char *s, const char *p) { return !sncmp(s, p, strlen(p)); }

static uint64_t need_bytes(ctx_t *C)
{
    uint64_t esp = 0;
    json_u64(json_get(C->man.root, "esp"), "bytes", &esp);
    return esp + (C->cfg.system_mib ? C->cfg.system_mib : MIN_SYSTEM_MIB) * MIB + C->cfg.win98_mib * MIB + 4 * MIB;
}

static int select_target(ctx_t *C)
{
    const unsigned n = C->P->disk_count(C->P->ctx);
    const config_t *c = &C->cfg;
    const uint64_t need = need_bytes(C), minb = c->min_mib * MIB > need ? c->min_mib * MIB : need;
    unsigned i, found = 0xffffffffu;
    plat_disk_t d, best;
    say(C, "block devices: %u", n);
    for (i = 0; i < n; ++i) {
        int ok;
        uint64_t bytes;
        if (C->P->disk_info(C->P->ctx, i, &d)) continue;
        bytes = d.sectors * d.sector_size;
        ok = !(d.flags & (PLAT_DISK_PARTITION | PLAT_DISK_READONLY)) && d.sector_size == 512 && bytes >= minb;
        say(C, "  [%u] %s %llu MiB, %u-byte sectors, serial '%s'%s%s", i, d.name, (unsigned long long)(bytes / MIB),
            d.sector_size, d.serial, d.flags & PLAT_DISK_PARTITION ? ", partition" : "",
            ok ? "" : d.flags & PLAT_DISK_PARTITION ? "" : ", not eligible");
        if (!ok) continue;
        if (text_ieq(c->select, "first") || (text_ieq(c->select, "first-nvme") && starts_with(d.name, "nvme")) ||
            (text_ieq(c->select, "first-ahci") && starts_with(d.name, "ahci")) ||
            (text_ieq(c->select, "first-mmc") && (starts_with(d.name, "mmc") || starts_with(d.name, "sdhci"))) ||
            (text_ieq(c->select, "first-ram") && starts_with(d.name, "ram")) ||
            (text_ieq(c->select, "size") && bytes / MIB == c->size_mib) ||
            (text_ieq(c->select, "serial") && !strcmp(d.serial, c->serial)) ||
            (text_ieq(c->select, "name") && !strcmp(d.name, c->name))) {
            if (found == 0xffffffffu) { found = i; best = d; }
        } else if (text_ieq(c->select, "largest") || text_ieq(c->select, "smallest")) {
            if (found == 0xffffffffu || (text_ieq(c->select, "largest") ? d.sectors > best.sectors : d.sectors < best.sectors)) {
                found = i;
                best = d;
            }
        }
    }
    if (found == 0xffffffffu)
        return failf(C, "no block device matches Select=%s (needs a writable whole disk >= %llu MiB, 512-byte sectors)",
                     c->select, (unsigned long long)(minb / MIB));
    C->disk = found;
    C->di = best;
    C->ss = best.sector_size;
    say(C, "target: [%u] %s, %llu MiB, serial '%s' (Select=%s)", found, best.name,
        (unsigned long long)(best.sectors * best.sector_size / MIB), best.serial, c->select);
    return 0;
}

static int check_blank(ctx_t *C)
{
    uint8_t *b = C->buf;
    int used = 0, i;
    if (disk_rw(C, 0, 0, 2, b)) return -1;
    if (b[510] == 0x55 && b[511] == 0xaa)
        for (i = 0; i < 4; ++i) if (b[446 + 16 * i + 4]) used = 1;
    if (!memcmp(b + C->ss, "EFI PART", 8)) used = 1;
    if (!used) { say(C, "target has no partition table"); return 0; }
    if (!C->cfg.allow_nonempty)
        return failf(C, "target %s already has a partition table; set [Target] AllowNonEmpty=yes to erase it", C->di.name);
    say(C, "target has a partition table; AllowNonEmpty=yes: it will be erased");
    return 0;
}

/* ---------------------------------------------------------------- identifiers */
static void derive(ctx_t *C, const char *label, uint8_t *out, size_t n)
{
    uint8_t d[32];
    if (C->cfg.seed[0]) {
        void *s = C->P->sha_begin(C->P->ctx);
        C->P->sha_update(C->P->ctx, s, C->cfg.seed, (uint32_t)strlen(C->cfg.seed));
        C->P->sha_update(C->P->ctx, s, ":", 1);
        C->P->sha_update(C->P->ctx, s, label, (uint32_t)strlen(label));
        C->P->sha_end(C->P->ctx, s, d);
        memcpy(out, d, n);
    } else if (C->P->random(C->P->ctx, out, (uint32_t)n)) {
        /* no RNG: hash the clock and the label (unique enough for one machine; logged) */
        uint64_t t = C->P->now(C->P->ctx);
        void *s = C->P->sha_begin(C->P->ctx);
        C->P->sha_update(C->P->ctx, s, &t, sizeof t);
        C->P->sha_update(C->P->ctx, s, label, (uint32_t)strlen(label));
        C->P->sha_update(C->P->ctx, s, C->di.serial, (uint32_t)strlen(C->di.serial));
        C->P->sha_end(C->P->ctx, s, d);
        memcpy(out, d, n);
    }
}

static void make_guid(ctx_t *C, const char *label, uint8_t g[16])      /* GPT (mixed-endian) random GUID, version 4 */
{
    derive(C, label, g, 16);
    g[7] = (uint8_t)((g[7] & 0x0f) | 0x40);
    g[8] = (uint8_t)((g[8] & 0x3f) | 0x80);
}

/* ---------------------------------------------------------------- layout */
static int plan_layout(ctx_t *C)
{
    const uint64_t align = MIB / C->ss, first = gpt_first_usable(C->ss), last = gpt_last_usable(C->ss, C->di.sectors);
    const uint64_t end = (last + 1) / align * align;                      /* aligned exclusive end */
    uint64_t esp_bytes = 0, p2_start, p2_end, sys_sectors;
    json_u64(json_get(C->man.root, "esp"), "bytes", &esp_bytes);
    C->pfirst[0] = align;
    if (C->pfirst[0] < first) return failf(C, "unexpected GPT geometry");
    C->plast[0] = C->pfirst[0] + esp_bytes / C->ss - 1;
    p2_start = (C->plast[0] + 1 + align - 1) / align * align;
    if (C->cfg.system_mib) {
        sys_sectors = C->cfg.system_mib * (MIB / C->ss);
        p2_end = p2_start + sys_sectors;
    } else {
        p2_end = end - C->cfg.win98_mib * (MIB / C->ss);
        if (p2_end <= p2_start) return failf(C, "disk too small");
        sys_sectors = p2_end - p2_start;
    }
    if (sys_sectors < MIN_SYSTEM_MIB * (MIB / C->ss)) return failf(C, "system partition would be smaller than %llu MiB", MIN_SYSTEM_MIB);
    C->pfirst[1] = p2_start;
    C->plast[1] = p2_end - 1;
    C->nparts = 2;
    if (C->cfg.win98_mib) {
        C->pfirst[2] = p2_end;
        C->plast[2] = p2_end + C->cfg.win98_mib * (MIB / C->ss) - 1;
        C->nparts = 3;
    }
    if (C->plast[C->nparts - 1] > last)
        return failf(C, "layout does not fit: needs LBA %llu, last usable is %llu", (unsigned long long)C->plast[C->nparts - 1],
                     (unsigned long long)last);
    say(C, "layout: p1 ESP LBA %llu-%llu (%llu MiB), p2 ShizukuFS LBA %llu-%llu (%llu MiB)%s",
        (unsigned long long)C->pfirst[0], (unsigned long long)C->plast[0], (unsigned long long)(esp_bytes / MIB),
        (unsigned long long)C->pfirst[1], (unsigned long long)C->plast[1],
        (unsigned long long)((C->plast[1] - C->pfirst[1] + 1) * C->ss / MIB), C->nparts == 3 ? ", p3 Win98 FAT32:" : "");
    if (C->nparts == 3)
        say(C, "        p3 LBA %llu-%llu (%llu MiB), empty; Windows 98 is not bundled", (unsigned long long)C->pfirst[2],
            (unsigned long long)C->plast[2], (unsigned long long)C->cfg.win98_mib);
    return 0;
}

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t le64(const uint8_t *p) { return le32(p) | (uint64_t)le32(p + 4) << 32; }

/* ---------------------------------------------------------------- p1: ESP
 * Payload ESP.SIM ("SHZSIMG1" sparse image): 64-byte header {magic[8], u32 block_size (4096), u32 0, u32 chunk_count,
 * u32 0, u64 image_bytes, u8 sha256[32] of the expanded image}, then chunk_count x {u64 first_block, u32 blocks, u32 0}
 * in ascending order, then the chunks' data. Blocks outside every chunk are zero. The installer writes EVERY block,
 * zeros included, so the partition equals esp.img byte for byte. */
static int write_esp(ctx_t *C)
{
    const jnode_t *esp = json_get(C->man.root, "esp");
    char path[240], hexs[65];
    void *h, *s;
    uint64_t fsize, total = 0, block, blocks, chunk_i = 0, nchunks, cur_first = 0, cur_count = 0, data_off;
    uint8_t hdr[64], want[32], got[32], ent[16];
    uint32_t bs;
    join(C, json_str(esp, "image"), path, sizeof path);
    json_u64(esp, "bytes", &total);
    unhex_sha(json_str(esp, "sha256"), want);
    if (C->P->file_open(C->P->ctx, path, &h, &fsize)) return failf(C, "cannot open %s", path);
    if (fsize < 64 || C->P->file_read(C->P->ctx, h, 0, hdr, 64) || memcmp(hdr, SIMG_MAGIC, 8)) {
        C->P->file_close(C->P->ctx, h);
        return failf(C, "%s is not a " SIMG_MAGIC " sparse image", path);
    }
    bs = le32(hdr + 8);
    nchunks = le32(hdr + 16);
    if (bs != 4096 || le64(hdr + 24) != total || memcmp(hdr + 32, want, 32)) {
        C->P->file_close(C->P->ctx, h);
        return failf(C, "%s: block size, image size or image sha256 does not match the manifest", path);
    }
    say(C, "p1: writing %s (%llu MiB, %llu data chunk(s)) to LBA %llu", json_str(esp, "image"),
        (unsigned long long)(total / MIB), (unsigned long long)nchunks, (unsigned long long)C->pfirst[0]);
    blocks = total / bs;
    data_off = 64 + nchunks * 16;
    s = C->P->sha_begin(C->P->ctx);
    for (block = 0; block < blocks;) {
        const uint32_t per = IOBUF / bs;
        uint32_t i;
        for (i = 0; i < per && block < blocks; ++i, ++block) {
            uint8_t *dst = C->buf + (size_t)i * bs;
            while (chunk_i < nchunks && block >= cur_first + cur_count) {       /* advance to the chunk covering block */
                if (C->P->file_read(C->P->ctx, h, 64 + chunk_i * 16, ent, 16)) { C->P->file_close(C->P->ctx, h); return failf(C, "%s: read error", path); }
                if (cur_count) data_off += cur_count * bs;
                cur_first = le64(ent);
                cur_count = le32(ent + 8);
                ++chunk_i;
                if (cur_first + cur_count > blocks || data_off + cur_count * bs > fsize) {
                    C->P->file_close(C->P->ctx, h);
                    return failf(C, "%s: chunk table out of range", path);
                }
            }
            if (block >= cur_first && block < cur_first + cur_count) {
                if (C->P->file_read(C->P->ctx, h, data_off + (block - cur_first) * bs, dst, bs)) {
                    C->P->file_close(C->P->ctx, h);
                    return failf(C, "%s: read error", path);
                }
            } else {
                memset(dst, 0, bs);
            }
        }
        C->P->sha_update(C->P->ctx, s, C->buf, i * bs);
        if (disk_rw(C, 1, C->pfirst[0] + (block - i) * (bs / C->ss), (uint64_t)i * (bs / C->ss), C->buf)) {
            C->P->file_close(C->P->ctx, h);
            return -1;
        }
    }
    C->P->file_close(C->P->ctx, h);
    C->P->sha_end(C->P->ctx, s, got);
    hex(got, 32, hexs);
    if (memcmp(got, want, 32)) return failf(C, "p1: the ESP image in the payload does not match the manifest (sha256 %s)", hexs);
    say(C, "p1: payload image sha256 %s matches the manifest", hexs);
    if (C->P->disk_flush(C->P->ctx, C->disk)) return failf(C, "flush failed");
    /* read back the whole partition */
    s = C->P->sha_begin(C->P->ctx);
    for (block = 0; block < total / C->ss;) {
        const uint64_t n = total / C->ss - block < IOBUF / C->ss ? total / C->ss - block : IOBUF / C->ss;
        if (disk_rw(C, 0, C->pfirst[0] + block, n, C->buf)) return -1;
        C->P->sha_update(C->P->ctx, s, C->buf, (uint32_t)(n * C->ss));
        block += n;
    }
    C->P->sha_end(C->P->ctx, s, got);
    hex(got, 32, hexs);
    if (memcmp(got, want, 32)) return failf(C, "p1: read-back sha256 %s differs from the manifest", hexs);
    say(C, "p1: read back %llu MiB from the disk, sha256 %s = manifest esp.sha256: OK", (unsigned long long)(total / MIB), hexs);
    return 0;
}

/* ---------------------------------------------------------------- p2: ShizukuFS */
static int p2_read(void *ctx, uint64_t block, uint32_t count, void *buf)
{
    ctx_t *C = ctx;
    const uint64_t per = SFSW_BLOCK / C->ss;
    if ((block + count) * per > C->plast[1] - C->pfirst[1] + 1) return -1;
    return disk_rw(C, 0, C->pfirst[1] + block * per, (uint64_t)count * per, buf) ? -1 : 0;
}
static int p2_write(void *ctx, uint64_t block, uint32_t count, const void *buf)
{
    ctx_t *C = ctx;
    const uint64_t per = SFSW_BLOCK / C->ss;
    if ((block + count) * per > C->plast[1] - C->pfirst[1] + 1) return -1;
    return disk_rw(C, 1, C->pfirst[1] + block * per, (uint64_t)count * per, (void *)(uintptr_t)buf) ? -1 : 0;
}
static void *io_alloc(void *ctx, size_t n) { ctx_t *C = ctx; return C->P->alloc(C->P->ctx, n); }
static void io_free(void *ctx, void *p) { ctx_t *C = ctx; C->P->free(C->P->ctx, p); }


static int open_archive(ctx_t *C)
{
    const char *name = json_str(json_get(C->man.root, "system"), "archive");
    char path[240];
    uint8_t hdr[16];
    uint64_t size;
    uint32_t i;
    size_t names = 0;
    join(C, name, path, sizeof path);
    if (C->P->file_open(C->P->ctx, path, &C->arc, &size)) return failf(C, "cannot open %s", path);
    if (size < 16 || C->P->file_read(C->P->ctx, C->arc, 0, hdr, 16) || memcmp(hdr, "SHZARC01", 8))
        return failf(C, "%s is not a SHZARC01 archive", path);
    C->arc_n = (uint32_t)hdr[8] | (uint32_t)hdr[9] << 8 | (uint32_t)hdr[10] << 16 | (uint32_t)hdr[11] << 24;
    if (C->arc_n > 65536 || 16 + (uint64_t)C->arc_n * 136 > size) return failf(C, "%s: bad entry count", path);
    C->arc_e = C->P->alloc(C->P->ctx, (size_t)C->arc_n * sizeof *C->arc_e);
    C->arc_names = C->P->alloc(C->P->ctx, (size_t)C->arc_n * 121);
    if (!C->arc_e || !C->arc_names) return failf(C, "out of memory");
    for (i = 0; i < C->arc_n; ++i) {
        uint8_t e[136];
        char *nm = C->arc_names + names;
        unsigned k;
        if (C->P->file_read(C->P->ctx, C->arc, 16 + (uint64_t)i * 136, e, 136)) return failf(C, "%s: read error", path);
        for (k = 0; k < 120 && e[k]; ++k) nm[k] = e[k] == '\\' ? '/' : (char)e[k];
        nm[k] = 0;
        names += k + 1;
        C->arc_e[i].path = nm;
        C->arc_e[i].off = le64(e + 120);
        C->arc_e[i].size = le64(e + 128);
        if (C->arc_e[i].off > size || C->arc_e[i].size > size - C->arc_e[i].off) return failf(C, "%s: entry out of range", path);
    }
    say(C, "p2: archive %s, %u file(s)", name, C->arc_n);
    return 0;
}

static const arc_entry_t *arc_find(ctx_t *C, const char *path)
{
    uint32_t i;
    for (i = 0; i < C->arc_n; ++i) if (!strcmp(C->arc_e[i].path, path)) return &C->arc_e[i];
    return 0;
}

typedef struct { const char *path; const char *data; uint64_t len; uint32_t handle; } gen_file_t;
#define MAX_GEN 3

static int plan_system(ctx_t *C, sfsw_t **wout, uint32_t **handles, uint32_t *log_handle, gen_file_t *gen, unsigned ngen)
{
    const jnode_t *sys = json_get(C->man.root, "system"), *x;
    sfsw_io io = {C, p2_read, p2_write, io_alloc, io_free};
    sfsw_params prm;
    sfsw_info info;
    sfsw_t *w;
    int err;
    unsigned i;
    uint32_t n = 0, cap = 0;
    uint64_t nbytes = 0;
    char uuid[37];
    static const char *const setup_dirs[] = {"/SHZ", "/SHZ/SETUP", "/SHZ/SETUP/log", 0};
    for (x = json_get(sys, "files")->kid; x; x = x->next) ++cap;
    *handles = C->P->alloc(C->P->ctx, (cap + 1) * sizeof **handles);
    if (!*handles) return failf(C, "out of memory");
    memset(&prm, 0, sizeof prm);
    prm.bytes = (C->plast[1] - C->pfirst[1] + 1) * C->ss;
    prm.time = (uint32_t)C->P->now(C->P->ctx);
    memcpy(prm.uuid, C->fs_uuid, 16);
    copy_str(prm.label, sizeof prm.label, json_str(sys, "label") ? json_str(sys, "label") : "SHZSYS");
    w = sfsw_create(&io, &prm, &err);
    if (!w) return failf(C, "p2: ShizukuFS format: %s", sfsw_strerror(err));
    *wout = w;
    for (x = json_get(sys, "dirs")->kid; x; x = x->next) {
        if (!package_selected(C, json_str(x, "package"))) continue;
        if ((err = sfsw_mkdir(w, json_str(x, "path")))) return failf(C, "p2: mkdir %s: %s", json_str(x, "path"), sfsw_strerror(err));
    }
    for (i = 0; setup_dirs[i]; ++i)
        if ((err = sfsw_mkdir(w, setup_dirs[i])) && err != SFSW_EEXIST) return failf(C, "p2: mkdir %s: %s", setup_dirs[i], sfsw_strerror(err));
    for (x = json_get(sys, "files")->kid; x; x = x->next) {
        uint64_t bytes;
        const arc_entry_t *a;
        if (!package_selected(C, json_str(x, "package"))) continue;
        json_u64(x, "bytes", &bytes);
        a = arc_find(C, json_str(x, "path"));
        if (!a || a->size != bytes) return failf(C, "p2: %s is missing from the archive or has the wrong size", json_str(x, "path"));
        if ((err = sfsw_add_file(w, json_str(x, "path"), bytes, &(*handles)[n])))
            return failf(C, "p2: add %s: %s", json_str(x, "path"), sfsw_strerror(err));
        ++n;
        nbytes += bytes;
    }
    for (i = 0; i < ngen; ++i)
        if ((err = sfsw_add_file(w, gen[i].path, gen[i].len, &gen[i].handle)))
            return failf(C, "p2: add %s: %s", gen[i].path, sfsw_strerror(err));
    if ((err = sfsw_add_file(w, "/SHZ/SETUP/log/install.log", LOG_CAP, log_handle)))
        return failf(C, "p2: add install.log: %s", sfsw_strerror(err));
    if ((err = sfsw_layout(w))) return failf(C, "p2: layout: %s", sfsw_strerror(err));
    sfsw_get_info(w, &info);
    gpt_guid_format(C->fs_uuid, uuid);
    say(C, "p2: ShizukuFS v1 (ext4 on-disk format): %llu blocks of 4 KiB, %u group(s), %u inodes, uuid %s",
        (unsigned long long)info.blocks, info.groups, info.inodes, uuid);
    say(C, "p2: %u payload file(s), %llu bytes, %u director(ies) incl. generated", n, (unsigned long long)nbytes, info.dirs);
    return 0;
}

static int write_system_data(ctx_t *C, sfsw_t *w, const uint32_t *handles, gen_file_t *gen, unsigned ngen)
{
    const jnode_t *sys = json_get(C->man.root, "system"), *x;
    uint32_t k = 0;
    unsigned i;
    int err;
    for (x = json_get(sys, "files")->kid; x; x = x->next) {
        const arc_entry_t *a;
        uint8_t want[32], got[32];
        uint64_t off = 0;
        void *s;
        if (!package_selected(C, json_str(x, "package"))) continue;
        a = arc_find(C, json_str(x, "path"));
        unhex_sha(json_str(x, "sha256"), want);
        s = C->P->sha_begin(C->P->ctx);
        while (off < a->size) {
            const uint32_t n = a->size - off < IOBUF ? (uint32_t)(a->size - off) : IOBUF;
            if (C->P->file_read(C->P->ctx, C->arc, a->off + off, C->buf, n)) return failf(C, "p2: archive read error");
            C->P->sha_update(C->P->ctx, s, C->buf, n);
            if ((err = sfsw_write(w, handles[k], off, C->buf, n))) return failf(C, "p2: write %s: %s", a->path, sfsw_strerror(err));
            off += n;
        }
        C->P->sha_end(C->P->ctx, s, got);
        if (memcmp(got, want, 32)) return failf(C, "p2: %s in the payload does not match its manifest sha256", a->path);
        ++k;
    }
    for (i = 0; i < ngen; ++i) {
        uint64_t off = 0;
        while (off < gen[i].len) {
            const uint32_t n = gen[i].len - off < IOBUF ? (uint32_t)(gen[i].len - off) : IOBUF;
            memcpy(C->buf, gen[i].data + off, n);
            if ((err = sfsw_write(w, gen[i].handle, off, C->buf, n))) return failf(C, "p2: write %s: %s", gen[i].path, sfsw_strerror(err));
            off += n;
        }
    }
    if ((err = sfsw_commit(w))) return failf(C, "p2: metadata: %s", sfsw_strerror(err));
    if (C->P->disk_flush(C->P->ctx, C->disk)) return failf(C, "flush failed");
    say(C, "p2: data and metadata written (%u payload file(s) hashed against the manifest on the way)", k);
    return 0;
}

/* Reads every installed file back through an independent decode of the on-disk structures. */
static int verify_system(ctx_t *C, gen_file_t *gen, unsigned ngen)
{
    const jnode_t *sys = json_get(C->man.root, "system"), *x;
    sfsw_io io = {C, p2_read, p2_write, io_alloc, io_free};
    sfsr_t *r;
    int err, is_dir;
    unsigned i;
    uint32_t ino, done;
    uint64_t size, ndirs = 0;
    r = sfsr_open(&io, &err);
    if (!r) return failf(C, "p2 verify: cannot open the new volume: %s", sfsw_strerror(err));
    for (x = json_get(sys, "dirs")->kid; x; x = x->next) {
        if (!package_selected(C, json_str(x, "package"))) continue;
        if ((err = sfsr_lookup(r, json_str(x, "path"), &ino, &size, &is_dir)) || !is_dir) {
            sfsr_close(r);
            return failf(C, "p2 verify: directory %s: %s", json_str(x, "path"), err ? sfsw_strerror(err) : "not a directory");
        }
        ++ndirs;
    }
    for (x = json_get(sys, "files")->kid; x; x = x->next) {
        uint8_t want[32], got[32];
        uint64_t bytes, off = 0;
        void *s;
        const char *path = json_str(x, "path");
        if (!package_selected(C, json_str(x, "package"))) continue;
        json_u64(x, "bytes", &bytes);
        unhex_sha(json_str(x, "sha256"), want);
        if ((err = sfsr_lookup(r, path, &ino, &size, &is_dir)) || is_dir || size != bytes) {
            sfsr_close(r);
            return failf(C, "p2 verify: %s: %s", path, err ? sfsw_strerror(err) : "wrong type or size");
        }
        s = C->P->sha_begin(C->P->ctx);
        while (off < size) {
            const uint32_t n = size - off < IOBUF ? (uint32_t)(size - off) : IOBUF;
            if ((err = sfsr_read(r, ino, off, C->buf, n, &done)) || done != n) {
                sfsr_close(r);
                return failf(C, "p2 verify: read %s: %s", path, sfsw_strerror(err));
            }
            C->P->sha_update(C->P->ctx, s, C->buf, n);
            off += n;
        }
        C->P->sha_end(C->P->ctx, s, got);
        if (memcmp(got, want, 32)) {
            char hx[65];
            hex(got, 32, hx);
            sfsr_close(r);
            return failf(C, "p2 verify: %s read back with sha256 %s, manifest says %s", path, hx, json_str(x, "sha256"));
        }
        C->files_ok++;
        C->bytes_ok += size;
    }
    for (i = 0; i < ngen; ++i) {
        if ((err = sfsr_lookup(r, gen[i].path, &ino, &size, &is_dir)) || size != gen[i].len ||
            (size && ((err = sfsr_read(r, ino, 0, C->buf, (uint32_t)size, &done)) || memcmp(C->buf, gen[i].data, (size_t)size)))) {
            sfsr_close(r);
            return failf(C, "p2 verify: generated file %s did not read back", gen[i].path);
        }
    }
    sfsr_close(r);
    say(C, "p2 verify: %llu file(s), %llu bytes: sha256 of every file read back from the disk matches the manifest; "
        "%llu director(ies) present", (unsigned long long)C->files_ok, (unsigned long long)C->bytes_ok, (unsigned long long)ndirs);
    return 0;
}

/* ---------------------------------------------------------------- p3: Windows 98 FAT32 (empty) */
static int p3_write(void *ctx, uint64_t sector, uint32_t count, const void *buf)
{
    ctx_t *C = ctx;
    if (sector + count > C->plast[2] - C->pfirst[2] + 1) return -1;
    return disk_rw(C, 1, C->pfirst[2] + sector, count, (void *)(uintptr_t)buf) ? -1 : 0;
}

static int format_win98(ctx_t *C)
{
    fat32_io io = {C, p3_write};
    fat32_params prm;
    uint32_t clusters = 0;
    int st;
    memset(&prm, 0, sizeof prm);
    prm.sectors = C->plast[2] - C->pfirst[2] + 1;
    prm.hidden = (uint32_t)C->pfirst[2];
    prm.volume_id = C->fat_id;
    memcpy(prm.label, "WIN98      ", 11);
    if ((st = fat32_format(&io, &prm, &clusters)))
        return failf(C, "p3: FAT32 format failed (%s)", st == -1 ? "size outside FAT32 limits" : "I/O error");
    if (disk_rw(C, 0, C->pfirst[2], 1, C->buf)) return -1;
    if (C->buf[510] != 0x55 || C->buf[511] != 0xaa || memcmp(C->buf + 0x52, "FAT32   ", 8))
        return failf(C, "p3: boot sector did not read back");
    say(C, "p3: empty FAT32 volume WIN98, %u clusters, volume id %x (for the user's own Windows 98; nothing bundled)",
        clusters, C->fat_id);
    return 0;
}

/* ---------------------------------------------------------------- partition tables */
static int wipe_tables(ctx_t *C)
{
    const uint64_t n = gpt_first_usable(C->ss);
    memset(C->buf, 0, (size_t)n * C->ss);
    if (disk_rw(C, 1, 0, n, C->buf) || disk_rw(C, 1, C->di.sectors - (n - 1), n - 1, C->buf)) return -1;
    if (C->P->disk_flush(C->P->ctx, C->disk)) return failf(C, "flush failed");
    say(C, "old partition tables erased (LBA 0-%llu and the last %llu sectors)", (unsigned long long)(n - 1),
        (unsigned long long)(n - 1));
    return 0;
}

static int write_gpt(ctx_t *C)
{
    gpt_layout_t L;
    const uint64_t asec = GPT_ARRAY_BYTES / C->ss, last = C->di.sectors - 1;
    uint8_t *mbr = C->buf2, *prim = mbr + C->ss, *array = prim + C->ss, *backup = array + GPT_ARRAY_BYTES, *rb = C->buf;
    char g[37];
    int st, i;
    static const char *const names[3] = {"EFI system partition", "ShizukuFS system", "Windows 98"};
    memset(&L, 0, sizeof L);
    L.sector_size = C->ss;
    L.sectors = C->di.sectors;
    memcpy(L.disk_guid, C->disk_guid, 16);
    L.mbr_signature = C->mbr_sig;
    L.boot_code = C->have_mbr_code && C->cfg.bios_boot_code ? C->mbr_code : 0;
    L.count = (unsigned)C->nparts;
    for (i = 0; i < C->nparts; ++i) {
        gpt_part_t *p = &L.part[i];
        memcpy(p->type, i == 0 ? GPT_TYPE_ESP : i == 1 ? GPT_TYPE_LINUX_FS : GPT_TYPE_MS_BASIC_DATA, 16);
        memcpy(p->guid, C->part_guid[i], 16);
        p->first_lba = C->pfirst[i];
        p->last_lba = C->plast[i];
        p->attrs = i == 0 ? GPT_ATTR_LEGACY_BIOS_BOOTABLE : 0;     /* the MBR code chain-loads the ESP's boot sector */
        copy_str(p->name, sizeof p->name, names[i]);
        p->mbr_type = (uint8_t)(i == 2 && C->cfg.win98_hybrid ? 0x0c : 0);
    }
    if ((st = gpt_build(&L, mbr, prim, array, backup))) return failf(C, "GPT build failed (%d)", st);
    if (disk_rw(C, 1, last - asec, asec, array) || disk_rw(C, 1, last, 1, backup) || disk_rw(C, 1, 2, asec, array) ||
        disk_rw(C, 1, 1, 1, prim) || disk_rw(C, 1, 0, 1, mbr))
        return -1;
    if (C->P->disk_flush(C->P->ctx, C->disk)) return failf(C, "flush failed");
    /* read back and check both copies */
    if (disk_rw(C, 0, 0, 2 + asec, rb)) return -1;
    if (memcmp(rb, mbr, C->ss)) return failf(C, "protective MBR did not read back");
    if ((st = gpt_check(rb + C->ss, rb + 2 * C->ss, C->ss, 1, C->di.sectors))) return failf(C, "primary GPT check failed (%d)", st);
    if (disk_rw(C, 0, last - asec, asec + 1, rb)) return -1;
    if ((st = gpt_check(rb + asec * C->ss, rb, C->ss, last, C->di.sectors))) return failf(C, "backup GPT check failed (%d)", st);
    gpt_guid_format(C->disk_guid, g);
    say(C, "GPT written: disk %s, %d partition(s), protective MBR%s%s; primary and backup headers read back, CRC32 OK", g,
        C->nparts, L.boot_code ? " with BIOS boot code" : " without boot code",
        C->cfg.win98_hybrid && C->nparts == 3 ? ", hybrid entry for p3 (type 0x0C)" : "");
    for (i = 0; i < C->nparts; ++i) {
        gpt_guid_format(C->part_guid[i], g);
        say(C, "  p%d %-20s LBA %llu-%llu guid %s", i + 1, names[i], (unsigned long long)C->pfirst[i],
            (unsigned long long)C->plast[i], g);
    }
    return 0;
}

/* ---------------------------------------------------------------- driver */
static int load_mbr_code(ctx_t *C)
{
    const jnode_t *m = json_get(C->man.root, "mbr");
    char path[240];
    void *h, *s;
    uint64_t size;
    uint8_t want[32], got[32];
    if (!m) { say(C, "manifest has no mbr entry: the protective MBR gets no BIOS boot code"); return 0; }
    join(C, json_str(m, "file") ? json_str(m, "file") : "", path, sizeof path);
    if (!json_str(m, "sha256") || unhex_sha(json_str(m, "sha256"), want)) return failf(C, "manifest: mbr.sha256 missing");
    if (C->P->file_open(C->P->ctx, path, &h, &size)) return failf(C, "cannot open %s", path);
    if (size != 440 || C->P->file_read(C->P->ctx, h, 0, C->mbr_code, 440)) {
        C->P->file_close(C->P->ctx, h);
        return failf(C, "%s must be exactly 440 bytes", path);
    }
    C->P->file_close(C->P->ctx, h);
    s = C->P->sha_begin(C->P->ctx);
    C->P->sha_update(C->P->ctx, s, C->mbr_code, 440);
    C->P->sha_end(C->P->ctx, s, got);
    if (memcmp(want, got, 32)) return failf(C, "%s does not match its manifest sha256", path);
    C->have_mbr_code = 1;
    return 0;
}

static char *append(char *o, const char *end, const char *s)
{
    while (*s && o < end) *o++ = *s++;
    return o;
}

static char *build_system_ini(ctx_t *C, uint64_t *len)
{
    char *t = C->P->alloc(C->P->ctx, 4096), *o = t, *end = t + 4000, g[37], when[24];
    int i;
    static const char *const keys[3] = {"EspPartitionGuid=", "SystemPartitionGuid=", "Win98PartitionGuid="};
    if (!t) return 0;
    iso_time(C->started, when);
    o = append(o, end, "; ShizukuDOS system identity, written by " SETUP_VERSION "\r\n[System]\r\nHostname=");
    o = append(o, end, C->cfg.hostname);
    o = append(o, end, "\r\n\r\n[Install]\r\nProduct=");
    o = append(o, end, json_str(C->man.root, "product") ? json_str(C->man.root, "product") : "ShizukuDOS");
    o = append(o, end, "\r\nSetup=" SETUP_VERSION "\r\nInstalledUtc=");
    o = append(o, end, when);
    o = append(o, end, "\r\nTargetDevice=");
    o = append(o, end, C->di.name);
    o = append(o, end, "\r\nTargetSerial=");
    o = append(o, end, C->di.serial);
    gpt_guid_format(C->disk_guid, g);
    o = append(o, end, "\r\nDiskGuid=");
    o = append(o, end, g);
    for (i = 0; i < C->nparts; ++i) {
        gpt_guid_format(C->part_guid[i], g);
        o = append(o, end, "\r\n");
        o = append(o, end, keys[i]);
        o = append(o, end, g);
    }
    gpt_guid_format(C->fs_uuid, g);
    o = append(o, end, "\r\nSystemVolumeUuid=");
    o = append(o, end, g);
    o = append(o, end, "\r\nDriverPackages=");
    o = append(o, end, C->cfg.drivers);
    o = append(o, end, "\r\n");
    *len = (uint64_t)(o - t);
    return t;
}

static int write_log(ctx_t *C, sfsw_t *w, uint32_t handle)
{
    sfsw_io io = {C, p2_read, p2_write, io_alloc, io_free};
    sfsr_t *r;
    uint32_t ino, done;
    uint64_t size;
    int err, is_dir;
    const size_t len = C->log_len;
    if ((err = sfsw_write(w, handle, 0, C->log, (uint32_t)len)) || (err = sfsw_shrink(w, handle, len)) || (err = sfsw_commit(w)))
        return failf(C, "install.log: %s", sfsw_strerror(err));
    if (C->P->disk_flush(C->P->ctx, C->disk)) return failf(C, "flush failed");
    r = sfsr_open(&io, &err);
    if (!r) return failf(C, "install.log verify: %s", sfsw_strerror(err));
    err = sfsr_lookup(r, "/SHZ/SETUP/log/install.log", &ino, &size, &is_dir);
    if (!err && size == len) err = sfsr_read(r, ino, 0, C->buf, (uint32_t)len, &done);
    sfsr_close(r);
    if (err || size != len || memcmp(C->buf, C->log, len)) return failf(C, "install.log did not read back");
    return 0;
}

void setup_run(const plat_t *P, const char *answer, const char *payload_dir, setup_result_t *res)
{
    ctx_t ctx, *C = &ctx;
    sfsw_t *w = 0;
    uint32_t *handles = 0, log_handle = 0;
    gen_file_t gen[MAX_GEN];
    char *sysini = 0, when[24];
    int st = -1;
    memset(C, 0, sizeof *C);
    memset(res, 0, sizeof *res);
    memset(gen, 0, sizeof gen);
    C->P = P;
    copy_str(C->payload, sizeof C->payload, payload_dir);
    C->log = P->alloc(P->ctx, LOG_CAP);
    C->buf = P->alloc(P->ctx, IOBUF);
    C->buf2 = P->alloc(P->ctx, 2 * 4096 + GPT_ARRAY_BYTES + 4096);
    C->started = P->now(P->ctx);
    iso_time(C->started, when);
    if (!C->log || !C->buf || !C->buf2) { failf(C, "out of memory"); goto out; }
    say(C, "%s (ShizukuDOS installer), started %s", SETUP_VERSION, when);
    if (read_answer(C, answer) || read_manifest(C) || load_mbr_code(C)) goto out;
    if (select_target(C) || check_blank(C) || plan_layout(C) || open_archive(C)) goto out;
    make_guid(C, "disk", C->disk_guid);
    make_guid(C, "p1", C->part_guid[0]);
    make_guid(C, "p2", C->part_guid[1]);
    make_guid(C, "p3", C->part_guid[2]);
    derive(C, "fs", C->fs_uuid, 16);
    C->fs_uuid[6] = (uint8_t)((C->fs_uuid[6] & 0x0f) | 0x40);
    C->fs_uuid[8] = (uint8_t)((C->fs_uuid[8] & 0x3f) | 0x80);
    derive(C, "mbr", (uint8_t *)&C->mbr_sig, 4);
    derive(C, "fat", (uint8_t *)&C->fat_id, 4);
    sysini = build_system_ini(C, &gen[0].len);
    if (!sysini) { failf(C, "out of memory"); goto out; }
    gen[0].path = "/SHZ/SYSTEM.INI";
    gen[0].data = sysini;
    gen[1].path = "/SHZ/SETUP/shzsetup.ini";
    gen[1].data = C->answer_text;
    gen[1].len = C->answer_len;
    gen[2].path = "/SHZ/SETUP/manifest.json";
    gen[2].data = C->manifest_text;
    gen[2].len = C->manifest_len;
    say(C, "destructive phase: erasing %s", C->di.name);
    if (wipe_tables(C) || write_esp(C)) goto out;
    if (plan_system(C, &w, &handles, &log_handle, gen, MAX_GEN) || write_system_data(C, w, handles, gen, MAX_GEN) ||
        verify_system(C, gen, MAX_GEN))
        goto out;
    if (C->nparts == 3 && format_win98(C)) goto out;
    if (write_gpt(C)) goto out;
    iso_time(P->now(P->ctx), when);
    say(C, "finished %s; %s installed on %s", when, json_str(C->man.root, "product") ? json_str(C->man.root, "product") : "ShizukuDOS",
        C->di.name);
    log_only(C, "SETUP-RESULT: OK\n");
    if (write_log(C, w, log_handle)) {
        P->out(P->ctx, "SHZSETUP: the install log could not be written; the installation itself verified\n");
        goto out;
    }
    say(C, "install log written to p2 /SHZ/SETUP/log/install.log (%u bytes) and read back", (unsigned)C->log_len);
    st = 0;
out:
    res->ok = st == 0;
    res->power = C->cfg.power;
    copy_str(res->reason, sizeof res->reason, st == 0 ? "" : C->fail);
    if (st) {
        P->out(P->ctx, "SETUP-RESULT: FAIL ");
        P->out(P->ctx, C->fail[0] ? C->fail : "(unknown)");
        P->out(P->ctx, "\n");
    } else {
        P->out(P->ctx, "SETUP-RESULT: OK\n");
    }
    if (w) sfsw_destroy(w);
    if (C->arc) P->file_close(P->ctx, C->arc);
    if (sysini) P->free(P->ctx, sysini);
    if (handles) P->free(P->ctx, handles);
    if (C->arc_e) P->free(P->ctx, C->arc_e);
    if (C->arc_names) P->free(P->ctx, C->arc_names);
    ini_free(P, &C->ini);
    json_free(P, &C->man);
    if (C->answer_text) P->free(P->ctx, C->answer_text);
    if (C->manifest_text) P->free(P->ctx, C->manifest_text);
    if (C->log) P->free(P->ctx, C->log);
    if (C->buf) P->free(P->ctx, C->buf);
    if (C->buf2) P->free(P->ctx, C->buf2);
}
