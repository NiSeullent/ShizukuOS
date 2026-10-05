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
 *
 * Bootable-target coherence (checked before the first destructive write, then independently read back):
 *   - boot closure: the manifest's esp.files must list the UEFI fallback loader \EFI\BOOT\BOOTX64.EFI, the boot
 *     policy \EFI\SHIZUKU\BOOT.INI, Core64 (KERNEL64.BIN), Core32 (KERNEL32.BIN) and the boot runtime WIN64.IMG;
 *     with BIOS boot also K64STUB.ELF, KERNEL64S.BIN, syslinux ldlinux.sys/ldlinux.c32 and the 440-byte MBR code;
 *     the system tree must carry the Win64 runtime (\SHZ\SYS64 ntdll/kernel32);
 *   - source closure: SYSTEM.ARC is hashed whole against system.archive_sha256, every selected manifest file must be
 *     in the archive with its size, and ESP.SIM is fully expanded and hashed before anything is erased;
 *   - capacity/alignment: every partition starts on a 1 MiB boundary, esp.first_lba (the BPB hidden-sector value)
 *     is mandatory and equals p1's start, the ESP file set fits the ESP image;
 *   - readback: after p1 is written its FAT32 is decoded again from the target disk (fat32fmt.c reader) and every
 *     esp.files member, BOOTX64.EFI included, is re-hashed from the disk; p2 files and the generated driver catalog
 *     \SHZ\DRIVERS\CATALOG.INI are re-read through the independent ShizukuFS reader.
 *   - boot manifest: the payload must carry \SHZDOS\SHZBOOT.MAN (template: generation 0, install_id zero) and its
 *     manifest.json "boot_manifest" description. Before the destructive phase the previous target's SHZBOOT.MAN is read
 *     (only from a valid FAT32 ESP at p1's LBA) to choose install_generation = previous + 1, else 1; install_id is 16
 *     nonzero bytes of platform RNG output (clock/disk-identifier hash only when the RNG fails, logged as weak). After
 *     p1 verified, header bytes [24,32) and [72,88) are stamped in place with fat32_overwrite_file (same size, data
 *     clusters only, no allocation), the file is re-read from a fresh FAT32 mount and verified (magic, header, entry
 *     table hash, generation, id, every pinned blob re-hashed from the disk). The whole-ESP sha256 in the install
 *     record and manifest.json therefore describe the image as written before the stamp.
 * Install record: one 512-byte sector "SHZINSR1" at LBA (p1 start - 1), inside the 1 MiB alignment gap that no GPT
 * structure or partition uses. It is written (and read back) WRITING when the destructive phase begins, FAILED with
 * the stage and reason when a later step fails, COMPLETE after the partition tables and the log verified. A target
 * that fails half way is therefore observable even though it has no partition table. Refusals before the
 * destructive phase write nothing to the disk.
 */
#include "plat.h"
#include "gpt.h"
#include "sfsw.h"
#include "fat32fmt.h"
#include "textparse.h"
#include "../../supervisor/src/boot_manifest.h"       /* frozen SHZBOOT.MAN layout (boot-core64 owner) */
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
#define INSTALL_RECORD_MAGIC "SHZINSR1"
#define INSTALL_RECORD_VERSION 1u
#define DRIVER_CATALOG_PATH "/SHZ/DRIVERS/CATALOG.INI"
#define DRIVER_CATALOG_SCHEMA "shizuku-driver-catalog/2"
#define DRIVER_CATALOG_MAX_BYTES 16384u
#define DRIVER_CATALOG_MAX_ROWS 32u
#define DRIVER_MATCH_MAX 8u
#define BMAN_ESP_PATH "/SHZDOS/" SHZ_BMAN_BLOB_NAME
#define BMAN_GEN_OFFSET 24u
#define BMAN_ID_OFFSET 72u
enum { INSTID_RNG = 1, INSTID_WEAK = 2 };

enum { REC_WRITING = 1, REC_FAILED = 2, REC_COMPLETE = 3 };
enum { STAGE_PREFLIGHT = 1, STAGE_WIPE, STAGE_ESP, STAGE_ESP_VERIFY, STAGE_SYSTEM, STAGE_SYSTEM_VERIFY, STAGE_WIN98,
       STAGE_GPT, STAGE_LOG, STAGE_DONE };

/* Files the installed ESP must carry for the target to boot without the installer medium. */
static const char *const uefi_closure[][2] = {
    {"/EFI/BOOT/BOOTX64.EFI", "UEFI fallback loader"}, {"/EFI/SHIZUKU/BOOT.INI", "boot policy"},
    {"/SHZDOS/KERNEL64.BIN", "Core64"}, {"/SHZDOS/KERNEL32.BIN", "Core32"}, {"/SHZDOS/WIN64.IMG", "boot runtime"}, {0, 0}};
static const char *const bios_closure[][2] = {
    {"/SHZDOS/K64STUB.ELF", "BIOS Multiboot stub"}, {"/SHZDOS/KERNEL64S.BIN", "BIOS Core64 image"},
    {"/syslinux/ldlinux.sys", "BIOS syslinux core"}, {"/syslinux/ldlinux.c32", "BIOS syslinux module"}, {0, 0}};
static const char *const runtime_closure[] = {"/SHZ/SYS64/ntdll.dll", "/SHZ/SYS64/kernel32.dll", 0};

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
    int stage, record_armed, bios_boot;
    const setup_plan_t *reviewed_plan;
    const setup_control_t *control;
    uint64_t io_bytes, payload_files, notified_bytes, notified_files;
    int notified_phase;
    int cleanup, can_cancel, layout_error;
    uint64_t record_lba;
    uint8_t esp_sha[32], manifest_sha[32];
    uint64_t esp_files_ok;
    uint64_t bman_gen, bman_prev_gen;           /* generation stamped on this target; previous target's (0 = none) */
    uint8_t bman_id[16], bman_entries[32];      /* install_id; entries_sha256 from manifest.json boot_manifest */
    uint32_t bman_id_source;                    /* INSTID_* */
} ctx_t;

/* Events describe completed I/O and verification. They are not a time estimate. */
static void notify(ctx_t *C, int complete)
{
    setup_event_t e;
    if (!C->control || !C->control->event) return;
    if(!complete&&C->notified_phase==C->stage&&C->notified_files==C->files_ok&&
       C->io_bytes-C->notified_bytes<IOBUF)return;
    C->notified_phase=C->stage;C->notified_files=C->files_ok;C->notified_bytes=C->io_bytes;
    memset(&e, 0, sizeof e);
    e.phase=(uint32_t)C->stage; e.cancellable=(uint32_t)C->can_cancel;
    e.destructive=(uint32_t)C->record_armed; e.verified_complete=(uint32_t)complete;
    e.io_bytes=C->io_bytes; e.files_done=C->files_ok; e.files_total=C->payload_files;
    C->control->event(C->control->ctx,&e);
}
static void phase(ctx_t *C, int value, int cancellable)
{ C->stage=value; C->can_cancel=cancellable; notify(C,0); }
static int cancellation(ctx_t *C)
{
    return !C->cleanup && C->can_cancel && C->control && C->control->cancel_requested &&
           C->control->cancel_requested(C->control->ctx);
}

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

static void setup_snprintf(char *buf, size_t cap, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    setup_vsnprintf(buf, cap, fmt, ap);
    va_end(ap);
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

static void uuid_format(const uint8_t u[16], char out[37])                  /* RFC 4122 byte order (ext4 s_uuid) */
{
    static const char h[] = "0123456789abcdef";
    int i, o = 0;
    for (i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out[o++] = '-';
        out[o++] = h[u[i] >> 4];
        out[o++] = h[u[i] & 15];
    }
    out[o] = 0;
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

static const jnode_t *list_find(const jnode_t *list, const char *path)
{
    const jnode_t *x;
    for (x = list ? list->kid : 0; x; x = x->next)
        if (json_str(x, "path") && text_ieq(json_str(x, "path"), path)) return x;
    return 0;
}

/* Boot/runtime closure, ESP capacity and alignment, checked before any target is selected or written. */
static int check_closure(ctx_t *C)
{
    const jnode_t *root = C->man.root, *esp = json_get(root, "esp"), *sys = json_get(root, "system");
    const jnode_t *files = json_get(esp, "files"), *sfiles = json_get(sys, "files"), *x, *y;
    uint64_t esp_bytes = 0, first = 0, sum = 0, v;
    uint8_t sha[32];
    unsigned i;
    json_u64(esp, "bytes", &esp_bytes);
    if (json_u64(esp, "first_lba", &first) || !first || first % (MIB / 512))
        return failf(C, "manifest.json: esp.first_lba (the ESP BPB hidden-sector value) must be present and 1 MiB aligned");
    if (esp_bytes % 4096) return failf(C, "manifest.json: esp.bytes is not a multiple of the 4 KiB image block");
    if (!files || files->type != J_ARR) return failf(C, "manifest.json: esp.files (the ESP boot closure) missing");
    for (x = files->kid; x; x = x->next) {
        const char *p = json_str(x, "path");
        if (!p || p[0] != '/' || json_u64(x, "bytes", &v) || v > 0xffffffffull || !json_str(x, "sha256") ||
            unhex_sha(json_str(x, "sha256"), sha))
            return failf(C, "manifest.json: malformed esp.files entry");
        for (y = files->kid; y != x; y = y->next)
            if (text_ieq(json_str(y, "path"), p)) return failf(C, "manifest.json: esp.files lists %s twice", p);
        sum += (v + 4095) / 4096 * 4096;
    }
    if (sum > esp_bytes) return failf(C, "manifest.json: the ESP files (%llu bytes) do not fit the %llu-byte ESP image",
                                      (unsigned long long)sum, (unsigned long long)esp_bytes);
    for (i = 0; uefi_closure[i][0]; ++i)
        if (!list_find(files, uefi_closure[i][0]))
            return failf(C, "manifest.json: boot closure incomplete: %s (%s) is not on the ESP", uefi_closure[i][0], uefi_closure[i][1]);
    C->bios_boot = json_str(esp, "bios_boot") != 0;
    if (C->bios_boot) {
        for (i = 0; bios_closure[i][0]; ++i)
            if (!list_find(files, bios_closure[i][0]))
                return failf(C, "manifest.json: BIOS boot closure incomplete: %s (%s) is not on the ESP", bios_closure[i][0],
                             bios_closure[i][1]);
        if (C->cfg.bios_boot_code && !json_get(root, "mbr"))
            return failf(C, "manifest.json: esp.bios_boot is set but the payload has no mbr boot code");
    }
    for (i = 0; runtime_closure[i]; ++i) {
        const jnode_t *f = list_find(sfiles, runtime_closure[i]);
        const char *pkg = f ? json_str(f, "package") : 0;
        if (!f || (pkg && strcmp(pkg, "base")))
            return failf(C, "manifest.json: runtime closure incomplete: %s is not a base system file", runtime_closure[i]);
    }
    if (list_find(sfiles, DRIVER_CATALOG_PATH)) return failf(C, "manifest.json: %s is generated by setup", DRIVER_CATALOG_PATH);
    {
        const jnode_t *bm = json_get(root, "boot_manifest"), *st = json_get(bm, "stamp"), *f = list_find(files, BMAN_ESP_PATH);
        uint64_t go = 0, io = 0, bytes = 0, fb = 0;
        const char *ts = json_str(bm, "template_sha256");
        if (!f || !bm || !st || !ts || !json_str(bm, "path") || !text_ieq(json_str(bm, "path"), BMAN_ESP_PATH) ||
            json_u64(st, "generation_offset", &go) || json_u64(st, "install_id_offset", &io) || go != BMAN_GEN_OFFSET ||
            io != BMAN_ID_OFFSET || json_u64(bm, "bytes", &bytes) || json_u64(f, "bytes", &fb) || bytes != fb ||
            bytes < sizeof(shz_bman_header_t) + sizeof(shz_bman_entry_t) || bytes > SHZ_BMAN_MAX_BYTES ||
            (bytes - sizeof(shz_bman_header_t)) % sizeof(shz_bman_entry_t) || !text_ieq(ts, json_str(f, "sha256")) ||
            !json_str(bm, "entries_sha256") || unhex_sha(json_str(bm, "entries_sha256"), C->bman_entries))
            return failf(C, "manifest.json: the payload has no valid installed-target boot manifest %s (boot_manifest/esp.files)",
                         BMAN_ESP_PATH);
    }
    if (!json_str(sys, "archive_sha256") || unhex_sha(json_str(sys, "archive_sha256"), sha))
        return failf(C, "manifest.json: system.archive_sha256 missing (source closure)");
    say(C, "boot closure: UEFI fallback %s, Core64, Core32, boot runtime%s; Win64 runtime in \\SHZ\\SYS64",
        uefi_closure[0][0], C->bios_boot ? ", BIOS chain (MBR -> ESP VBR -> syslinux -> K64STUB)" : "");
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
    {
        void *h = C->P->sha_begin(C->P->ctx);
        C->P->sha_update(C->P->ctx, h, C->manifest_text, (uint32_t)C->manifest_len);
        C->P->sha_end(C->P->ctx, h, C->manifest_sha);
    }
    return check_closure(C);
}

/* ---------------------------------------------------------------- disks */
static int disk_rw(ctx_t *C, int write, uint64_t lba, uint64_t count, void *buf)
{
    uint8_t *p = buf;
    const uint32_t max = C->P->max_io_sectors ? C->P->max_io_sectors : 128;
    while (count) {
        const uint32_t n = count < max ? (uint32_t)count : max;
        int st;
        if (cancellation(C)) return failf(C, "installation cancelled at an I/O checkpoint");
        st = write ? C->P->disk_write(C->P->ctx, C->disk, lba, n, p) : C->P->disk_read(C->P->ctx, C->disk, lba, n, p);
        if (st) return failf(C, "%s error on %s at LBA %llu (%u sectors)", write ? "write" : "read", C->di.name,
                             (unsigned long long)lba, n);
        C->io_bytes += (uint64_t)n * C->ss; notify(C,0);
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
    const uint64_t lim = (1ull << 44);                     /* 16 TiB per term: no sum below can wrap */
    json_u64(json_get(C->man.root, "esp"), "bytes", &esp);
    if (esp >= lim || C->cfg.system_mib >= lim / MIB || C->cfg.win98_mib >= lim / MIB) return ~0ull;
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
        bytes = d.sector_size && d.sectors > ~0ull / d.sector_size ? ~0ull : d.sectors * d.sector_size;
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
    uint64_t esp_bytes = 0, esp_lba = 0, p2_start, p2_end, sys_sectors;
    json_u64(json_get(C->man.root, "esp"), "bytes", &esp_bytes);
    C->pfirst[0] = align;
    if (C->pfirst[0] < first) return failf(C, "unexpected GPT geometry");
    if (!json_u64(json_get(C->man.root, "esp"), "first_lba", &esp_lba) && esp_lba != C->pfirst[0])
        return failf(C, "esp.img was built for p1 at LBA %llu (BPB hidden sectors), this layout starts p1 at LBA %llu",
                     (unsigned long long)esp_lba, (unsigned long long)C->pfirst[0]);
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
    {
        int i;
        for (i = 0; i < C->nparts; ++i)
            if (C->pfirst[i] % align || C->plast[i] < C->pfirst[i] || (i && C->pfirst[i] <= C->plast[i - 1]))
                return failf(C, "layout: p%d is not 1 MiB aligned or overlaps", i + 1);
    }
    C->record_lba = C->pfirst[0] - 1;
    if (C->ss != 512 || C->record_lba < first) return failf(C, "layout: no room for the install record before p1");
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
static void put64le(uint8_t *p, uint64_t v);

/* ---------------------------------------------------------------- p1: ESP
 * Payload ESP.SIM ("SHZSIMG1" sparse image): 64-byte header {magic[8], u32 block_size (4096), u32 0, u32 chunk_count,
 * u32 0, u64 image_bytes, u8 sha256[32] of the expanded image}, then chunk_count x {u64 first_block, u32 blocks, u32 0}
 * in ascending order, then the chunks' data. Blocks outside every chunk are zero. The installer writes EVERY block,
 * zeros included, so the partition equals esp.img byte for byte. */
/* One pass over ESP.SIM. write=0: source-closure pre-pass (expand and hash only, before anything is erased).
 * write=1: expand, hash and write every block to p1. The expanded image must hash to esp.sha256 either way. */
static int esp_pass(ctx_t *C, int write)
{
    const jnode_t *esp = json_get(C->man.root, "esp");
    char path[240], hexs[65];
    void *h, *s;
    uint64_t fsize, total = 0, block, blocks, chunk_i = 0, nchunks, cur_first = 0, cur_count = 0, data_off, prev_end = 0;
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
    if (bs != 4096 || le64(hdr + 24) != total || memcmp(hdr + 32, want, 32) || 64 + nchunks * 16 > fsize) {
        C->P->file_close(C->P->ctx, h);
        return failf(C, "%s: block size, image size, chunk table or image sha256 does not match the manifest", path);
    }
    if (write)
        say(C, "p1: writing %s (%llu MiB, %llu data chunk(s)) to LBA %llu", json_str(esp, "image"),
            (unsigned long long)(total / MIB), (unsigned long long)nchunks, (unsigned long long)C->pfirst[0]);
    blocks = total / bs;
    data_off = 64 + nchunks * 16;
    s = C->P->sha_begin(C->P->ctx);
    for (block = 0; block < blocks;) {
        if(cancellation(C)){C->P->sha_end(C->P->ctx,s,got);C->P->file_close(C->P->ctx,h);return failf(C,"installation cancelled at an ESP checkpoint");}
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
                if (!cur_count || cur_first < prev_end || cur_first > blocks || cur_count > blocks - cur_first ||
                    data_off + cur_count * bs > fsize) {                       /* ascending, disjoint, inside both */
                    C->P->file_close(C->P->ctx, h);
                    return failf(C, "%s: chunk table out of range or unordered", path);
                }
                prev_end = cur_first + cur_count;
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
        if (write && disk_rw(C, 1, C->pfirst[0] + (block - i) * (bs / C->ss), (uint64_t)i * (bs / C->ss), C->buf)) {
            C->P->file_close(C->P->ctx, h);
            return -1;
        }
    }
    C->P->file_close(C->P->ctx, h);
    C->P->sha_end(C->P->ctx, s, got);
    hex(got, 32, hexs);
    if (chunk_i != nchunks) return failf(C, "%s: %llu chunk(s) beyond the image", path, (unsigned long long)(nchunks - chunk_i));
    if (memcmp(got, want, 32)) return failf(C, "p1: the ESP image in the payload does not match the manifest (sha256 %s)", hexs);
    memcpy(C->esp_sha, got, 32);
    say(C, write ? "p1: payload image sha256 %s matches the manifest" : "source closure: ESP.SIM expands to sha256 %s = manifest", hexs);
    return 0;
}

static int write_esp(ctx_t *C)
{
    char hexs[65];
    void *s;
    uint64_t block, total = 0;
    uint8_t got[32];
    json_u64(json_get(C->man.root, "esp"), "bytes", &total);
    if (esp_pass(C, 1)) return -1;
    if (C->P->disk_flush(C->P->ctx, C->disk)) return failf(C, "flush failed");
    phase(C,STAGE_ESP_VERIFY,1);
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
    if (memcmp(got, C->esp_sha, 32)) return failf(C, "p1: read-back sha256 %s differs from the manifest", hexs);
    say(C, "p1: read back %llu MiB from the disk, sha256 %s = manifest esp.sha256: OK", (unsigned long long)(total / MIB), hexs);
    return 0;
}

/* Independent file-level readback of the installed ESP: decode its FAT32 from the target disk (not from the payload)
 * and re-hash every esp.files member, so the UEFI fallback loader, boot policy, Core32/64 and the boot runtime are
 * proven reachable by path on the target itself. */
typedef struct { ctx_t *C; void *sha; uint8_t *cap; uint32_t cap_len, cap_max; } esp_sink_t;

static int p1_read(void *ctx, uint64_t sector, uint32_t count, void *buf)
{
    ctx_t *C = ctx;
    if (sector + count > C->plast[0] - C->pfirst[0] + 1) return -1;
    return disk_rw(C, 0, C->pfirst[0] + sector, count, buf) ? -1 : 0;
}

static int esp_sink(void *ctx, const void *data, uint32_t len)
{
    esp_sink_t *k = ctx;
    k->C->P->sha_update(k->C->P->ctx, k->sha, data, len);
    if (k->cap) {
        if (len > k->cap_max - k->cap_len) return 1;
        memcpy(k->cap + k->cap_len, data, len);
        k->cap_len += len;
    }
    return 0;
}

static int bman_field(const char *f, unsigned size)
{
    unsigned i;
    for (i = 0; i < size && f[i]; ++i) if ((unsigned char)f[i] < 0x20 || (unsigned char)f[i] > 0x7e) return 0;
    if (i == size) return 0;
    for (; i < size; ++i) if (f[i]) return 0;
    return 1;
}

/* SHZBOOT.MAN as installed: structure per boot_manifest.h, self hash, and every entry's blob re-hashed from the
 * installed copy on the target ESP (the read-back bytes, not the payload). Core admission policy (loader_profile,
 * capabilities, hierarchy/acyclic dependencies) stays with shz_bman_parse in the Supervisor; this only proves the
 * installed target carries exactly the files the manifest pins. */
static int all_zero(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) if (p[i]) return 0;
    return 1;
}

/* gen == 0: the template as copied from the payload (generation 0, install_id zero). Otherwise the stamped file: its
 * generation and install_id must equal what this run stamped. Either way the entry table hash must equal the
 * manifest.json boot_manifest.entries_sha256 (stamping never changes it). */
static int verify_boot_manifest(ctx_t *C, fat32_vol *v, uint8_t *cbuf, const uint8_t *m, uint32_t len, uint64_t gen,
                                const uint8_t id[16])
{
    shz_bman_header_t h;
    uint8_t got[32];
    unsigned i, k;
    void *s;
    if (len < sizeof h) return failf(C, "p1 verify: SHZBOOT.MAN too short");
    memcpy(&h, m, sizeof h);
    if (h.magic != SHZ_BMAN_MAGIC || h.version != SHZ_BMAN_VERSION || h.header_size != sizeof(shz_bman_header_t) ||
        h.entry_size != sizeof(shz_bman_entry_t) || !h.entry_count || h.entry_count > SHZ_BMAN_MAX_ENTRIES ||
        h.total_size != len || len != h.header_size + (uint32_t)h.entry_count * h.entry_size || h.flags || h.reserved[0] ||
        h.reserved[1])
        return failf(C, "p1 verify: SHZBOOT.MAN header is not a version-1 boot manifest");
    if (gen ? h.install_generation != gen || memcmp(h.install_id, id, 16) : h.install_generation || !all_zero(h.install_id, 16))
        return failf(C, "p1 verify: SHZBOOT.MAN %s", gen ? "stamp (generation/install_id) did not read back"
                                                         : "template is already stamped (generation/install_id nonzero)");
    s = C->P->sha_begin(C->P->ctx);
    C->P->sha_update(C->P->ctx, s, m + h.header_size, len - h.header_size);
    C->P->sha_end(C->P->ctx, s, got);
    if (memcmp(got, h.entries_sha256, 32) || memcmp(got, C->bman_entries, 32))
        return failf(C, "p1 verify: SHZBOOT.MAN entries_sha256 mismatch (file or manifest.json boot_manifest)");
    for (i = 0; i < h.entry_count; ++i) {
        shz_bman_entry_t e;
        char path[65];
        uint32_t first, size;
        int st, is_dir;
        esp_sink_t sk;
        memcpy(&e, m + h.header_size + i * h.entry_size, sizeof e);
        if (!bman_field(e.component, 16) || !bman_field(e.parent, 16) || !bman_field(e.blob, 16) ||
            !bman_field(e.install_path, 64) || e.kind > SHZ_BMAN_KIND_RESOURCE || e.reserved ||
            (i == 0) != (e.kind == SHZ_BMAN_KIND_CORE) || (i == 0 && strcmp(e.component, SHZ_BMAN_ROOT_NAME)))
            return failf(C, "p1 verify: SHZBOOT.MAN entry %u is malformed", i);
        if (!e.size && !e.install_path[0]) continue;
        if (e.install_path[0] != '\\' || e.size > 0xffffffffull)
            return failf(C, "p1 verify: SHZBOOT.MAN entry %s has no installed ESP path", e.component);
        for (k = 0; k < 65 && e.install_path[k]; ++k) path[k] = e.install_path[k] == '\\' ? '/' : e.install_path[k];
        path[k] = 0;
        st = fat32_lookup(v, path, &first, &size, &is_dir);
        if (st == FAT32R_ENOENT && !(e.flags & SHZ_BMAN_REQUIRED)) { say(C, "p1 verify: optional %s absent", path); continue; }
        if (st || is_dir || size != e.size)
            return failf(C, "p1 verify: SHZBOOT.MAN %s (%s): %s", e.component, path, st ? fat32_rstrerror(st) : "size differs");
        sk.C = C;
        sk.cap = 0;
        sk.sha = C->P->sha_begin(C->P->ctx);
        st = fat32_stream(v, first, size, cbuf, esp_sink, &sk);
        C->P->sha_end(C->P->ctx, sk.sha, got);
        if (st || memcmp(got, e.sha256, 32))
            return failf(C, "p1 verify: SHZBOOT.MAN %s (%s) read back with a different sha256", e.component, path);
    }
    say(C, "p1 verify: SHZBOOT.MAN %s (%u entries, generation %llu) pins only files read back from the target",
        gen ? "stamped" : "template", (unsigned)h.entry_count, (unsigned long long)h.install_generation);
    return 0;
}

static int verify_esp_files(ctx_t *C)
{
    const jnode_t *x;
    fat32_rio io;
    fat32_vol *v = C->P->alloc(C->P->ctx, sizeof *v);
    uint8_t *cbuf = 0, *bman = 0;
    uint32_t bman_len = 0;
    int st, is_dir;
    if (!v) return failf(C, "out of memory");
    io.ctx = C;
    io.read = p1_read;
    io.sectors = C->plast[0] - C->pfirst[0] + 1;
    if ((st = fat32_mount(v, &io))) { C->P->free(C->P->ctx, v); return failf(C, "p1 verify: %s", fat32_rstrerror(st)); }
    if (v->hidden != C->pfirst[0]) {
        C->P->free(C->P->ctx, v);
        return failf(C, "p1 verify: ESP BPB hidden sectors %u differ from p1 LBA %llu (BIOS chain-load would fail)", v->hidden,
                     (unsigned long long)C->pfirst[0]);
    }
    cbuf = C->P->alloc(C->P->ctx, (size_t)v->spc * 512u);
    if (!cbuf) { C->P->free(C->P->ctx, v); return failf(C, "out of memory"); }
    for (x = json_get(json_get(C->man.root, "esp"), "files")->kid; x; x = x->next) {
        const char *path = json_str(x, "path");
        uint64_t bytes = 0;
        uint32_t first, size;
        uint8_t want[32], got[32];
        esp_sink_t k;
        json_u64(x, "bytes", &bytes);
        unhex_sha(json_str(x, "sha256"), want);
        if ((st = fat32_lookup(v, path, &first, &size, &is_dir)) || is_dir || size != bytes) {
            C->P->free(C->P->ctx, v);
            C->P->free(C->P->ctx, cbuf);
            if (bman) C->P->free(C->P->ctx, bman);
            return failf(C, "p1 verify: %s: %s", path, st ? fat32_rstrerror(st) : "wrong type or size");
        }
        k.C = C;
        k.cap = 0;
        k.cap_len = 0;
        k.cap_max = SHZ_BMAN_MAX_BYTES;
        if (text_ieq(path, "/SHZDOS/" SHZ_BMAN_BLOB_NAME) && !bman) k.cap = bman = C->P->alloc(C->P->ctx, SHZ_BMAN_MAX_BYTES);
        k.sha = C->P->sha_begin(C->P->ctx);
        st = fat32_stream(v, first, size, cbuf, esp_sink, &k);
        if (k.cap) bman_len = k.cap_len;
        C->P->sha_end(C->P->ctx, k.sha, got);
        if (st || memcmp(got, want, 32)) {
            C->P->free(C->P->ctx, v);
            C->P->free(C->P->ctx, cbuf);
            if (bman) C->P->free(C->P->ctx, bman);
            return failf(C, "p1 verify: %s %s", path, st ? fat32_rstrerror(st) : "read back with a different sha256");
        }
        ++C->esp_files_ok;
    }
    if (bman) {
        st = verify_boot_manifest(C, v, cbuf, bman, bman_len, 0, 0);
        C->P->free(C->P->ctx, bman);
    } else {
        st = failf(C, "p1 verify: \\SHZDOS\\" SHZ_BMAN_BLOB_NAME " was not read back from the target ESP");
    }
    C->P->free(C->P->ctx, v);
    C->P->free(C->P->ctx, cbuf);
    if (st) return -1;
    say(C, "p1 verify: FAT32 decoded from the target; %llu ESP file(s) incl. %s, Core64, Core32 re-hashed from disk: OK",
        (unsigned long long)C->esp_files_ok, uefi_closure[0][0]);
    return 0;
}

static int p1_write(void *ctx, uint64_t sector, uint32_t count, const void *buf)
{
    ctx_t *C = ctx;
    if (sector + count > C->plast[0] - C->pfirst[0] + 1) return -1;
    return disk_rw(C, 1, C->pfirst[0] + sector, count, (void *)buf) ? -1 : 0;
}

/* Reads SHZBOOT.MAN (bounded by SHZ_BMAN_MAX_BYTES) from a FAT32 volume at p1's LBA into m. 0 = read, else FAT32R_*. */
static int read_bman_file(ctx_t *C, fat32_vol *v, uint8_t **cbuf, uint8_t *m, uint32_t *len)
{
    uint32_t first, size;
    int st, is_dir;
    esp_sink_t k;
    fat32_rio io;
    io.ctx = C;
    io.read = p1_read;
    io.sectors = C->plast[0] - C->pfirst[0] + 1;
    if ((st = fat32_mount(v, &io))) return st;
    if (v->hidden != C->pfirst[0]) return FAT32R_EBPB;
    if (!*cbuf && !(*cbuf = C->P->alloc(C->P->ctx, (size_t)v->spc * 512u))) return FAT32R_EIO;
    if ((st = fat32_lookup(v, BMAN_ESP_PATH, &first, &size, &is_dir))) return st;
    if (is_dir || size < sizeof(shz_bman_header_t) || size > SHZ_BMAN_MAX_BYTES) return FAT32R_ESIZE;
    k.C = C;
    k.cap = m;
    k.cap_len = 0;
    k.cap_max = SHZ_BMAN_MAX_BYTES;
    k.sha = C->P->sha_begin(C->P->ctx);
    st = fat32_stream(v, first, size, *cbuf, esp_sink, &k);
    C->P->sha_end(C->P->ctx, k.sha, (uint8_t[32]){0});
    *len = k.cap_len;
    return st;
}

/* Preflight (reads only): the generation of the target's previous installation, from its SHZBOOT.MAN, and this
 * installation's install_id. A disk without a valid previous ESP/manifest starts at generation 1. */
static int plan_install_identity(ctx_t *C)
{
    fat32_vol *v = C->P->alloc(C->P->ctx, sizeof *v);
    uint8_t *m = C->P->alloc(C->P->ctx, SHZ_BMAN_MAX_BYTES), *cbuf = 0, d[32];
    uint32_t len = 0;
    int st = -1;
    if (!v || !m) { if (v) C->P->free(C->P->ctx, v); if (m) C->P->free(C->P->ctx, m); return failf(C, "out of memory"); }
    C->bman_prev_gen = 0;
    st = read_bman_file(C, v, &cbuf, m, &len);
    if (!st) {
        shz_bman_header_t h;
        void *s;
        memcpy(&h, m, sizeof h);
        s = C->P->sha_begin(C->P->ctx);
        C->P->sha_update(C->P->ctx, s, m + sizeof h, len - (uint32_t)sizeof h);
        C->P->sha_end(C->P->ctx, s, d);
        if (h.magic == SHZ_BMAN_MAGIC && h.version == SHZ_BMAN_VERSION && h.header_size == sizeof h &&
            h.entry_size == sizeof(shz_bman_entry_t) && h.entry_count && h.entry_count <= SHZ_BMAN_MAX_ENTRIES &&
            h.total_size == len && len == sizeof h + (uint32_t)h.entry_count * sizeof(shz_bman_entry_t) &&
            !memcmp(d, h.entries_sha256, 32)) {
            C->bman_prev_gen = h.install_generation;
            say(C, "previous target: %s generation %llu found on the ESP at LBA %llu", BMAN_ESP_PATH,
                (unsigned long long)h.install_generation, (unsigned long long)C->pfirst[0]);
        } else {
            say(C, "previous target: %s on the ESP is not a valid boot manifest; generation restarts", BMAN_ESP_PATH);
        }
    } else {
        say(C, "previous target: no readable %s at LBA %llu (%s); first generation", BMAN_ESP_PATH,
            (unsigned long long)C->pfirst[0], fat32_rstrerror(st));
    }
    if (cbuf) C->P->free(C->P->ctx, cbuf);
    C->P->free(C->P->ctx, v);
    C->P->free(C->P->ctx, m);
    if (C->bman_prev_gen == ~0ull) return failf(C, "previous target generation is exhausted");
    C->bman_gen = C->bman_prev_gen + 1;
    /* Entropy: the platform RNG (SHZSETUP: bcrypt BCryptGenRandom, system-preferred RNG). Only if it fails, a SHA-256
     * of the clock and target disk identifiers, logged and recorded as weak. GuidSeed is deliberately not used: two
     * installations with one answer file must not share an identity. */
    C->bman_id_source = INSTID_RNG;
    if (C->P->random(C->P->ctx, C->bman_id, 16) || all_zero(C->bman_id, 16)) {
        uint64_t t = C->P->now(C->P->ctx);
        void *s = C->P->sha_begin(C->P->ctx);
        C->P->sha_update(C->P->ctx, s, &t, sizeof t);
        C->P->sha_update(C->P->ctx, s, &C->started, sizeof C->started);
        C->P->sha_update(C->P->ctx, s, C->di.serial, (uint32_t)strlen(C->di.serial));
        C->P->sha_update(C->P->ctx, s, C->di.name, (uint32_t)strlen(C->di.name));
        C->P->sha_update(C->P->ctx, s, &C->di.sectors, sizeof C->di.sectors);
        C->P->sha_update(C->P->ctx, s, &C->bman_gen, sizeof C->bman_gen);
        C->P->sha_update(C->P->ctx, s, C->manifest_sha, 32);
        C->P->sha_end(C->P->ctx, s, d);
        memcpy(C->bman_id, d, 16);
        C->bman_id_source = INSTID_WEAK;
    }
    if (all_zero(C->bman_id, 16)) return failf(C, "install_id: no nonzero identity could be produced");
    {
        char hx[33];
        hex(C->bman_id, 16, hx);
        say(C, "install identity: generation %llu, install_id %s (%s)", (unsigned long long)C->bman_gen, hx,
            C->bman_id_source == INSTID_RNG ? "platform RNG" : "WEAK: clock + disk identifiers, platform RNG failed");
    }
    return 0;
}

/* After p1 verified: stamp generation + install_id into the installed SHZBOOT.MAN (same size, data clusters only), then
 * re-read it through a fresh FAT32 mount and verify everything again. */
static int stamp_boot_manifest(ctx_t *C)
{
    fat32_vol *v = C->P->alloc(C->P->ctx, sizeof *v);
    uint8_t *m = C->P->alloc(C->P->ctx, SHZ_BMAN_MAX_BYTES), *rb = C->P->alloc(C->P->ctx, SHZ_BMAN_MAX_BYTES), *cbuf = 0;
    uint32_t len = 0, rlen = 0;
    int st = -1, rc = -1;
    if (!v || !m || !rb) { failf(C, "out of memory"); goto done; }
    if ((st = read_bman_file(C, v, &cbuf, m, &len))) { failf(C, "p1 stamp: %s: %s", BMAN_ESP_PATH, fat32_rstrerror(st)); goto done; }
    if (len < sizeof(shz_bman_header_t) || (len - sizeof(shz_bman_header_t)) % sizeof(shz_bman_entry_t) ||
        le64(m + BMAN_GEN_OFFSET) || !all_zero(m + BMAN_ID_OFFSET, 16)) {
        failf(C, "p1 stamp: %s is not an unstamped template of 96 + n*176 bytes", BMAN_ESP_PATH);
        goto done;
    }
    put64le(m + BMAN_GEN_OFFSET, C->bman_gen);
    memcpy(m + BMAN_ID_OFFSET, C->bman_id, 16);
    if ((st = fat32_overwrite_file(v, p1_write, C, BMAN_ESP_PATH, m, len, cbuf))) {
        failf(C, "p1 stamp: %s: %s", BMAN_ESP_PATH, fat32_rstrerror(st));
        goto done;
    }
    if (C->P->disk_flush(C->P->ctx, C->disk)) { failf(C, "flush failed"); goto done; }
    /* independent readback: fresh mount, nothing cached from the write */
    if ((st = read_bman_file(C, v, &cbuf, rb, &rlen)) || rlen != len || memcmp(rb, m, len)) {
        failf(C, "p1 stamp: %s did not read back as stamped (%s)", BMAN_ESP_PATH, st ? fat32_rstrerror(st) : "content differs");
        goto done;
    }
    if (verify_boot_manifest(C, v, cbuf, rb, rlen, C->bman_gen, C->bman_id)) goto done;
    say(C, "p1 stamp: %s generation %llu + install_id written in place and read back", BMAN_ESP_PATH,
        (unsigned long long)C->bman_gen);
    rc = 0;
done:
    if (v) C->P->free(C->P->ctx, v);
    if (m) C->P->free(C->P->ctx, m);
    if (rb) C->P->free(C->P->ctx, rb);
    if (cbuf) C->P->free(C->P->ctx, cbuf);
    return rc;
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


static const arc_entry_t *arc_find(ctx_t *C, const char *path);

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
    {   /* source closure: the whole archive is the one the manifest describes, before anything is erased */
        uint8_t want[32], got[32];
        uint64_t off = 0;
        void *s = C->P->sha_begin(C->P->ctx);
        const jnode_t *x;
        unhex_sha(json_str(json_get(C->man.root, "system"), "archive_sha256"), want);
        while (off < size) {
            const uint32_t n = size - off < IOBUF ? (uint32_t)(size - off) : IOBUF;
            if (cancellation(C)) { C->P->sha_end(C->P->ctx,s,got); return failf(C,"installation cancelled before disk writes"); }
            if (C->P->file_read(C->P->ctx, C->arc, off, C->buf, n)) { C->P->sha_end(C->P->ctx, s, got); return failf(C, "%s: read error", path); }
            C->P->sha_update(C->P->ctx, s, C->buf, n);
            off += n;
        }
        C->P->sha_end(C->P->ctx, s, got);
        if (memcmp(got, want, 32)) return failf(C, "source closure: %s does not match system.archive_sha256", path);
        for (x = json_get(json_get(C->man.root, "system"), "files")->kid; x; x = x->next) {
            const arc_entry_t *a;
            uint64_t bytes = 0;
            if (!package_selected(C, json_str(x, "package"))) continue;
            json_u64(x, "bytes", &bytes);
            a = arc_find(C, json_str(x, "path"));
            if (!a || a->size != bytes)
                return failf(C, "source closure: %s is missing from %s or has the wrong size", json_str(x, "path"), name);
        }
        say(C, "source closure: %s sha256 = manifest; every selected system file present with its size", name);
    }
    return 0;
}

static const arc_entry_t *arc_find(ctx_t *C, const char *path)
{
    uint32_t i;
    for (i = 0; i < C->arc_n; ++i) if (!strcmp(C->arc_e[i].path, path)) return &C->arc_e[i];
    return 0;
}

typedef struct { const char *path; const char *data; uint64_t len; uint32_t handle; } gen_file_t;
#define MAX_GEN 5

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
    if (!w) { C->layout_error=err; return failf(C, "p2: ShizukuFS format: %s", sfsw_strerror(err)); }
    *wout = w;
    for (x = json_get(sys, "dirs")->kid; x; x = x->next) {
        if (!package_selected(C, json_str(x, "package"))) continue;
        if ((err = sfsw_mkdir(w, json_str(x, "path")))) { C->layout_error=err; return failf(C, "p2: mkdir %s: %s", json_str(x, "path"), sfsw_strerror(err)); }
    }
    for (i = 0; setup_dirs[i]; ++i)
        if ((err = sfsw_mkdir(w, setup_dirs[i])) && err != SFSW_EEXIST) { C->layout_error=err; return failf(C, "p2: mkdir %s: %s", setup_dirs[i], sfsw_strerror(err)); }
    for (x = json_get(sys, "files")->kid; x; x = x->next) {
        uint64_t bytes;
        const arc_entry_t *a;
        if (!package_selected(C, json_str(x, "package"))) continue;
        json_u64(x, "bytes", &bytes);
        a = arc_find(C, json_str(x, "path"));
        /* Read-only capacity planning uses the manifest tree without opening
         * the archive. The executable install always validates the archive. */
        if (C->arc && (!a || a->size != bytes)) return failf(C, "p2: %s is missing from the archive or has the wrong size", json_str(x, "path"));
        if ((err = sfsw_add_file(w, json_str(x, "path"), bytes, &(*handles)[n])))
            { C->layout_error=err; return failf(C, "p2: add %s: %s", json_str(x, "path"), sfsw_strerror(err)); }
        ++n;
        nbytes += bytes;
    }
    for (i = 0; i < ngen; ++i)
        if ((err = sfsw_add_file(w, gen[i].path, gen[i].len, &gen[i].handle)))
            { C->layout_error=err; return failf(C, "p2: add %s: %s", gen[i].path, sfsw_strerror(err)); }
    if ((err = sfsw_add_file(w, "/SHZ/SETUP/log/install.log", LOG_CAP, log_handle)))
        { C->layout_error=err; return failf(C, "p2: add install.log: %s", sfsw_strerror(err)); }
    if ((err = sfsw_layout(w))) { C->layout_error=err; return failf(C, "p2: layout: %s", sfsw_strerror(err)); }
    sfsw_get_info(w, &info);
    uuid_format(C->fs_uuid, uuid);
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
            if (cancellation(C)) { C->P->sha_end(C->P->ctx,s,got); return failf(C,"installation cancelled while copying system files"); }
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
        C->bytes_ok += size; notify(C,0);
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
    uuid_format(C->fs_uuid, g);
    o = append(o, end, "\r\nSystemVolumeUuid=");
    o = append(o, end, g);
    o = append(o, end, "\r\nDriverPackages=");
    o = append(o, end, C->cfg.drivers);
    o = append(o, end, "\r\nDriverCatalog=" DRIVER_CATALOG_PATH "\r\n\r\n[Boot]\r\nUefiFallback=\\EFI\\BOOT\\BOOTX64.EFI\r\nBootPolicy="
               "\\EFI\\SHIZUKU\\BOOT.INI\r\nBiosChain=");
    o = append(o, end, C->bios_boot && C->have_mbr_code && C->cfg.bios_boot_code ? "yes" : "no");
    {
        static const char *const keys2[] = {"\r\nCore64Sha256=", "\r\nCore32Sha256=", "\r\nBootRuntimeSha256="};
        const jnode_t *files = json_get(json_get(C->man.root, "esp"), "files");
        for (i = 0; i < 3; ++i) {
            const jnode_t *f = list_find(files, uefi_closure[2 + i][0]);
            o = append(o, end, keys2[i]);
            o = append(o, end, f && json_str(f, "sha256") ? json_str(f, "sha256") : "");
        }
    }
    {
        char num[24], hx[33];
        setup_snprintf(num, sizeof num, "%llu", (unsigned long long)C->bman_gen);
        hex(C->bman_id, 16, hx);
        o = append(o, end, "\r\nBootManifest=\\SHZDOS\\" SHZ_BMAN_BLOB_NAME "\r\nInstallGeneration=");
        o = append(o, end, num);
        o = append(o, end, "\r\nInstallId=");
        o = append(o, end, hx);
    }
    o = append(o, end, "\r\nInstallRecordLba=");
    {
        char num[24];
        setup_snprintf(num, sizeof num, "%llu", (unsigned long long)C->record_lba);
        o = append(o, end, num);
    }
    o = append(o, end, "\r\n");
    *len = (uint64_t)(o - t);
    return t;
}

/* Installed driver catalog v2 (contract routing02 C5): one row per selected driver package, from manifest.json
 * "drivers" (kind, match ids, service image) plus the package's descriptor file (Path/Bytes/Sha256, hashed on the way
 * in and re-read from the target by verify_system). Builtin rows are drivers compiled into KERNEL64S.BIN, whose sha256
 * comes from the ESP closure that verify_esp_files re-hashed. Refuses (NULL, C->fail set) instead of writing a catalog
 * the Kernel64 importer would reject. */
static int hexn(const char *s, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f') || (s[i] >= 'A' && s[i] <= 'F'))) return 0;
    return 1;
}

static int match_ok(const char *m)        /* "vvvv:dddd" | "vvvv:dddd-dddd" | "class cc:ss" | "class cc:ss:pp" */
{
    const size_t n = strlen(m);
    if (!sncmp(m, "class ", 6))
        return (n == 11 && hexn(m + 6, 2) && m[8] == ':' && hexn(m + 9, 2)) ||
               (n == 14 && hexn(m + 6, 2) && m[8] == ':' && hexn(m + 9, 2) && m[11] == ':' && hexn(m + 12, 2));
    return (n == 9 && hexn(m, 4) && m[4] == ':' && hexn(m + 5, 4)) ||
           (n == 14 && hexn(m, 4) && m[4] == ':' && hexn(m + 5, 4) && m[9] == '-' && hexn(m + 10, 4));
}

static int service_ok(const char *s)
{
    size_t i;
    for (i = 0; s[i]; ++i)
        if (i >= 31 || !((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '_'))
            return 0;
    return i != 0;
}

static char *build_driver_catalog(ctx_t *C, uint64_t *len)
{
    const jnode_t *drivers = json_get(C->man.root, "drivers"), *sfiles = json_get(json_get(C->man.root, "system"), "files");
    const jnode_t *k64 = list_find(json_get(json_get(C->man.root, "esp"), "files"), "/SHZDOS/KERNEL64S.BIN"), *x, *d, *f, *m;
    const char *ksha = k64 ? json_str(k64, "sha256") : 0;
    const size_t cap = DRIVER_CATALOG_MAX_BYTES + 1;
    unsigned n = 0;
    char *t, *o, *end, num[24], pkgname[64];
    if (!drivers || drivers->type != J_ARR) { failf(C, "manifest.json: \"drivers\" metadata (driver catalog v2) missing"); return 0; }
    if (!ksha || strlen(ksha) != 64 || !hexn(ksha, 64)) { failf(C, "driver catalog: KERNEL64S.BIN is not in the ESP closure"); return 0; }
    /* every selected driver-* package file must be described by exactly one drivers row */
    for (x = sfiles->kid; x; x = x->next) {
        const char *pkg = json_str(x, "package");
        unsigned rows = 0;
        if (!pkg || sncmp(pkg, "driver-", 7) || !package_selected(C, pkg)) continue;
        for (d = drivers->kid; d; d = d->next)
            if (json_str(d, "package") && !strcmp(json_str(d, "package"), pkg)) ++rows;
        if (rows != 1) { failf(C, "manifest.json: driver package %s has %u \"drivers\" rows (need 1)", pkg, rows); return 0; }
    }
    if (!(t = C->P->alloc(C->P->ctx, cap))) { failf(C, "driver catalog: out of memory"); return 0; }
    o = t;
    end = t + cap - 1;
    o = append(o, end, "; ShizukuOS installed driver catalog, written and read back by " SETUP_VERSION "\r\n[Catalog]\r\nSchema="
               DRIVER_CATALOG_SCHEMA "\r\nSelection=");
    o = append(o, end, C->cfg.drivers);
    setup_snprintf(num, sizeof num, "%llu", (unsigned long long)C->bman_gen);
    o = append(o, end, "\r\nInstallGeneration=");
    o = append(o, end, num);
    o = append(o, end, "\r\nKernel64Sha256=");
    o = append(o, end, ksha);
    o = append(o, end, "\r\n");
    for (d = drivers->kid; d; d = d->next) {
        const char *name = json_str(d, "name"), *pkg = json_str(d, "package"), *kind = json_str(d, "kind");
        const char *start = json_str(d, "start"), *isha = json_str(d, "image_sha256");
        const jnode_t *pf = 0;
        unsigned files = 0, nm = 0;
        uint64_t bytes = 0;
        int service;
        setup_snprintf(pkgname, sizeof pkgname, "driver-%s", name ? name : "");
        if (!name || !pkg || strcmp(pkg, pkgname) || !kind || (strcmp(kind, "builtin") && strcmp(kind, "service")) || !start ||
            (strcmp(start, "boot") && strcmp(start, "system") && strcmp(start, "demand")) || !isha || strlen(isha) != 64 ||
            !hexn(isha, 64)) {
            failf(C, "manifest.json: malformed \"drivers\" row %s", name ? name : "(no name)");
            goto bad;
        }
        if (!package_selected(C, pkg)) continue;
        if (n >= DRIVER_CATALOG_MAX_ROWS) { failf(C, "driver catalog: more than %u rows", DRIVER_CATALOG_MAX_ROWS); goto bad; }
        service = !strcmp(kind, "service");
        for (f = sfiles->kid; f; f = f->next)
            if (json_str(f, "package") && !strcmp(json_str(f, "package"), pkg)) { pf = pf ? pf : f; ++files; }
        if (files != 1) { failf(C, "driver catalog: package %s has %u descriptor files (need 1)", pkg, files); goto bad; }
        if (!service && !text_ieq(isha, ksha)) { failf(C, "driver catalog: builtin %s image is not KERNEL64S.BIN", name); goto bad; }
        setup_snprintf(num, sizeof num, "%u", n++);
        o = append(o, end, "\r\n[Driver.");
        o = append(o, end, num);
        o = append(o, end, "]\r\nPackage=");
        o = append(o, end, pkg);
        o = append(o, end, "\r\nKind=");
        o = append(o, end, kind);
        o = append(o, end, "\r\nMatch=");
        m = json_get(d, "match");
        for (x = m && m->type == J_ARR ? m->kid : 0; x; x = x->next) {
            if (x->type != J_STR || !match_ok(x->s) || ++nm > DRIVER_MATCH_MAX) {
                failf(C, "manifest.json: driver %s has a malformed or too long match list", name);
                goto bad;
            }
            if (nm > 1) o = append(o, end, ",");
            o = append(o, end, x->s);
        }
        if (!nm) { failf(C, "manifest.json: driver %s has no match ids", name); goto bad; }
        if (service) {
            const char *svc = json_str(d, "service"), *img = json_str(d, "image");
            const jnode_t *imf = img ? list_find(sfiles, img) : 0;
            if (!svc || !service_ok(svc) || !img || sncmp(img, "/SHZ/DRIVERS/", 13) || strlen(img) > 200 || !imf ||
                !json_str(imf, "package") || strcmp(json_str(imf, "package"), pkg) || !text_ieq(json_str(imf, "sha256"), isha)) {
                failf(C, "manifest.json: service driver %s needs a valid Service and an Image in its own package with that sha256", name);
                goto bad;
            }
            o = append(o, end, "\r\nService=");
            o = append(o, end, svc);
            o = append(o, end, "\r\nImage=");
            for (; *img && o < end; ++img) *o++ = *img == '/' ? '\\' : *img;
            o = append(o, end, "\r\nImageSha256=");
            o = append(o, end, isha);
        }
        o = append(o, end, "\r\nStart=");
        o = append(o, end, start);
        json_u64(pf, "bytes", &bytes);
        o = append(o, end, "\r\nPath=");
        o = append(o, end, json_str(pf, "path"));
        setup_snprintf(num, sizeof num, "%llu", (unsigned long long)bytes);
        o = append(o, end, "\r\nBytes=");
        o = append(o, end, num);
        o = append(o, end, "\r\nSha256=");
        o = append(o, end, json_str(pf, "sha256"));
        o = append(o, end, "\r\n");
    }
    setup_snprintf(num, sizeof num, "%u", n);
    o = append(o, end, "\r\n[Summary]\r\nCount=");
    o = append(o, end, num);
    o = append(o, end, "\r\n");
    if (o >= end) { failf(C, "driver catalog exceeds %u bytes", DRIVER_CATALOG_MAX_BYTES); goto bad; }
    *len = (uint64_t)(o - t);
    say(C, "driver catalog %s (%s): %u row(s), InstallGeneration %llu", DRIVER_CATALOG_PATH, DRIVER_CATALOG_SCHEMA, n,
        (unsigned long long)C->bman_gen);
    return t;
bad:
    C->P->free(C->P->ctx, t);
    return 0;
}

/* ---------------------------------------------------------------- install record (see the header comment) */
static void put32le(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static void put64le(uint8_t *p, uint64_t v) { put32le(p, (uint32_t)v); put32le(p + 4, (uint32_t)(v >> 32)); }

/* Layout (512 bytes, little endian): 0 magic "SHZINSR1", 8 u32 version, 12 u32 state (1 writing, 2 failed,
 * 3 complete), 16 u32 stage, 20 u32 partitions, 24 u64 started, 32 u64 updated, 40 u64 disk sectors, 48 u64 p1 LBA,
 * 56 u64 p2 LBA, 64 sha256 ESP image, 96 sha256 manifest.json, 128 char reason[160] (NUL padded),
 * 288 char setup[32], 320 u64 install_generation (stamped into SHZBOOT.MAN), 328 u8 install_id[16], 344 sha256
 * SHZBOOT.MAN entries_sha256, 376 u32 install_id source (1 platform RNG, 2 weak clock/disk hash), 380..507 zero,
 * 508 u32 CRC32 (gpt_crc32) of bytes 0..507. Fields 320..379 are additive in version 1 (previously zero). */
static int write_record(ctx_t *C, uint32_t state)
{
    uint8_t rec[512], rb[512];
    size_t n;
    memset(rec, 0, sizeof rec);
    memcpy(rec, INSTALL_RECORD_MAGIC, 8);
    put32le(rec + 8, INSTALL_RECORD_VERSION);
    put32le(rec + 12, state);
    put32le(rec + 16, (uint32_t)C->stage);
    put32le(rec + 20, (uint32_t)C->nparts);
    put64le(rec + 24, C->started);
    put64le(rec + 32, C->P->now(C->P->ctx));
    put64le(rec + 40, C->di.sectors);
    put64le(rec + 48, C->pfirst[0]);
    put64le(rec + 56, C->pfirst[1]);
    memcpy(rec + 64, C->esp_sha, 32);
    memcpy(rec + 96, C->manifest_sha, 32);
    if (state == REC_FAILED) {
        n = strlen(C->fail[0] ? C->fail : "(unknown)");
        memcpy(rec + 128, C->fail[0] ? C->fail : "(unknown)", n < 159 ? n : 159);
    }
    memcpy(rec + 288, SETUP_VERSION, sizeof SETUP_VERSION < 32 ? sizeof SETUP_VERSION : 31);
    put64le(rec + 320, C->bman_gen);
    memcpy(rec + 328, C->bman_id, 16);
    memcpy(rec + 344, C->bman_entries, 32);
    put32le(rec + 376, C->bman_id_source);
    put32le(rec + 508, gpt_crc32(rec, 508));
    if (C->P->disk_write(C->P->ctx, C->disk, C->record_lba, 1, rec) || C->P->disk_flush(C->P->ctx, C->disk) ||
        C->P->disk_read(C->P->ctx, C->disk, C->record_lba, 1, rb) || memcmp(rb, rec, 512))
        return -1;
    return 0;
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

static void run_engine(const plat_t *P, const char *answer, const char *payload_dir,
                       const setup_plan_t *plan, const setup_control_t *control, setup_result_t *res)
{
    ctx_t ctx, *C = &ctx;
    sfsw_t *w = 0;
    uint32_t *handles = 0, log_handle = 0;
    gen_file_t gen[MAX_GEN];
    char *sysini = 0, *catalog = 0, when[24];
    uint8_t prefs[16];
    int st = -1;
    memset(C, 0, sizeof *C);
    memset(res, 0, sizeof *res);
    memset(gen, 0, sizeof gen);
    C->P = P; C->reviewed_plan=plan; C->control=control;
    copy_str(C->payload, sizeof C->payload, payload_dir);
    C->log = P->alloc(P->ctx, LOG_CAP);
    C->buf = P->alloc(P->ctx, IOBUF);
    C->buf2 = P->alloc(P->ctx, 2 * 4096 + GPT_ARRAY_BYTES + 4096);
    C->started = P->now(P->ctx);
    iso_time(C->started, when);
    if (!C->log || !C->buf || !C->buf2) { failf(C, "out of memory"); goto out; }
    say(C, "%s (ShizukuOS installer), started %s", SETUP_VERSION, when);
    phase(C,STAGE_PREFLIGHT,1);
    if (read_answer(C, answer) || read_manifest(C) || load_mbr_code(C)) goto out;
    if (plan) {
        plat_disk_t current;
        if (plan->version!=SETUP_PLAN_VERSION || !control || !control->check ||
            control->check(control->ctx,plan) ||
            P->disk_info(P->ctx,plan->target.index,&current) ||
            memcmp(&current,&plan->target.disk,sizeof current) ||
            memcmp(C->manifest_sha,plan->image.manifest_sha256,32)) {
            failf(C,"reviewed source or target changed; return to target selection"); goto out;
        }
        C->disk=plan->target.index; C->di=current; C->ss=current.sector_size;
        C->payload_files=plan->image.payload_files;
    } else if (select_target(C)) goto out;
    if (check_blank(C) || plan_layout(C) || open_archive(C) || esp_pass(C,0) || plan_install_identity(C)) goto out;
    if (plan && (C->nparts!=(int)plan->partitions ||
        memcmp(C->pfirst,plan->first,sizeof C->pfirst) || memcmp(C->plast,plan->last,sizeof C->plast))) {
        failf(C,"reviewed installation layout changed; nothing was written"); goto out;
    }
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
    catalog = build_driver_catalog(C, &gen[3].len);
    if (!catalog) goto out;                          /* build_driver_catalog set the reason */
    gen[3].path = DRIVER_CATALOG_PATH;
    gen[3].data = catalog;
    put32le(prefs,SETUP_PREFS_MAGIC); put32le(prefs+4,1);
    put32le(prefs+8,plan?plan->language:SETUP_LANGUAGE_KO); put32le(prefs+12,SETUP_KEYBOARD_US);
    gen[4].path=SETUP_PREFS_PATH; gen[4].data=(const char *)prefs; gen[4].len=sizeof prefs;
    if (cancellation(C)) { failf(C,"installation cancelled before disk writes"); goto out; }
    /* Final check after all payload validation, immediately before destruction. */
    if (plan && control->check(control->ctx,plan)) {
        failf(C,"reviewed target or source changed before first write"); goto out;
    }
    say(C, "destructive phase: erasing %s", C->di.name);
    phase(C,STAGE_WIPE,0);
    C->record_armed = 1;          /* the record is the first destructive write; any later failure leaves FAILED */
    if (write_record(C, REC_WRITING)) { failf(C, "install record at LBA %llu did not read back", (unsigned long long)C->record_lba); goto out; }
    say(C, "install record WRITING at LBA %llu", (unsigned long long)C->record_lba);
    if (wipe_tables(C)) goto out;
    phase(C,STAGE_ESP,1);
    if (write_esp(C) || verify_esp_files(C) || stamp_boot_manifest(C)) goto out;
    phase(C,STAGE_SYSTEM,1);
    if (plan_system(C, &w, &handles, &log_handle, gen, MAX_GEN) || write_system_data(C, w, handles, gen, MAX_GEN)) goto out;
    phase(C,STAGE_SYSTEM_VERIFY,1);
    if (verify_system(C, gen, MAX_GEN)) goto out;
    phase(C,STAGE_WIN98,0);
    if (C->nparts == 3 && format_win98(C)) goto out;
    phase(C,STAGE_GPT,0);
    if (write_gpt(C)) goto out;
    phase(C,STAGE_LOG,0);
    iso_time(P->now(P->ctx), when);
    say(C, "finished %s; %s installed on %s", when, json_str(C->man.root, "product") ? json_str(C->man.root, "product") : "ShizukuDOS",
        C->di.name);
    log_only(C, "SETUP-RESULT: OK\n");
    if (write_log(C, w, log_handle)) {
        P->out(P->ctx, "SHZSETUP: the install log could not be written; the installation itself verified\n");
        goto out;
    }
    say(C, "install log written to p2 /SHZ/SETUP/log/install.log (%u bytes) and read back", (unsigned)C->log_len);
    phase(C,STAGE_DONE,0);
    if (write_record(C, REC_COMPLETE)) {
        failf(C, "install record COMPLETE at LBA %llu did not read back", (unsigned long long)C->record_lba);
        goto out;
    }
    P->out(P->ctx, "SHZSETUP: install record COMPLETE written and read back\n");
    st = 0;
out:
    C->cleanup=1; C->can_cancel=0;
    if (st && C->record_armed) {
        if (write_record(C, REC_FAILED))
            P->out(P->ctx, "SHZSETUP: the FAILED install record could not be written or read back\n");
        else
            P->out(P->ctx, "SHZSETUP: install record FAILED (stage and reason) written before p1 and read back\n");
    }
    /* A verified-complete UI is impossible until the final record and the
     * device cache flush actually succeed. A flush failure retains FAILED. */
    if (!st && P->disk_flush(P->ctx,C->disk)) {
        st=-1; failf(C,"final device cache flush failed");
        if (C->record_armed) write_record(C,REC_FAILED);
    }
    notify(C,st==0);
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
    if (catalog) P->free(P->ctx, catalog);
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

void setup_run(const plat_t *P,const char *answer,const char *payload,setup_result_t *r)
{ run_engine(P,answer,payload,0,0,r); }
void setup_run_planned(const plat_t *P,const char *answer,const char *payload,
                       const setup_plan_t *plan,const setup_control_t *control,setup_result_t *r)
{ run_engine(P,answer,payload,plan,control,r); }

/* Read-only planning reuses the manifest parser, partition planner and actual
 * SFS writer's no-I/O layout. Reserved generated-file maxima are installation
 * policy, not a payload-size guess. 8 MiB of free SFS workspace is mandatory. */
#define PLAN_WORKSPACE (8ull*MIB)
static void quiet(void *ctx,const char *text) { (void)ctx; (void)text; }
static void plan_cleanup(ctx_t *C)
{
    if(C->manifest_text)C->P->free(C->P->ctx,C->manifest_text);
    json_free(C->P,&C->man);
    if(C->buf)C->P->free(C->P->ctx,C->buf);
}
static int plan_init(ctx_t *C,const plat_t *P,const char *payload)
{
    memset(C,0,sizeof *C); C->P=P;
    copy_str(C->payload,sizeof C->payload,payload);
    strcpy(C->cfg.hostname,"SHIZUKUOS"); strcpy(C->cfg.drivers,"all");
    C->cfg.bios_boot_code=1; C->cfg.allow_nonempty=1;
    C->buf=P->alloc(P->ctx,IOBUF);
    if(!C->buf)return failf(C,"out of memory");
    return read_manifest(C);
}
static int dry_system(ctx_t *C,uint64_t mib,sfsw_info *info)
{
    sfsw_t *w=0; uint32_t *handles=0,logh=0;
    gen_file_t gen[MAX_GEN]; int rc;
    memset(gen,0,sizeof gen);
    gen[0].path="/SHZ/SYSTEM.INI"; gen[0].len=4096;
    gen[1].path="/SHZ/SETUP/shzsetup.ini"; gen[1].len=1024;
    gen[2].path="/SHZ/SETUP/manifest.json"; gen[2].len=C->manifest_len;
    gen[3].path=DRIVER_CATALOG_PATH; gen[3].len=DRIVER_CATALOG_MAX_BYTES;
    gen[4].path=SETUP_PREFS_PATH; gen[4].len=16;
    C->pfirst[1]=0; C->plast[1]=mib*(MIB/512)-1; C->ss=512;
    C->layout_error=0;
    rc=plan_system(C,&w,&handles,&logh,gen,MAX_GEN);
    if(!rc){sfsw_get_info(w,info);if(info->free_blocks<PLAN_WORKSPACE/4096){C->layout_error=SFSW_ENOSPC;rc=-1;}}
    if(w)sfsw_destroy(w);
    if(handles)C->P->free(C->P->ctx,handles);
    return rc;
}
static int image_details(ctx_t *C,setup_image_t *image)
{
    const jnode_t *x; uint64_t bytes=0,rounded=0,high=MIN_SYSTEM_MIB,low=MIN_SYSTEM_MIB;
    sfsw_info info; int rc;
    memset(image,0,sizeof *image);
    if(!json_str(C->man.root,"product")||!json_str(C->man.root,"product")[0]||strlen(json_str(C->man.root,"product"))>=sizeof image->product)
        return failf(C,"installation image product/version metadata missing or too long");
    copy_str(image->product,sizeof image->product,json_str(C->man.root,"product"));
    memcpy(image->manifest_sha256,C->manifest_sha,32);
    json_u64(json_get(C->man.root,"esp"),"bytes",&image->esp_bytes);
    for(x=json_get(json_get(C->man.root,"system"),"files")->kid;x;x=x->next){
        if(!package_selected(C,json_str(x,"package")))continue;
        json_u64(x,"bytes",&bytes);
        if(bytes>UINT64_MAX-4095 || image->payload_bytes>UINT64_MAX-bytes ||
           rounded>UINT64_MAX-((bytes+4095)/4096)*4096)return failf(C,"payload size overflow");
        image->payload_bytes+=bytes; ++image->payload_files;
        rounded+=((bytes+4095)/4096)*4096;
    }
    if(rounded>UINT64_MAX-PLAN_WORKSPACE-MIB+1)return failf(C,"payload capacity overflow");
    high=(rounded+PLAN_WORKSPACE+MIB-1)/MIB;
    if(high<MIN_SYSTEM_MIB)high=MIN_SYSTEM_MIB;
    for(;;){
        memset(&info,0,sizeof info);rc=dry_system(C,high,&info);
        if(!rc)break;
        if(C->layout_error!=SFSW_ENOSPC)return -1;
        if(high>=(1ull<<24))return failf(C,"payload cannot fit supported SFS geometry");
        high*=2;
    }
    while(low<high){uint64_t mid=low+(high-low)/2;
        memset(&info,0,sizeof info);if(!dry_system(C,mid,&info))high=mid;
        else if(C->layout_error==SFSW_ENOSPC)low=mid+1;else return -1;
    }
    C->fail[0]=0;
    if(image->esp_bytes>UINT64_MAX-low*MIB-4*MIB)return failf(C,"installation size overflow");
    image->required_bytes=image->esp_bytes+low*MIB+4*MIB;
    return 0;
}
int setup_image_inspect(const plat_t *P,const char *payload,setup_image_t *image,setup_result_t *r)
{
    ctx_t C; plat_t silent=*P; int rc;
    memset(r,0,sizeof *r);silent.out=quiet;
    rc=plan_init(&C,&silent,payload);
    if(!rc)rc=image_details(&C,image);
    r->ok=!rc; copy_str(r->reason,sizeof r->reason,rc?C.fail:"");plan_cleanup(&C);return rc;
}
int setup_plan_build(const plat_t *P,const char *payload,const setup_target_t *target,
                     uint32_t language,setup_plan_t *plan,setup_result_t *r)
{
    ctx_t C; plat_t silent=*P; sfsw_info info; int rc; unsigned i; uint8_t any=0;
    memset(plan,0,sizeof *plan);memset(r,0,sizeof *r);silent.out=quiet;
    rc=plan_init(&C,&silent,payload);if(rc)goto done;
    for(i=0;i<16;++i)any|=target->whole_id[i];
    if(!any||!target->generation||(language!=SETUP_LANGUAGE_KO&&language!=SETUP_LANGUAGE_EN)||
       target->disk.flags&(PLAT_DISK_PARTITION|PLAT_DISK_READONLY)||target->disk.sector_size!=512||
       target->disk.sectors>UINT64_MAX/512){rc=failf(&C,"target authority or geometry unavailable");goto done;}
    rc=image_details(&C,&plan->image);if(rc)goto done;
    if(target->disk.sectors*512<plan->image.required_bytes){rc=failf(&C,"insufficient target capacity");goto done;}
    C.di=target->disk;C.disk=target->index;C.ss=512;
    rc=plan_layout(&C);if(rc)goto done;
    memcpy(plan->first,C.pfirst,sizeof plan->first);memcpy(plan->last,C.plast,sizeof plan->last);
    memset(&info,0,sizeof info);
    rc=dry_system(&C,(plan->last[1]-plan->first[1]+1)/2048,&info);if(rc){failf(&C,"system tree or workspace cannot fit");goto done;}
    plan->version=SETUP_PLAN_VERSION;plan->language=language;plan->keyboard=SETUP_KEYBOARD_US;
    plan->target=*target;plan->partitions=(uint32_t)C.nparts;
    plan->required_bytes=plan->image.required_bytes;
    plan->system_used_bytes=(info.blocks-info.free_blocks)*4096;
    plan->workspace_bytes=PLAN_WORKSPACE;plan->bios_boot=(uint32_t)C.bios_boot;
    plan->erase_whole_disk=1;
done:
    r->ok=!rc;copy_str(r->reason,sizeof r->reason,rc?C.fail:"");plan_cleanup(&C);return rc;
}
