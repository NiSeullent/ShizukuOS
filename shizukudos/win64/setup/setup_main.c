/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP.EXE: the ShizukuDOS installer as a Win64 console program on Kernel64.
 *
 *   SHZSETUP.EXE [/unattend <answer.ini>] [/payload <dir>]
 *     defaults: C:\SHZ\SETUP\SHZSETUP.INI and C:\SHZ\SETUP\PAYLOAD (manifest.json, ESP.SIM, SYSTEM.ARC, GPTMBR.BIN)
 *
 * Platform glue for the portable core (install.c): payload files through kernel32, SHA-256 and random numbers through
 * bcrypt.dll, block devices through the installer syscalls (blkio.c). Exit code 0 = SETUP-RESULT: OK, 1 = FAIL; the
 * answer file's Reboot= choice is handed to the kernel (NtShzSetupPower), which acts on it after this process exits.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include "plat.h"                       /* before shzcrt.h, whose malloc/free macros would rename plat_t members */
#include "native_install.h"
#include "blkio.h"
#include "interactive_ui.h"
#include "shzcrt.h"

static BCRYPT_ALG_HANDLE sha_alg;
static char interactive_answer[1024];
static const char ui_answer_path[] = "SHZSETUP:INTERACTIVE";
static int interactive;

static void out(void *c, const char *t)
{ (void)c; shz_puts(t); if (interactive) setup_ui_progress(t); }
static void *al(void *c, size_t n) { (void)c; return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n ? n : 1); }
static void fr(void *c, void *p) { (void)c; if (p) HeapFree(GetProcessHeap(), 0, p); }

static int f_open(void *c, const char *path, void **h, uint64_t *size)
{
    char p[260];
    size_t i;
    LARGE_INTEGER sz;
    HANDLE f;
    (void)c;
    if (interactive && !strcmp(path, ui_answer_path)) {
        *h = interactive_answer; *size = strlen(interactive_answer); return 0;
    }
    for (i = 0; path[i] && i < sizeof p - 1; ++i) p[i] = path[i] == '/' ? '\\' : path[i];
    p[i] = 0;
    f = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (f == INVALID_HANDLE_VALUE) return -1;
    if (!GetFileSizeEx(f, &sz)) { CloseHandle(f); return -1; }
    *h = f;
    *size = (uint64_t)sz.QuadPart;
    return 0;
}

static int f_read(void *c, void *h, uint64_t off, void *buf, uint32_t len)
{
    LARGE_INTEGER pos;
    DWORD got;
    uint8_t *p = buf;
    (void)c;
    if (h == interactive_answer) {
        const size_t size = strlen(interactive_answer);
        if (off > size || len > size - off) return -1;
        memcpy(buf, interactive_answer + (size_t)off, len); return 0;
    }
    pos.QuadPart = (LONGLONG)off;
    if (!SetFilePointerEx(h, pos, 0, FILE_BEGIN)) return -1;
    while (len) {
        if (!ReadFile(h, p, len, &got, 0) || !got) return -1;
        p += got;
        len -= got;
    }
    return 0;
}

static void f_close(void *c, void *h) { (void)c; if (h != interactive_answer) CloseHandle(h); }

static void *sha_begin(void *c)
{
    BCRYPT_HASH_HANDLE h = 0;
    (void)c;
    if (BCryptCreateHash(sha_alg, &h, 0, 0, 0, 0, 0)) return 0;
    return h;
}
static void sha_update(void *c, void *s, const void *buf, uint32_t len) { (void)c; if (s) BCryptHashData(s, (PUCHAR)buf, len, 0); }
static void sha_end(void *c, void *s, uint8_t o[32])
{
    (void)c;
    memset(o, 0, 32);
    if (!s) return;
    BCryptFinishHash(s, o, 32, 0);
    BCryptDestroyHash(s);
}
static int rnd(void *c, void *buf, uint32_t len) { (void)c; return BCryptGenRandom(0, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) ? -1 : 0; }
static uint64_t now(void *c)
{
    FILETIME ft;
    uint64_t t;
    (void)c;
    GetSystemTimeAsFileTime(&ft);
    t = (uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime;
    return t < 116444736000000000ull ? 0 : (t - 116444736000000000ull) / 10000000ull;
}

/* Development entry only. The kernel storage-authority adapter is not yet
 * supplied. NULL native ops refuse before file opens, device enumeration or
 * writes. Final importer/UI will supply its own admitted pin and reviewed
 * whole tuple; command-line text cannot provide whole-device authority. */
static int native_cli(const plat_t *p, int argc, char **argv)
{
    native_setup_request_v1_t q;
    native_setup_result_v1_t r;
    unsigned seen = 0;
    int i;
    memset(&q, 0, sizeof q);
    q.version = NATIVE_SETUP_VERSION; q.bytes = sizeof q;
    q.reviewed_target.disk.sector_size = 512;
    if (argc < 3 || strlen(argv[2]) > NATIVE_SETUP_PATH_MAX) goto bad;
    q.manifest_path = argv[2];
    for (i = 3; i < argc; i += 2) {
        const char *s;
        unsigned bit, j;
        if (i + 1 >= argc) goto bad;
        s = argv[i + 1];
        if (!strcmp(argv[i], "/sim")) {
            bit = 1; if (!*s || strlen(s) > NATIVE_SETUP_PATH_MAX) goto bad; q.sim_path = s;
        } else if (!strcmp(argv[i], "/manifest-sha256")) {
            bit = 2; if (strlen(s) != 64) goto bad;
            for (j = 0; j < 32; ++j) {
                unsigned a, b; char x = s[2*j], y = s[2*j+1];
                if (x >= '0' && x <= '9') a = (unsigned)(x-'0');
                else if (x >= 'a' && x <= 'f') a = (unsigned)(x-'a'+10); else goto bad;
                if (y >= '0' && y <= '9') b = (unsigned)(y-'0');
                else if (y >= 'a' && y <= 'f') b = (unsigned)(y-'a'+10); else goto bad;
                q.admitted_manifest_sha256[j] = (uint8_t)(a*16+b);
            }
        } else if (!strcmp(argv[i], "/target")) {
            bit = 4; if (!*s || strlen(s) >= sizeof q.reviewed_target.disk.name) goto bad;
            strcpy(q.reviewed_target.disk.name, s);
        } else if (!strcmp(argv[i], "/serial")) {
            bit = 8; if (!*s || strlen(s) >= sizeof q.reviewed_target.disk.serial) goto bad;
            strcpy(q.reviewed_target.disk.serial, s);
        } else if (!strcmp(argv[i], "/sectors")) {
            uint64_t n = 0; bit = 16; if (!*s) goto bad;
            for (j = 0; s[j]; ++j) {
                unsigned d;
                if (s[j] < '0' || s[j] > '9') goto bad;
                d = (unsigned)(s[j]-'0'); if (n > (UINT64_MAX-d)/10) goto bad; n = n*10+d;
            }
            if (!n || n > UINT64_MAX/512) goto bad;
            q.reviewed_target.disk.sectors = n;
        } else if (!strcmp(argv[i], "/confirm")) {
            bit = 32; if (strcmp(s, "ERASE")) goto bad; q.confirmation = s;
        } else goto bad;
        if (seen & bit) goto bad;
        seen |= bit;
    }
    if (seen != 63) goto bad;
    setup_run_native(p, 0, &q, &r);
    return r.ok ? 0 : 1;
bad:
    shz_puts("NATIVE-SETUP-RESULT: FAIL invalid explicit native command line (no disk writes)\n");
    return 1;
}

int main(int argc, char **argv)
{
    plat_t P = {0, out, al, fr, f_open, f_read, f_close, sha_begin, sha_update, sha_end, rnd, now,
                blkio_count, blkio_info, blkio_read, blkio_write, blkio_flush, BLKIO_MAX_SECTORS};
    const char *answer = "C:\\SHZ\\SETUP\\SHZSETUP.INI", *payload = "C:\\SHZ\\SETUP\\PAYLOAD";
    setup_result_t r;
    int i, unattended = 0;
    if (argc > 1 && !strcmp(argv[1], "/native")) return native_cli(&P, argc, argv);
    interactive = 1;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "/unattend") && i + 1 < argc) { answer = argv[++i]; unattended = 1; }
        else if (!strcmp(argv[i], "/interactive")) { /* default */ }
        else if (!strcmp(argv[i], "/payload") && i + 1 < argc) payload = argv[++i];
        else {
            printf("usage: SHZSETUP.EXE [/interactive | /unattend answer.ini] [/payload dir]\n");
            printf("SETUP-RESULT: FAIL bad command line\n");
            return 1;
        }
    }
    interactive = !unattended;
    if (BCryptOpenAlgorithmProvider(&sha_alg, BCRYPT_SHA256_ALGORITHM, 0, 0)) {
        printf("SETUP-RESULT: FAIL bcrypt.dll has no SHA-256 provider\n");
        return 1;
    }
    if (blkio_init()) {
        BCryptCloseAlgorithmProvider(sha_alg, 0);
        printf("SETUP-RESULT: FAIL block devices could not be enumerated\n");
        return 1;
    }
    if (interactive) {
        int chosen = setup_ui_choose(&P, interactive_answer, sizeof interactive_answer);
        if (chosen) {
            BCryptCloseAlgorithmProvider(sha_alg, 0);
            printf(chosen > 0 ? "SETUP-RESULT: CANCELLED (no disk writes)\n" :
                               "SETUP-RESULT: FAIL interactive display unavailable (no disk writes)\n");
            return chosen > 0 ? 0 : 1;
        }
        answer = ui_answer_path;
    }
    setup_run(&P, answer, payload, &r);
    BCryptCloseAlgorithmProvider(sha_alg, 0);
    if (interactive) setup_ui_finish(&r);
    blkio_power(r.power);
    return r.ok ? 0 : 1;
}
