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
#include "blkio.h"
#include "shzcrt.h"

static BCRYPT_ALG_HANDLE sha_alg;

static void out(void *c, const char *t) { (void)c; shz_puts(t); }
static void *al(void *c, size_t n) { (void)c; return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n ? n : 1); }
static void fr(void *c, void *p) { (void)c; if (p) HeapFree(GetProcessHeap(), 0, p); }

static int f_open(void *c, const char *path, void **h, uint64_t *size)
{
    char p[260];
    size_t i;
    LARGE_INTEGER sz;
    HANDLE f;
    (void)c;
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
    pos.QuadPart = (LONGLONG)off;
    if (!SetFilePointerEx(h, pos, 0, FILE_BEGIN)) return -1;
    while (len) {
        if (!ReadFile(h, p, len, &got, 0) || !got) return -1;
        p += got;
        len -= got;
    }
    return 0;
}

static void f_close(void *c, void *h) { (void)c; CloseHandle(h); }

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

int main(int argc, char **argv)
{
    plat_t P = {0, out, al, fr, f_open, f_read, f_close, sha_begin, sha_update, sha_end, rnd, now,
                blkio_count, blkio_info, blkio_read, blkio_write, blkio_flush, BLKIO_MAX_SECTORS};
    const char *answer = "C:\\SHZ\\SETUP\\SHZSETUP.INI", *payload = "C:\\SHZ\\SETUP\\PAYLOAD";
    setup_result_t r;
    int i;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "/unattend") && i + 1 < argc) answer = argv[++i];
        else if (!strcmp(argv[i], "/payload") && i + 1 < argc) payload = argv[++i];
        else {
            printf("usage: SHZSETUP.EXE [/unattend answer.ini] [/payload dir]\n");
            printf("SETUP-RESULT: FAIL bad command line\n");
            return 1;
        }
    }
    if (BCryptOpenAlgorithmProvider(&sha_alg, BCRYPT_SHA256_ALGORITHM, 0, 0)) {
        printf("SETUP-RESULT: FAIL bcrypt.dll has no SHA-256 provider\n");
        return 1;
    }
    if (blkio_init()) {
        printf("SETUP-RESULT: FAIL block devices could not be enumerated\n");
        return 1;
    }
    setup_run(&P, answer, payload, &r);
    BCryptCloseAlgorithmProvider(sha_alg, 0);
    blkio_power(r.power);
    return r.ok ? 0 : 1;
}
