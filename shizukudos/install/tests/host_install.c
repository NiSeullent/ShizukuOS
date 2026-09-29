/* SPDX-License-Identifier: GPL-2.0-only
 * Host platform for the SHZSETUP core (win64/setup/install.c): runs the very same installer code on Linux against
 * disk image files, so the partitioning, ESP write, ShizukuFS population, FAT32 format and verification logic can be
 * tested quickly (run_host_install.py) before the guest run (tests/run_install.py) exercises it on Kernel64.
 *   host_install --answer FILE --payload DIR --disk NAME=IMAGE[,SERIAL] [--disk ...]
 * Exit code 0 when the installer printed SETUP-RESULT: OK.
 */
#define _DEFAULT_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "../../win64/setup/plat.h"

/* ---- SHA-256 (FIPS 180-4), host tests only; the guest uses bcrypt.dll ---- */
typedef struct { uint32_t h[8]; uint64_t len; uint8_t b[64]; unsigned n; } sha_t;
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha_block(sha_t *s, const uint8_t *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; ++i) w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (i = 16; i < 64; ++i)
        w[i] = (ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10)) + w[i - 7] + (ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3)) + w[i - 16];
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3]; e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}
static void *sha_begin(void *ctx)
{
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    sha_t *s = calloc(1, sizeof *s);
    (void)ctx;
    memcpy(s->h, iv, sizeof iv);
    return s;
}
static void sha_update(void *ctx, void *v, const void *buf, uint32_t len)
{
    sha_t *s = v;
    const uint8_t *p = buf;
    (void)ctx;
    s->len += len;
    while (len) {
        if (s->n == 0 && len >= 64) { sha_block(s, p); p += 64; len -= 64; continue; }
        s->b[s->n++] = *p++;
        --len;
        if (s->n == 64) { sha_block(s, s->b); s->n = 0; }
    }
}
static void sha_end(void *ctx, void *v, uint8_t out[32])
{
    sha_t *s = v;
    const uint64_t bits = s->len * 8;
    uint8_t pad = 0x80, z = 0, L[8];
    int i;
    sha_update(ctx, s, &pad, 1);
    while (s->n != 56) sha_update(ctx, s, &z, 1);
    for (i = 0; i < 8; ++i) L[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha_update(ctx, s, L, 8);
    for (i = 0; i < 8; ++i) { out[4 * i] = (uint8_t)(s->h[i] >> 24); out[4 * i + 1] = (uint8_t)(s->h[i] >> 16); out[4 * i + 2] = (uint8_t)(s->h[i] >> 8); out[4 * i + 3] = (uint8_t)s->h[i]; }
    free(s);
}

/* ---- platform ---- */
typedef struct { char name[16], serial[32]; int fd; uint64_t sectors; } hdisk_t;
static hdisk_t disks[8];
static unsigned ndisks;

static void out(void *c, const char *t) { (void)c; fputs(t, stdout); fflush(stdout); }
static void *al(void *c, size_t n) { (void)c; return calloc(1, n ? n : 1); }
static void fr(void *c, void *p) { (void)c; free(p); }
static int fopen_(void *c, const char *path, void **h, uint64_t *size)
{
    struct stat st;
    int fd = open(path, O_RDONLY);
    (void)c;
    if (fd < 0 || fstat(fd, &st)) return -1;
    *h = (void *)(intptr_t)(fd + 1);
    *size = (uint64_t)st.st_size;
    return 0;
}
static int fread_(void *c, void *h, uint64_t off, void *buf, uint32_t len)
{
    (void)c;
    return pread((int)(intptr_t)h - 1, buf, len, (off_t)off) == (ssize_t)len ? 0 : -1;
}
static void fclose_(void *c, void *h) { (void)c; close((int)(intptr_t)h - 1); }
static int rnd(void *c, void *buf, uint32_t len)
{
    int fd = open("/dev/urandom", O_RDONLY), ok;
    (void)c;
    ok = fd >= 0 && read(fd, buf, len) == (ssize_t)len;
    if (fd >= 0) close(fd);
    return ok ? 0 : -1;
}
static uint64_t now(void *c) { (void)c; return (uint64_t)time(0); }
static unsigned dcount(void *c) { (void)c; return ndisks; }
static int dinfo(void *c, unsigned i, plat_disk_t *o)
{
    (void)c;
    if (i >= ndisks) return -1;
    memset(o, 0, sizeof *o);
    memcpy(o->name, disks[i].name, sizeof o->name);
    memcpy(o->serial, disks[i].serial, sizeof o->serial);
    o->sectors = disks[i].sectors;
    o->sector_size = 512;
    return 0;
}
static int dread(void *c, unsigned i, uint64_t lba, uint32_t n, void *buf)
{
    (void)c;
    if (i >= ndisks || lba + n > disks[i].sectors) return -1;
    return pread(disks[i].fd, buf, (size_t)n * 512, (off_t)(lba * 512)) == (ssize_t)n * 512 ? 0 : -1;
}
static int dwrite(void *c, unsigned i, uint64_t lba, uint32_t n, const void *buf)
{
    (void)c;
    if (i >= ndisks || lba + n > disks[i].sectors) return -1;
    return pwrite(disks[i].fd, buf, (size_t)n * 512, (off_t)(lba * 512)) == (ssize_t)n * 512 ? 0 : -1;
}
static int dflush(void *c, unsigned i) { (void)c; return i < ndisks && !fsync(disks[i].fd) ? 0 : -1; }

int main(int argc, char **argv)
{
    plat_t P = {0, out, al, fr, fopen_, fread_, fclose_, sha_begin, sha_update, sha_end, rnd, now,
                dcount, dinfo, dread, dwrite, dflush, 2048};
    setup_result_t r;
    const char *answer = 0, *payload = 0;
    int i;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--answer") && i + 1 < argc) answer = argv[++i];
        else if (!strcmp(argv[i], "--payload") && i + 1 < argc) payload = argv[++i];
        else if (!strcmp(argv[i], "--disk") && i + 1 < argc && ndisks < 8) {
            char spec[512], *eq, *comma;
            struct stat st;
            snprintf(spec, sizeof spec, "%s", argv[++i]);
            eq = strchr(spec, '=');
            if (!eq) return 2;
            *eq = 0;
            comma = strchr(eq + 1, ',');
            if (comma) { *comma = 0; snprintf(disks[ndisks].serial, sizeof disks[ndisks].serial, "%.31s", comma + 1); }
            snprintf(disks[ndisks].name, sizeof disks[ndisks].name, "%.15s", spec);
            disks[ndisks].fd = open(eq + 1, O_RDWR);
            if (disks[ndisks].fd < 0 || fstat(disks[ndisks].fd, &st)) { perror(eq + 1); return 2; }
            disks[ndisks].sectors = (uint64_t)st.st_size / 512;
            ++ndisks;
        } else {
            fprintf(stderr, "usage: %s --answer FILE --payload DIR --disk NAME=IMAGE[,SERIAL] ...\n", argv[0]);
            return 2;
        }
    }
    if (!answer || !payload) return 2;
    setup_run(&P, answer, payload, &r);
    printf("host_install: ok=%d power=%d\n", r.ok, r.power);
    return r.ok ? 0 : 1;
}
