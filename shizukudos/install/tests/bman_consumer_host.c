/* SPDX-License-Identifier: GPL-2.0-only
 * Host consumer pass for the SHZBOOT.MAN producer fixture: links the Supervisor's own shz_bman_parse
 * (supervisor/src/boot_manifest.c, unmodified) and runs it over a manifest + blob files written by
 * test_boot_manifest_producer.py. argv: manifest loader_flags cap_bits [NAME=file ...]. Prints PARSE-OK or
 * PARSE-FAIL <reason>. This checks structure/hash/blob binding only, not core.c hierarchy admission. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../supervisor/src/boot_manifest.h"

void log_capture(char *dst, unsigned size, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(dst, size, fmt, ap);
    va_end(ap);
}

static void *slurp(const char *path, uint64_t *len)
{
    FILE *f = fopen(path, "rb");
    void *p;
    long n;
    if (!f || fseek(f, 0, SEEK_END) || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) exit(2);
    p = aligned_alloc(64, ((size_t)n + 64) & ~(size_t)63);
    if (!p || fread(p, 1, (size_t)n, f) != (size_t)n) exit(2);
    fclose(f);
    *len = (uint64_t)n;
    return p;
}

int main(int argc, char **argv)
{
    static shz_info_t info;
    shz_blob_t man;
    shz_bman_t out;
    char err[160] = "";
    int i;
    if (argc < 4) return 2;
    memset(&man, 0, sizeof man);
    man.base = (uint64_t)(uintptr_t)slurp(argv[1], &man.size);
    info.loader_flags = (uint32_t)strtoul(argv[2], 0, 0);
    for (i = 4; i < argc && i - 4 < SHZ_MAX_BLOBS; ++i) {
        char *eq = strchr(argv[i], '=');
        if (!eq || eq - argv[i] > 15) return 2;
        memcpy(info.blobs[i - 4].name, argv[i], (size_t)(eq - argv[i]));
        info.blobs[i - 4].base = (uint64_t)(uintptr_t)slurp(eq + 1, &info.blobs[i - 4].size);
    }
    if (shz_bman_parse(&info, &man, (uint32_t)strtoul(argv[3], 0, 0), &out, err, sizeof err)) {
        printf("PARSE-FAIL %s\n", err);
        return 1;
    }
    printf("PARSE-OK entries=%u present=0x%x generation=%llu\n", out.count, out.present,
           (unsigned long long)out.header->install_generation);
    return 0;
}
