/* SPDX-License-Identifier: GPL-2.0-only
 * Host check of fat32_overwrite_file() (win64/setup/fat32fmt.c, the SHZSETUP source) on a small mkfs.fat image.
 * argv: image path newdata-file. Overwrites `path` in place, then re-mounts and streams it back. Exit 0 = written and
 * read back equal; prints OVERWRITE-<status>. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../win64/setup/fat32fmt.h"

static FILE *img;
static uint64_t sectors;
static int rd(void *c, uint64_t s, uint32_t n, void *b) { (void)c; return fseek(img, (long)(s * 512), SEEK_SET) || fread(b, 512, n, img) != n; }
static int wr(void *c, uint64_t s, uint32_t n, const void *b)
{
    (void)c;
    if (s + n > sectors) return -1;
    return fseek(img, (long)(s * 512), SEEK_SET) || fwrite(b, 512, n, img) != n;
}
static uint8_t back[1 << 16];
static uint32_t back_len;
static int sink(void *c, const void *d, uint32_t n) { (void)c; if (n > sizeof back - back_len) return 1; memcpy(back + back_len, d, n); back_len += n; return 0; }

int main(int argc, char **argv)
{
    static fat32_vol v;
    static uint8_t data[1 << 16], cbuf[128 * 512];
    fat32_rio io;
    uint32_t first, size;
    int st, dir;
    size_t n;
    FILE *f;
    if (argc != 4 || !(img = fopen(argv[1], "r+b")) || !(f = fopen(argv[3], "rb"))) return 2;
    n = fread(data, 1, sizeof data, f);
    fclose(f);
    fseek(img, 0, SEEK_END);
    sectors = (uint64_t)ftell(img) / 512;
    io.ctx = 0; io.read = rd; io.sectors = sectors;
    if ((st = fat32_mount(&v, &io))) { printf("OVERWRITE-MOUNT %s\n", fat32_rstrerror(st)); return 1; }
    st = fat32_overwrite_file(&v, wr, 0, argv[2], data, (uint32_t)n, cbuf);
    if (st) { printf("OVERWRITE-REFUSED %s\n", fat32_rstrerror(st)); return 1; }
    fflush(img);
    if ((st = fat32_mount(&v, &io)) || (st = fat32_lookup(&v, argv[2], &first, &size, &dir)) ||
        (st = fat32_stream(&v, first, size, cbuf, sink, 0))) { printf("OVERWRITE-READBACK %s\n", fat32_rstrerror(st)); return 1; }
    if (back_len != n || memcmp(back, data, n)) { printf("OVERWRITE-READBACK differs\n"); return 1; }
    printf("OVERWRITE-OK %u bytes\n", (unsigned)n);
    fclose(img);
    return 0;
}
