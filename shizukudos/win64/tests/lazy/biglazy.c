/* SPDX-License-Identifier: GPL-2.0-only
 * BIGLAZY.DLL / BIGRELOC.DLL: large test DLLs of known content for Kernel64's lazily mapped (file-backed) images.
 * Built by shizukudos/tests/k64_lazy_dll.py, not by win64/build.py: the blob (hundreds of MiB, generated
 * deterministically: page i = SHA-256("shz-lazy-<i>") repeated 128 times) is appended with .incbin (lazyblob.S).
 *
 *   page_hash(i)      touches exactly page i of the blob and returns a hash the host recomputes
 *   blob_pages()      number of 4 KiB blob pages
 *   check_relocs()    counts the pointers in .data that equal their expected targets after relocation: a table of
 *                     256 DIR64 pointers into the blob and one pointer that straddles a page boundary
 *                     (bytes 4092..4099 of a page-aligned structure)
 * No CRT, no DllMain, no imports: the only thing the loader has to get right is the mapping. */
#include <stdint.h>

extern const unsigned char big_blob[];
extern const unsigned char big_blob_end[];

#define TABLE 256

#define P(i) big_blob + (uint64_t)(i) * 4096u * 37u + (i)
#define P4(i) P(i), P(i + 1), P(i + 2), P(i + 3)
#define P16(i) P4(i), P4(i + 4), P4(i + 8), P4(i + 12)
#define P64(i) P16(i), P16(i + 16), P16(i + 32), P16(i + 48)
const unsigned char *ptr_table[TABLE] = { P64(0), P64(64), P64(128), P64(192) };

struct __attribute__((packed, aligned(4096))) straddle {
    unsigned char pad[4092];
    const unsigned char *p;                  /* bytes 4092..4099: the DIR64 fixup spans two pages */
    unsigned char tail[4];
};
struct straddle straddle_at_page_edge = { { 1 }, big_blob + 123, { 2 } };

__declspec(dllexport) uint64_t page_hash(uint64_t page)
{
    const volatile uint64_t *w = (const volatile uint64_t *)(big_blob + page * 4096u);
    uint64_t h = 0x5348495a554b4136ull ^ page;
    unsigned i;
    for (i = 0; i < 512; ++i) h = ((h << 7) | (h >> 57)) ^ w[i];
    return h;
}

__declspec(dllexport) uint64_t blob_pages(void) { return (uint64_t)(big_blob_end - big_blob) / 4096u; }

__declspec(dllexport) const void *blob_address(void) { return big_blob; }

__declspec(dllexport) int check_relocs(void)
{
    const volatile unsigned char *const volatile *t = (const volatile unsigned char *const volatile *)ptr_table;
    int good = 0;
    unsigned i;
    for (i = 0; i < TABLE; ++i)
        if (t[i] == big_blob + (uint64_t)i * 4096u * 37u + i) ++good;
    if (*(const unsigned char *const volatile *)&straddle_at_page_edge.p == big_blob + 123) good += 1000;
    return good;
}
