/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_K32_NATIVE_HANDOFF_H
#define SHZ_K32_NATIVE_HANDOFF_H
#include <stdint.h>
#define K32_NATIVE_HANDOFF_GPA 0x6000u
#define K32_NATIVE_WRITER 0x32424d53u
#define K32_NATIVE_MAGIC 0x32415048u
typedef struct { uint32_t magic, version, size, writer, profile, low, bytes, paging_off, checksum; } k32_native_handoff_t;
static inline uint32_t k32_native_checksum(const k32_native_handoff_t *h)
{
    return h->magic+h->version+h->size+h->writer+h->profile+h->low+h->bytes+h->paging_off+h->checksum;
}
static inline int k32_native_handoff_valid(const k32_native_handoff_t *h)
{
    return h && h->magic==K32_NATIVE_MAGIC && h->version==1 && h->size==sizeof *h &&
        h->writer==K32_NATIVE_WRITER && h->profile==32 && h->low==0x1000 && h->bytes==0x7000 &&
        h->paging_off==1 && !k32_native_checksum(h);
}
#endif
