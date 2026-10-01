/* SPDX-License-Identifier: GPL-2.0-only
 * QEMU 10.1 Multiboot prepends its image filename. Other Multiboot loaders
 * control their own command line; never assume that their first word is a path.
 * This adapter changes only the standalone K32 provider, not service policy.
 */
#ifndef SHZ_K32_MULTIBOOT_CMDLINE_H
#define SHZ_K32_MULTIBOOT_CMDLINE_H
#include <stdint.h>
#include "../../abi/shz_abi.h"

static inline int shz_mb1_loader_is_qemu(const volatile char *name)
{
    const char expected[] = "qemu";
    if (!name) return 0;
    for (unsigned i=0;i<sizeof expected;++i)
        if (name[i]!=expected[i]) return 0;
    return 1;
}

/* Reads at most SHZ_CMDLINE_MAX bytes, including the required terminator.
 * Unknown arguments remain present for the fail-closed service validator.
 * No truncation can silently remove an explicit service-mode request.
 */
static inline int shz_mb1_k32_cmdline(char *out, uint32_t capacity,
                                    const volatile char *raw, int image_prefix)
{
    uint32_t at=0, used=0;
    if (!out || !capacity || !raw) return -1;
    out[0]=0;
    if (image_prefix) {
        for (;;) {
            if (at==SHZ_CMDLINE_MAX) return -1;
            const unsigned char c=(unsigned char)raw[at];
            if (!c) return 0;
            if (c==' ' || c=='\t') {
                if (!at) return -1;
                break;
            }
            if (c<0x20 || c>=0x7f) return -1;
            ++at;
        }
        while (at<SHZ_CMDLINE_MAX && (raw[at]==' ' || raw[at]=='\t')) ++at;
    }
    while (at<SHZ_CMDLINE_MAX) {
        const unsigned char c=(unsigned char)raw[at++];
        if (!c) { out[used]=0; return (int)used; }
        if (c<0x20 || c>=0x7f || used>=capacity-1) { out[0]=0; return -1; }
        out[used++]=(char)c;
    }
    out[0]=0;
    return -1;
}
#endif
