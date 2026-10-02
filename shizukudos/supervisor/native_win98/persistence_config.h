/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WIN98_PERSISTENCE_CONFIG_H
#define SHZ_WIN98_PERSISTENCE_CONFIG_H
#include <stdint.h>
#define W98_PERSIST_CONFIG_MAGIC 0x52503957u /* W9PR */
#define W98_PERSIST_CONFIG_VERSION 1u
#define W98_PERSIST_BAR_MEM32 1u
#define W98_PERSIST_BAR_MEM64 2u
#define W98_PERSIST_BAR_IO 3u
typedef struct { uint64_t base, bytes; uint32_t kind, reserved; } w98_persist_bar_t;
/* Separate W98PERS.BIN opt-in. Its producer/approval must bind these resources
 * to the actual owned QEMU device epoch; fixture bytes cannot authorize I/O. */
typedef struct {
    uint32_t magic, version;
    uint16_t bdf, vendor, device, reserved16;
    uint64_t esp_bytes, member_bytes;
    uint32_t volume_id, reserved32;
    w98_persist_bar_t bar[6];
    uint64_t reserved64;
} w98_persist_config_t;
_Static_assert(sizeof(w98_persist_config_t)==192,"separate persistence config extent");
#endif
