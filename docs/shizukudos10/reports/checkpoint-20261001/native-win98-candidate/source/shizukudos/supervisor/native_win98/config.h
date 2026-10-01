/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WIN98_CONFIG_H
#define SHZ_WIN98_CONFIG_H
#include <stdint.h>
#define W98_CONFIG_MAGIC 0x38395753u
#define W98_CONFIG_VERSION 1u
#define W98_RAM_MIB 128u
#define W98_DISK_BYTES (2ull << 30)
#define W98_ROM_BYTES (256u << 10)
typedef struct {uint32_t magic,version,ram_mib,reserved;} w98_config_t;
static inline int w98_config_valid(const w98_config_t *c,uint64_t size)
{return size==sizeof *c && c->magic==W98_CONFIG_MAGIC && c->version==W98_CONFIG_VERSION && c->ram_mib==W98_RAM_MIB && !c->reserved;}
#endif
