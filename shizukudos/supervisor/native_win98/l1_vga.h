/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_L1_VGA_H
#define SHZ_L1_VGA_H
#include <stdint.h>
#define W98_VGA_MAGIC 0x41475657u
#define W98_VGA_ROM_BYTES 65536u
#define W98_VGA_LFB_BYTES (16u<<20)
/* Separate opt-in input; existing W98 config and shz_info ABI are unchanged.
 * Producer source/config digests identify inputs, never certify runtime/source
 * provenance by themselves. The actual build receipt remains independently required. */
typedef struct {
    uint32_t magic,version,bytes,flags,bdf,reserved;
    uint64_t lfb_base,lfb_bytes;
    uint8_t rom_sha256[32],source_sha256[32],config_sha256[32];
} w98_vga_config_t;
_Static_assert(sizeof(w98_vga_config_t)==136,"VGA binding wire extent");
typedef struct {
    void *opaque;
    uint32_t (*cfg_read)(void *,uint16_t,unsigned);
    int (*in)(void *,uint16_t,unsigned,uint32_t *);
    int (*out)(void *,uint16_t,unsigned,uint32_t);
    int (*map)(void *,uint32_t,uint64_t,uint32_t,uint64_t);
    int (*host_uc)(void *,uint64_t,uint64_t);
    int (*exclude_display_writers)(void *);
    int (*a20_get)(void *);
} w98_vga_ops_t;
typedef struct {
    w98_vga_config_t binding;
    w98_vga_ops_t ops;
    const uint8_t *rom;
    uint8_t *aperture_pointer;
    uint32_t selector,bar0,rombar;
    uint8_t config[256];
    uint16_t dispi_index;
    unsigned active,failed,bar_probe,rom_probe,a20_on;
} w98_l1_vga_t;
int w98_vga_config_valid(const w98_vga_config_t *,uint64_t);
int w98_l1_vga_init(w98_l1_vga_t *,const w98_vga_config_t *,uint64_t,const uint8_t *,uint64_t,const w98_vga_ops_t *);
/* 0 unrelated/inactive, 1 handled, -1 fatal mapping/hardware failure. */
int w98_l1_vga_in(w98_l1_vga_t *,uint16_t,unsigned,uint32_t *);
int w98_l1_vga_out(w98_l1_vga_t *,uint16_t,unsigned,uint32_t);
/* 1 means the range belongs to the selected device even when decode is off. */
int w98_l1_vga_physical(w98_l1_vga_t *,uint32_t,unsigned,int,uint8_t **);
int w98_l1_vga_page(w98_l1_vga_t *,uint32_t,uint64_t *,uint64_t *);
int w98_l1_vga_sync_a20(w98_l1_vga_t *,int);
#endif
