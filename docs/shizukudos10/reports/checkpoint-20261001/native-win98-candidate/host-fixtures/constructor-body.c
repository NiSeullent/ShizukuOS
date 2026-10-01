/* SPDX-License-Identifier: GPL-2.0-only
 * Explicit installed-Win98 domain. Executes genuine SeaBIOS on an actual VMCS;
 * the BIOS constructs its own IVT/BDA/boot flow. No Shizuku low-memory bootinfo.
 */
#include "win98.h"
#include "config.h"
#include "ata_pio.h"
#include "string_pio.h"
#include "../src/console.h"
#include "../src/cpu.h"
#include "../src/devices.h"
#include "../src/guest.h"
#include "../src/pool.h"
#include "../src/video.h"
static domain_t *w98;
static w98_ata_t ata;
static const shz_blob_t *rom;
static uint64_t last_render;
static const shz_blob_t *find_rom(const shz_info_t *info)
{
    static const char name[]="SEABIOS.BIN";
    unsigned i,k;
    for(i=0;i<SHZ_MAX_BLOBS;++i) {
        for(k=0;k<sizeof name && info->blobs[i].name[k]==name[k];++k) {}
        if(k==sizeof name && info->blobs[i].size) return &info->blobs[i];
    }
    return 0;
}
static void uart_tx(uint8_t c)
{
    serial_putc((char)c);++G.info->guest_console_bytes;
}
static void ata_irq(void *unused)
{
    (void)unused;dev_irq_raise(14);
}
int win98_domain_create(shz_info_t *info,const shz_caps_t *caps)
{
    domain_t *d=&g_dom[SHZ_DOM_WIN98];vmx_cfg_t cfg;uint8_t *ram;
    rom=find_rom(info);
    if(!(info->loader_flags&SHZ_LOADER_NATIVE_WIN98) || !rom || rom->size!=W98_ROM_BYTES ||
       (rom->base&4095) || !info->guest_ram_base || (info->guest_ram_base&4095) ||
       info->guest_ram_size!=(uint64_t)W98_RAM_MIB<<20 || !info->disk_base || info->disk_size!=W98_DISK_BYTES) {
        log_capture(info->last_error,sizeof info->last_error,"invalid explicit Win98 RAM/disk/SeaBIOS geometry");return -1;
    }
    memset(d,0,sizeof *d);memset(&cfg,0,sizeof cfg);
    d->id=SHZ_DOM_WIN98;d->name="WIN98";d->kind=DK_WIN98;d->generation=1;
    d->ram_base=info->guest_ram_base;d->ram_size=info->guest_ram_size;
    d->fx[0]=0x7f;d->fx[1]=3;d->fx[24]=0x80;d->fx[25]=0x1f;
    ram=(uint8_t *)(uintptr_t)d->ram_base;memset(ram,0,d->ram_size);
    /* Standard ISA alias is the final128KiB; full ROM is also mapped at the top
     * of the real32-bit physical bus for SeaBIOS's genuine protected-mode code. */
    memcpy(ram+0xe0000,(const void *)(uintptr_t)(rom->base+rom->size-0x20000),0x20000);
    if(ept_init(&d->ept) || ept_map(&d->ept,0,d->ram_base,d->ram_size,EPT_RWX|EPT_WB,1) ||
       ept_map(&d->ept,0x100000000ull-rom->size,rom->base,rom->size,EPT_R|EPT_X|EPT_WB,1)) {
        log_capture(info->last_error,sizeof info->last_error,"Win98 EPT RAM/real-ROM construction failed");return -1;
    }
    d->io_bitmap_a=pool_alloc_pages(1);d->io_bitmap_b=pool_alloc_pages(1);d->msr_bitmap=pool_alloc_pages(1);cfg.vmcs=pool_alloc_pages(1);
    if(!d->io_bitmap_a || !d->io_bitmap_b || !d->msr_bitmap || !cfg.vmcs) {
        log_capture(info->last_error,sizeof info->last_error,"Win98 Supervisor pool exhausted");return -1;
    }
    memset(d->io_bitmap_a,0xff,4096);memset(d->io_bitmap_b,0xff,4096);memset(d->msr_bitmap,0xff,4096);
    G.info=info;G.vc=&d->vc;G.ram_base=d->ram_base;G.ram_size=d->ram_size;G.tsc_hz=info->tsc_hz;
    dev_init(info->tsc_hz,d->ram_size);dev_uart_tx_hook=uart_tx;
    if(w98_ata_init(&ata,(uint8_t *)(uintptr_t)info->disk_base,info->disk_size,ata_irq,0)) return -1;
    cfg.io_bitmap_a=d->io_bitmap_a;cfg.io_bitmap_b=d->io_bitmap_b;cfg.msr_bitmap=d->msr_bitmap;
    cfg.mode=VMODE_REAL;cfg.eptp=ept_pointer(&d->ept);cfg.vpid=SHZ_DOM_WIN98;
    cfg.cs_sel=0xf000;cfg.rip=0xfff0;cfg.rsp=0;cfg.cr3=0;
    if(vmx_vcpu_init(&d->vc,info,caps,&cfg)) return -1;
    w98=d;d->state=SHZ_DS_RUNNABLE;
    info->domains[d->id].kind=d->kind;info->domains[d->id].generation=d->generation;info->domains[d->id].state=d->state;
    kprintf("SHZ: real Win98 VMCS created RAM=%lluMiB SeaBIOS=%llu owned ATA=%llu bytes (boot unverified)\n",d->ram_size>>20,rom->size,ata.bytes);
    return 0;
}
