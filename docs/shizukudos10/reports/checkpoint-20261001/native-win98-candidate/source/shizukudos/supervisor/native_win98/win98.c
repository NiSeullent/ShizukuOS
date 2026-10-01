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
static uint8_t *physical(void *opaque,uint32_t gpa,unsigned bytes,int write)
{
    domain_t *d=opaque;
    if(!dev_a20_get()) gpa&=~0x100000u;
    if(gpa>=0x100000000ull-rom->size) {
        const uint64_t offset=gpa-(0x100000000ull-rom->size);
        if(write || bytes>rom->size-offset) return 0;
        return (uint8_t *)(uintptr_t)(rom->base+offset);
    }
    return dom_gpa_ptr(d,gpa,bytes);
}
static int input(void *unused,uint16_t port,unsigned bytes,uint32_t *value)
{
    (void)unused;
    if(w98_ata_in(&ata,port,bytes,value) || dev_pio_in(port,(int)bytes,value)) return 1;
    ++G.info->io_unhandled;*value=0xffffffffu;return 1; /* absent hardware floats high */
}
static int output(void *unused,uint16_t port,unsigned bytes,uint32_t value)
{
    (void)unused;
    if(w98_ata_out(&ata,port,bytes,value) || dev_pio_out(port,(int)bytes,value)) return 1;
    if(port==0x402) {uart_tx((uint8_t)value);return 1;} /* SeaBIOS genuine debug output */
    ++G.info->io_unhandled;return 1; /* no device consumes an absent port write */
}
static void handle_io(domain_t *d)
{
    uint64_t q=vmread(VMCS_EXIT_QUAL);unsigned bytes=(unsigned)(q&7)+1;
    const int in=(int)((q>>3)&1);uint16_t port=(uint16_t)(q>>16);uint32_t value;
    ++G.info->io_exits;
    if(bytes!=1 && bytes!=2 && bytes!=4) {dom_fail(d,"invalid Win98 port width");return;}
    if(q&0x10) {
        uint64_t instruction=vmread(VMCS_EXIT_INSTR_INFO),flags=vmread(VMCS_GUEST_RFLAGS);
        const unsigned address=(unsigned)((instruction>>7)&7),segment=in?0:(unsigned)((instruction>>15)&7);
        const unsigned reg=in?GPR_RDI:GPR_RSI;
        w98_memory_t memory={d,physical,(uint32_t)vmread(VMCS_GUEST_CR0),(uint32_t)vmread(VMCS_GUEST_CR3),(uint32_t)vmread(VMCS_GUEST_CR4),(unsigned)(vmread(VMCS_GUEST_CS_SEL)&3)};
        w98_string_io_t s;w98_io_fault_t f;const w98_ports_t ports={d,input,output};int rc;
        if(address>1 || segment>5) {dom_fail(d,"unsupported Win98 string addressing");return;}
        if(flags&0x20000) memory.cpl=3;
        memset(&s,0,sizeof s);s.index=d->vc.gpr[reg];s.count=d->vc.gpr[GPR_RCX];
        s.segment_base=(uint32_t)vmread(VMCS_GUEST_ES_BASE+segment*2);
        s.segment_limit=(uint32_t)vmread(VMCS_GUEST_ES_LIMIT+segment*2);
        s.segment_ar=(uint32_t)vmread(VMCS_GUEST_ES_AR+segment*2);
        s.address_bits=address==0?16:32;s.width=bytes;s.input=(unsigned)in;s.repeat=(unsigned)((q>>5)&1);
        s.direction_down=(unsigned)((flags>>10)&1);s.alignment_check=memory.cpl==3 && (memory.cr0&0x40000) && (flags&0x40000);s.segment_is_ss=segment==2;s.port=port;
        rc=w98_string_pio(&memory,&s,&ports,&f,64);
        d->vc.gpr[reg]=s.index;d->vc.gpr[GPR_RCX]=s.count;
        if(rc==0) dom_advance_rip();
        else if(rc==-1) {
            if(f.vector==14) d->guest_cr2=f.linear;
            vmx_inject_exception((uint8_t)f.vector,1,f.error);
        } else if(rc<0) dom_fail(d,"unimplemented Win98 string mapping/port %x rc=%d",port,rc);
        return; /* bounded progress keeps RIP on REP and reschedules genuine remaining elements */
    }
    if(in) {
        input(d,port,bytes,&value);
        if(bytes==1) d->vc.gpr[GPR_RAX]=(d->vc.gpr[GPR_RAX]&~0xffull)|(value&0xff);
        else if(bytes==2) d->vc.gpr[GPR_RAX]=(d->vc.gpr[GPR_RAX]&~0xffffull)|(value&0xffff);
        else d->vc.gpr[GPR_RAX]=value;
    } else output(d,port,bytes,(uint32_t)d->vc.gpr[GPR_RAX]);
    dom_advance_rip();
}
int win98_handle_exit(domain_t *d,uint32_t reason)
{
    if(reason==EXIT_IO) {handle_io(d);return 1;}
    if(reason==EXIT_HLT) {
        dom_advance_rip();
        if(!(vmread(VMCS_GUEST_RFLAGS)&0x200)) dom_fail(d,"Win98 halted with interrupts disabled");
        else d->state=SHZ_DS_WAITING;
        return 1;
    }
    return 0;
}
int win98_ready(domain_t *d,uint64_t now)
{
    dev_poll(now);
    return dev_irq_pending() || (d->doorbell_vector && d->doorbell_pending && !d->doorbell_signaled);
}
void win98_housekeeping(void)
{
    if(!w98 || w98->state==SHZ_DS_FAILED || w98->state==SHZ_DS_EXITED) return;
    if(dev_a20_dirty) {
        uint64_t gpa;dev_a20_dirty=0;
        for(gpa=0x100000;gpa<w98->ram_size;gpa+=4096) if(gpa&0x100000) {
            const uint64_t physical=w98->ram_base+(dev_a20_get()?gpa:gpa&~0x100000ull);
            if(ept_remap_page(&w98->ept,gpa,physical,EPT_RWX|EPT_WB)) {dom_fail(w98,"Win98 A20 EPT update failed");return;}
        }
        ept_invalidate();
    }
    if(rdtsc()-last_render>G.tsc_hz/20) {last_render=rdtsc();video_render();}
}
