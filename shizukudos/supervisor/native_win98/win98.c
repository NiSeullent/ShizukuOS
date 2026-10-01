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
static uint8_t *absent_lapic;
#define W98_ABSENT_LAPIC_GPA 0xfee00000u
static uint64_t last_render;
/* Passive fixed ring: no control, register, memory or delivery writes. */
typedef struct {
    uint64_t sequence,rip,cs_base,cr0,cr3,rsp,qual,rax,rdx;
    uint32_t reason,intr,vectoring;
    uint16_t cs;
} w98_trace_t;
static w98_trace_t trace_ring[32];
static uint64_t trace_count;
static int trace_emitted;
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
    trace_count=0;trace_emitted=0;
    d->id=SHZ_DOM_WIN98;d->name="WIN98";d->kind=DK_WIN98;d->generation=1;
    d->ram_base=info->guest_ram_base;d->ram_size=info->guest_ram_size;
    d->fx[0]=0x7f;d->fx[1]=3;d->fx[24]=0x80;d->fx[25]=0x1f;
    ram=(uint8_t *)(uintptr_t)d->ram_base;memset(ram,0,d->ram_size);
    /* Our explicit no-PCI profile uses an always writable RAM shadow. Populate
     * the whole pinned 256 KiB image, not only the final ISA 128 KiB: genuine
     * SeaBIOS protected-mode callees also live below E0000. Its normal PCI/PAM
     * copy path cannot supply those bytes when no host bridge is emulated.
     * The high ROM alias stays read-only; this does not advertise PCI/PAM. */
    memcpy(ram+0x100000-rom->size,(const void *)(uintptr_t)rom->base,rom->size);
    /* SeaBIOS rel-1.17.0 src/fw/mptable.c reads LAPIC version unconditionally.
     * This explicit single-CPU profile has no LAPIC: only its exact 4 KiB bus
     * window floats high. It cannot consume writes, execute code or deliver IRQs;
     * CPUID APIC and APICBASE remain absent. All other unknown GPAs still fault. */
    absent_lapic=pool_alloc_pages(1);
    if(!absent_lapic) {
        log_capture(info->last_error,sizeof info->last_error,"Win98 absent-device page allocation failed");return -1;
    }
    memset(absent_lapic,0xff,4096);
    if(ept_init(&d->ept) || ept_map(&d->ept,0,d->ram_base,d->ram_size,EPT_RWX|EPT_WB,1) ||
       ept_map(&d->ept,0x100000000ull-rom->size,rom->base,rom->size,EPT_R|EPT_X|EPT_WB,1) ||
       ept_map(&d->ept,W98_ABSENT_LAPIC_GPA,(uintptr_t)absent_lapic,4096,EPT_R|EPT_UC,1)) {
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
    if(!bytes) return 0;
    if(!dev_a20_get()) gpa&=~0x100000u;
    if(gpa>=W98_ABSENT_LAPIC_GPA && gpa-W98_ABSENT_LAPIC_GPA<4096) {
        const unsigned offset=gpa-W98_ABSENT_LAPIC_GPA;
        if(write || !absent_lapic || bytes>4096-offset) return 0;
        return absent_lapic+offset;
    }
    if(gpa>=0x100000000ull-rom->size) {
        const uint64_t offset=gpa-(0x100000000ull-rom->size);
        if(write || bytes>rom->size-offset) return 0;
        return (uint8_t *)(uintptr_t)(rom->base+offset);
    }
    return dom_gpa_ptr(d,gpa,bytes);
}
static const uint8_t *trace_read(domain_t *d,uint64_t gpa,unsigned bytes)
{
    /* Check the complete 32-bit bus span before narrowing; never turn an
     * arbitrary GPA into a host pointer. physical() applies actual A20 state. */
    if(d!=w98 || !rom || !bytes || bytes>64 || gpa>0xffffffffull ||
       bytes>0x100000000ull-gpa || !d->ram_base ||
       d->ram_base>~0ull-d->ram_size || !rom->base ||
       rom->base>~0ull-rom->size) return 0;
    return physical(d,(uint32_t)gpa,bytes,0);
}
static void trace_memory(domain_t *d,const char *name,uint64_t linear,unsigned bytes)
{
    const uint8_t *p;
    /* Without paging, linear address equals GPA. Do not invent a translation
     * after the guest turns paging on: that observation is explicitly absent. */
    if(vmread(VMCS_GUEST_CR0)&0x80000000ull) {
        kprintf("W98TRACE %s linear=%llx paging-unsupported\n",name,linear);return;
    }
    p=trace_read(d,linear,bytes);
    if(!p) {kprintf("W98TRACE %s gpa=%llx unmapped bytes=%u\n",name,linear,bytes);return;}
    kprintf("W98TRACE %s gpa=%llx bytes=%u",name,linear,bytes);
    for(unsigned i=0;i<bytes;++i) kprintf(" %02x",(unsigned)p[i]);
    kprintf("\n");
}
void win98_observe_exit(domain_t *d,uint32_t reason)
{
    w98_trace_t *t;uint64_t start,base,limit,rip,rsp;
    if(d!=w98 || d->kind!=DK_WIN98 || trace_emitted) return;
    t=&trace_ring[trace_count%32];memset(t,0,sizeof *t);
    t->sequence=++trace_count;t->reason=reason;
    t->rip=vmread(VMCS_GUEST_RIP);t->cs=(uint16_t)vmread(VMCS_GUEST_CS_SEL);
    t->cs_base=vmread(VMCS_GUEST_CS_BASE);t->cr0=vmread(VMCS_GUEST_CR0);
    t->cr3=vmread(VMCS_GUEST_CR3);t->rsp=vmread(VMCS_GUEST_RSP);
    t->qual=vmread(VMCS_EXIT_QUAL);t->intr=(uint32_t)vmread(VMCS_EXIT_INTR_INFO);
    t->vectoring=(uint32_t)vmread(VMCS_IDT_VECTORING_INFO);
    t->rax=d->vc.gpr[GPR_RAX];t->rdx=d->vc.gpr[GPR_RDX];
    if(reason!=EXIT_TRIPLE_FAULT && reason!=EXIT_EPT_VIOLATION &&
       reason!=EXIT_EPT_MISCONFIG && reason!=EXIT_INVALID_GUEST_STATE &&
       reason!=EXIT_EXCEPTION_NMI) return;
    trace_emitted=1;
    kprintf("W98TRACE paused-VMCS reason=%u count=%llu guest-physical-bus=32 A20=%d\n",reason,trace_count,dev_a20_get());
    start=trace_count>32?trace_count-32:0;
    for(uint64_t n=start;n<trace_count;++n) {
        t=&trace_ring[n%32];
        kprintf("W98TRACE seq=%llu reason=%u rip=%llx cs=%x base=%llx cr0=%llx cr3=%llx rsp=%llx qual=%llx intr=%x vectoring=%x ax=%llx dx=%llx\n",
            t->sequence,t->reason,t->rip,(unsigned)t->cs,t->cs_base,t->cr0,t->cr3,t->rsp,t->qual,t->intr,t->vectoring,t->rax,t->rdx);
    }
    kprintf("W98TRACE cr4=%llx efer=%llx flags=%llx exit-intr-error=%llx vectoring-error=%llx gpa=%llx linear=%llx\n",
        vmread(VMCS_GUEST_CR4),vmread(VMCS_GUEST_EFER),vmread(VMCS_GUEST_RFLAGS),
        vmread(VMCS_EXIT_INTR_ERRCODE),vmread(VMCS_IDT_VECTORING_ERR),vmread(VMCS_GUEST_PHYS_ADDR),vmread(VMCS_GUEST_LINEAR_ADDR));
    for(unsigned i=0;i<6;++i)
        kprintf("W98TRACE seg=%u sel=%llx base=%llx limit=%llx ar=%llx\n",i,
            vmread(VMCS_GUEST_ES_SEL+2*i),vmread(VMCS_GUEST_ES_BASE+2*i),
            vmread(VMCS_GUEST_ES_LIMIT+2*i),vmread(VMCS_GUEST_ES_AR+2*i));
    for(unsigned i=0;i<GPR_COUNT;++i) kprintf("W98TRACE gpr=%u value=%llx\n",i,d->vc.gpr[i]);
    base=vmread(VMCS_GUEST_CS_BASE);rip=vmread(VMCS_GUEST_RIP);
    if(base<=~0ull-rip) trace_memory(d,"code",base+rip,64);
    else kprintf("W98TRACE code linear-overflow\n");
    base=vmread(VMCS_GUEST_SS_BASE);rsp=vmread(VMCS_GUEST_RSP);
    if(base<=~0ull-rsp) trace_memory(d,"stack",base+rsp,64);
    else kprintf("W98TRACE stack linear-overflow\n");
    base=vmread(VMCS_GUEST_GDTR_BASE);limit=vmread(VMCS_GUEST_GDTR_LIMIT);
    trace_memory(d,"gdt",base,(unsigned)(limit<63?limit+1:64));
    base=vmread(VMCS_GUEST_IDTR_BASE);limit=vmread(VMCS_GUEST_IDTR_LIMIT);
    trace_memory(d,"idt",base,(unsigned)(limit<63?limit+1:64));
    trace_memory(d,"shadow-start",0xe0000,64);
    trace_memory(d,"ROM-source",0xfffe0000,64);
}
static int input(void *unused,uint16_t port,unsigned bytes,uint32_t *value)
{
    (void)unused;
    /* Configured SeaBIOS debugcon has an 8-bit E9 presence signature. */
    if(port==0x402 && bytes==1) {*value=0xe9;return 1;}
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
