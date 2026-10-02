/* SPDX-License-Identifier: GPL-2.0-only
 * Supervisor host environment: GDT/IDT/TSS, exception reporting and identity
 * paging. Everything the firmware left behind (its GDT, IDT and page tables) is
 * replaced before any VMX state is built from the host registers.
 */
#include "platform.h"
#include "console.h"
#include "cpu.h"
#include "../include/ap_boot.h"

#define MAX_GIB 64
#define PTE_P 1ull
#define PTE_RW 2ull
#define PTE_PWT 8ull
#define PTE_PCD 16ull
#define PTE_PS 0x80ull

/* Boot stack: first object in .bss so the linker script can name its top. */
uint8_t sup_stack[65536] __attribute__((section(".bss.stack"), aligned(4096)));

static uint64_t gdt[8] __attribute__((aligned(16)));
struct __attribute__((packed)) host_tss {
    uint32_t reserved0;
    uint64_t rsp[3];
    uint64_t reserved1;
    uint64_t ist[7];
    uint64_t reserved2;
    uint16_t reserved3, iopb;
};
static struct host_tss tss __attribute__((aligned(16)));

struct __attribute__((packed)) idt_gate {
    uint16_t off0, sel;
    uint8_t ist, type;
    uint16_t off1;
    uint32_t off2, zero;
};
static struct idt_gate idt[256] __attribute__((aligned(16)));

static uint64_t pml4[512] __attribute__((aligned(4096)));
static uint64_t pdpt[512] __attribute__((aligned(4096)));
static uint64_t pd[MAX_GIB][512] __attribute__((aligned(4096)));
static uint8_t window_is_ram[MAX_GIB * 512 / 8];
static uint64_t vga_low_pt[512] __attribute__((aligned(4096)));
static uint64_t vga_lfb_pt[8][512] __attribute__((aligned(4096)));
static uint64_t vga_lfb_binding,vga_pat_binding;

static shz_info_t *g_info;
/* Private roots share only the immutable identity hierarchy built on the BSP.
 * This component never mutates mappings once AP initialization starts. */
static struct ap_platform {
    uint64_t root[512] __attribute__((aligned(4096)));
    uint8_t stack[SHZ_AP_STACK_BYTES] __attribute__((aligned(4096)));
    uint64_t gdt[8] __attribute__((aligned(16)));
    struct host_tss tss __attribute__((aligned(16)));
    struct idt_gate idt[256] __attribute__((aligned(16)));
    unsigned ready;
} ap_platform[SHZ_SMP_MAX_CPUS] __attribute__((aligned(4096)));

uint64_t platform_gdt_base(void) { return (uint64_t)(uintptr_t)gdt; }
uint64_t platform_idt_base(void) { return (uint64_t)(uintptr_t)idt; }
uint64_t platform_tss_base(void) { return (uint64_t)(uintptr_t)&tss; }

void platform_fail(shz_info_t *info, const char *message)
{
    info->stage = SHZ_STAGE_FAILED;
    log_capture(info->last_error, sizeof info->last_error, "%s", message);
    kprintf("SHZ: FATAL %s\n", message);
    for (;;) {
        cli();
        hlt();
    }
}

struct exc_frame {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rbp, rbx, rdx, rcx, rax;
    uint64_t vector, error, rip, cs, rflags, rsp, ss;
};

void sup_exception(struct exc_frame *f)
{
    if (g_info) {
        g_info->stage = SHZ_STAGE_FAILED;
        log_capture(g_info->last_error, sizeof g_info->last_error,
                    "host exception %d err=%llx rip=%llx cr2=%llx", (int)f->vector,
                    f->error, f->rip, read_cr2());
    }
    kprintf("SHZ: HOST EXCEPTION vec=%d err=%llx rip=%llx cs=%llx rflags=%llx rsp=%llx cr2=%llx\n",
            (int)f->vector, f->error, f->rip, f->cs, f->rflags, f->rsp, read_cr2());
    kprintf("SHZ: rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx\n", f->rax, f->rbx,
            f->rcx, f->rdx, f->rsi, f->rdi);
}

static void mark_ram(uint64_t start, uint64_t end)
{
    uint64_t w;
    if (end <= start)
        return;
    for (w = start >> 21; w <= (end - 1) >> 21 && w < MAX_GIB * 512ull; ++w)
        window_is_ram[w >> 3] |= (uint8_t)(1u << (w & 7));
}

/* Physical range 0..top is identity mapped with 2 MiB pages. Windows that hold
 * RAM (per the retained UEFI memory map) are write-back; everything else,
 * including the framebuffer, LAPIC and PCI windows, is uncached. */
static uint64_t build_paging(shz_info_t *info)
{
    uint64_t top = 4ull << 30, gib, i, addr;
    const uint8_t *map = (const uint8_t *)(uintptr_t)info->memmap_base;
    uint64_t off;
    vga_lfb_binding=0;vga_pat_binding=0;

    for (off = 0; off + info->memmap_desc_size <= info->memmap_bytes; off += info->memmap_desc_size) {
        const uint32_t type = *(const uint32_t *)(map + off);
        const uint64_t phys = *(const uint64_t *)(map + off + 8);
        const uint64_t pages = *(const uint64_t *)(map + off + 24);
        const uint64_t end = phys + pages * 4096;
        const int ramish = (type >= 1 && type <= 7) || type == 9 || type == 10 || type == 14;
        if (ramish) {
            mark_ram(phys, end);
            if (end > top)
                top = end;
        }
    }
    /* Always keep the loader-owned regions cached and mapped. */
    mark_ram(info->region_base, info->region_base + info->region_size);
    mark_ram(info->guest_ram_base, info->guest_ram_base + info->guest_ram_size);
    mark_ram(info->disk_base, info->disk_base + info->disk_size);
    if (top > (uint64_t)MAX_GIB << 30)
        top = (uint64_t)MAX_GIB << 30;
    gib = (top + (1ull << 30) - 1) >> 30;

    memset(pml4, 0, sizeof pml4);
    memset(pdpt, 0, sizeof pdpt);
    pml4[0] = (uint64_t)(uintptr_t)pdpt | PTE_P | PTE_RW;
    for (i = 0; i < gib; ++i) {
        pdpt[i] = (uint64_t)(uintptr_t)pd[i] | PTE_P | PTE_RW;
        for (addr = 0; addr < 512; ++addr) {
            const uint64_t phys = (i << 30) | (addr << 21);
            const uint64_t w = phys >> 21;
            uint64_t e = phys | PTE_P | PTE_RW | PTE_PS;
            if (!(window_is_ram[w >> 3] & (1u << (w & 7))))
                e |= PTE_PCD | PTE_PWT;
            pd[i][addr] = e;
        }
    }
    return gib;
}

int platform_vga_uc(uint64_t base,uint64_t bytes)
{
    uint64_t pat,uc_flags=0;unsigned slot;
    if(bytes!=(16u<<20) || base<(128u<<20) || base>0x100000000ull-bytes ||
       (base&(bytes-1)) || read_cr3()!=(uintptr_t)pml4)return -1;
    pat=rdmsr(MSR_IA32_PAT);
    for(slot=0;slot<8;++slot)if(((pat>>(slot*8))&255)==0)break;
    if(slot==8)return -1; /* UC-minus is not substituted for UC. */
    if(vga_lfb_binding)return vga_lfb_binding==base && vga_pat_binding==pat?0:-1;
    /* Validate all nine identity large leaves before modifying any table. */
    for(unsigned n=0;n<9;++n){uint64_t address=n?base+((uint64_t)(n-1)<<21):0;
        uint64_t entry=pd[address>>30][(address>>21)&511];
        if((entry&(PTE_P|PTE_RW|PTE_PS))!=(PTE_P|PTE_RW|PTE_PS) ||
           (entry&0x000fffffffe00000ull)!=address)return -1;}
    uc_flags=(slot&1?PTE_PWT:0)|(slot&2?PTE_PCD:0)|(slot&4?0x80ull:0);
    uint64_t old=pd[0][0],attributes=(old&~0x000ffffffffff000ull)&~PTE_PS;
    if(old&0x1000)attributes|=0x80; /* large PAT bit12 becomes 4 KiB bit7 */
    for(unsigned n=0;n<512;++n)vga_low_pt[n]=((uint64_t)n<<12)|attributes;
    for(unsigned n=0xa0;n<0xc0;++n)vga_low_pt[n]=((uint64_t)n<<12)|PTE_P|PTE_RW|uc_flags;
    for(unsigned block=0;block<8;++block)for(unsigned n=0;n<512;++n)
        vga_lfb_pt[block][n]=(base+((uint64_t)block<<21)+((uint64_t)n<<12))|PTE_P|PTE_RW|uc_flags;
    pd[0][0]=(uintptr_t)vga_low_pt|PTE_P|PTE_RW;
    for(unsigned block=0;block<8;++block){uint64_t address=base+((uint64_t)block<<21);
        pd[address>>30][(address>>21)&511]=(uintptr_t)vga_lfb_pt[block]|PTE_P|PTE_RW;}
    vga_lfb_binding=base;vga_pat_binding=pat;
    write_cr3((uintptr_t)pml4);return 0;
}

void platform_init(shz_info_t *info)
{
    struct dtr gdtr, idtr;
    uint64_t tss_base = platform_tss_base(), gib, cr4, i;

    g_info = info;
    gdt[0] = 0;
    gdt[1] = 0x00af9b000000ffffull;     /* 0x08: 64-bit code, DPL0 */
    gdt[2] = 0x00cf93000000ffffull;     /* 0x10: data, DPL0 */
    memset(&tss, 0, sizeof tss);
    tss.iopb = sizeof tss;
    /* 0x18: 64-bit available TSS descriptor (16 bytes) */
    gdt[3] = (sizeof tss - 1) | ((tss_base & 0xffffffull) << 16) | (0x89ull << 40) |
             (((tss_base >> 24) & 0xff) << 56);
    gdt[4] = tss_base >> 32;

    for (i = 0; i < 256; ++i) {
        const uint64_t h = isr_table[i];
        idt[i].off0 = (uint16_t)h;
        idt[i].sel = HOST_CS;
        idt[i].ist = 0;
        idt[i].type = 0x8e;
        idt[i].off1 = (uint16_t)(h >> 16);
        idt[i].off2 = (uint32_t)(h >> 32);
        idt[i].zero = 0;
    }
    gdtr.limit = sizeof gdt - 1;
    gdtr.base = platform_gdt_base();
    idtr.limit = sizeof idt - 1;
    idtr.base = platform_idt_base();

    gib = build_paging(info);
    /* PGE/PCIDE off: a plain CR3 write flushes everything, no PCID hazards. */
    cr4 = read_cr4();
    cr4 &= ~((1ull << 17) | (1ull << 7));
    write_cr4(cr4);
    write_cr3((uint64_t)(uintptr_t)pml4);
    load_descriptor_tables(&gdtr, &idtr, HOST_TR);
    kprintf("SHZ: platform: own GDT/IDT/TSS, identity map %llu GiB (2 MiB pages)\n", gib);
}

int platform_ap_prepare(unsigned cpu,uint64_t *cr3,uint64_t *stack)
{
    if(!cpu || cpu>=SHZ_SMP_MAX_CPUS || !g_info || ap_platform[cpu].ready) return -1;
    struct ap_platform *p=&ap_platform[cpu];
    uint64_t base=(uint64_t)(uintptr_t)&p->tss;
    memcpy(p->root,pml4,sizeof p->root);
    p->gdt[1]=0x00af9b000000ffffull;
    p->gdt[2]=0x00cf93000000ffffull;
    p->tss.iopb=sizeof p->tss;
    p->tss.rsp[0]=(uint64_t)(uintptr_t)(p->stack+sizeof p->stack);
    p->gdt[3]=(sizeof p->tss-1)|((base&0xffffffull)<<16)|(0x89ull<<40)|(((base>>24)&255)<<56);
    p->gdt[4]=base>>32;
    memcpy(p->idt,idt,sizeof p->idt);
    *cr3=(uint64_t)(uintptr_t)p->root;
    *stack=(uint64_t)(uintptr_t)(p->stack+sizeof p->stack);
    if(*cr3>UINT32_MAX || (*cr3&4095)) return -1;
    p->ready=1;
    return 0;
}

int platform_apic_uncached(uint64_t pa)
{
    if(read_cr3()!=(uint64_t)(uintptr_t)pml4 || pa>UINT32_MAX) return 0;
    const uint64_t expected_pdpt=(uint64_t)(uintptr_t)pdpt;
    if((pml4[0]&~UINT64_C(0xfff))!=expected_pdpt || !(pml4[0]&PTE_P)) return 0;
    unsigned gib=(unsigned)(pa>>30);
    if((pdpt[gib]&~UINT64_C(0xfff))!=(uint64_t)(uintptr_t)pd[gib] || !(pdpt[gib]&PTE_P)) return 0;
    return shz_ap_lapic_pte_ok(pd[gib][(pa>>21)&511],pa);
}

int platform_ap_enter(unsigned cpu,uint64_t *gdt_base,uint64_t *idt_base,uint64_t *tss_base)
{
    if(!cpu || cpu>=SHZ_SMP_MAX_CPUS || !ap_platform[cpu].ready) return -1;
    struct ap_platform *p=&ap_platform[cpu];
    if(read_cr3()!=(uint64_t)(uintptr_t)p->root || (read_cr4()&((1ull<<17)|(1ull<<7)))) return -1;
    struct dtr gdtr={sizeof p->gdt-1,(uint64_t)(uintptr_t)p->gdt};
    struct dtr idtr={sizeof p->idt-1,(uint64_t)(uintptr_t)p->idt};
    load_descriptor_tables(&gdtr,&idtr,HOST_TR);
    *gdt_base=gdtr.base; *idt_base=idtr.base; *tss_base=(uint64_t)(uintptr_t)&p->tss;
    return 0;
}
