/* SPDX-License-Identifier: GPL-2.0-only
 * Native Kernel64 component workload: actual AP entry and two-sided concurrent
 * progress. It deliberately does not run the current UP scheduler on APs.
 */
#include "../kernel64/k64.h"
#include "../kernel64/smp_boot.h"
#include "../kernel64/pci.h"
#include "../kcommon/standalone_dev.h"
#include "k64_smp_firmware.h"
static shz_bootinfo_t boot;
int initrd_files=-1;
int k64_boot_framebuffer(k64_boot_fb_t *out) { (void)out; return -1; }
const char *k64_boot_cmdline(void) { return boot.cmdline; }
static volatile uint32_t release,bsp_progress,suppress_ipis,ipi_turn;
static struct shz_smp_test_firmware firmware;
static unsigned unavailable_reads;
static int firmware_read(void *ctx,uint64_t pa,void *dst,size_t len)
{
    unsigned i; (void)ctx;
    if(pa>UINT64_MAX-len || pa+len>(64ull<<30)) return -1;
    for(i=0;i<firmware.count;i++) {
        const uint64_t base=firmware.range[i].base,size=firmware.range[i].size;
        if(pa>=base && pa-base<=size && len<=size-(pa-base)) {
            const void *mapped=pa<=mem_ram_top() && len<=mem_ram_top()-pa ?
                (const void *)p2v(pa) : mmio_map(pa,len);
            if(!mapped) return -1;
            memcpy(dst,mapped,len); return 0;
        }
    }
    if(unavailable_reads++<4)
        kprintf("SMP-FIRMWARE: unavailable pa=%llx size=%llu ranges=%u\n",pa,(uint64_t)len,firmware.count);
    return -1;
}
static struct {
    uint32_t progress,checkpoint,barrier_bad,done,ping_done,result,overlap,cpu,physical_apic,resched_ipis,tlb_ipis,send_bad;
    uint64_t cr3,stack,ipi_stack;
} jobs[SHZ_SMP_MAX_CPUS];
/* Test-private GDT/TSS/IDT proves IRQ delivery uses each allocated private
 * stack. The existing production UP arch state is never entered on APs. The
 * integration owner still has to connect its real per-CPU arch/scheduler. */
struct __attribute__((packed)) probe_dtr { uint16_t limit; uint64_t base; };
struct __attribute__((packed)) probe_gate { uint16_t lo,sel; uint8_t ist,type; uint16_t mid; uint32_t hi,zero; };
struct __attribute__((packed)) probe_tss {
    uint32_t reserved0; uint64_t rsp[3],reserved1,ist[7],reserved2;
    uint16_t reserved3,iomap;
};
struct probe_iret_frame { uint64_t rip,cs,flags,rsp,ss; };
static uint64_t probe_gdt[SHZ_SMP_MAX_CPUS][7];
static struct probe_tss probe_tss[SHZ_SMP_MAX_CPUS];
static struct probe_gate probe_idt[SHZ_SMP_MAX_CPUS][256];
extern void load_gdt(void *,uint16_t);
extern void load_idt(void *);
static void ipi_record(int tlb)
{
    const unsigned cpu=shz_smp_this_cpu();
    uint64_t local=0;
    if(cpu<SHZ_SMP_MAX_CPUS) {
        jobs[cpu].ipi_stack=(uint64_t)&local;
        if(tlb) __atomic_add_fetch(&jobs[cpu].tlb_ipis,1,__ATOMIC_RELEASE);
        else __atomic_add_fetch(&jobs[cpu].resched_ipis,1,__ATOMIC_RELEASE);
    }
    shz_smp_apic_eoi();
}
static void __attribute__((interrupt)) ipi_resched(struct probe_iret_frame *frame)
{ (void)frame; ipi_record(0); }
static void __attribute__((interrupt)) ipi_tlb(struct probe_iret_frame *frame)
{ (void)frame; ipi_record(1); }
static void __attribute__((interrupt)) ipi_spurious(struct probe_iret_frame *frame)
{ (void)frame; }
static void gate(unsigned cpu,unsigned vector,uint64_t entry,unsigned ist)
{
    struct probe_gate *g=&probe_idt[cpu][vector];
    g->lo=(uint16_t)entry; g->mid=(uint16_t)(entry>>16); g->hi=(uint32_t)(entry>>32);
    g->sel=0x08; g->ist=(uint8_t)ist; g->type=0x8e; g->zero=0;
}
static void private_arch(unsigned cpu)
{
    struct probe_tss *t=&probe_tss[cpu];
    const uint64_t base=(uint64_t)t;
    struct probe_dtr gdtr={sizeof probe_gdt[cpu]-1,(uint64_t)probe_gdt[cpu]};
    struct probe_dtr idtr={sizeof probe_idt[cpu]-1,(uint64_t)probe_idt[cpu]};
    t->iomap=sizeof *t; t->rsp[0]=shz_smp_cpus[cpu].boot_stack_top;
    t->ist[0]=shz_smp_cpus[cpu].irq_stack_top; t->ist[1]=shz_smp_cpus[cpu].df_stack_top;
    probe_gdt[cpu][1]=0x00af9b000000ffffull; probe_gdt[cpu][2]=0x00cf93000000ffffull;
    probe_gdt[cpu][5]=(sizeof *t-1)|((base&0xffffffull)<<16)|(0x89ull<<40)|(((base>>24)&0xff)<<56);
    probe_gdt[cpu][6]=base>>32;
    gate(cpu,SHZ_SMP_VEC_RESCHEDULE,(uint64_t)ipi_resched,1);
    gate(cpu,SHZ_SMP_VEC_TLB,(uint64_t)ipi_tlb,1);
    gate(cpu,SHZ_SMP_VEC_SPURIOUS,(uint64_t)ipi_spurious,0);
    load_gdt(&gdtr,0x28); load_idt(&idtr);
}
static int option(const char *wanted)
{
    const char *p=boot.cmdline; const size_t n=strlen(wanted);
    while(*p) {
        while(*p==' ') ++p;
        if(!strncmp(p,wanted,n) && (!p[n] || p[n]==' ')) return 1;
        while(*p && *p!=' ') ++p;
    }
    return 0;
}
static unsigned physical_apic(void)
{
    uint32_t a=1,b,c,d;
    __asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));
    return b>>24;
}
static uint32_t hash(unsigned cpu,unsigned loops,int bsp)
{
    uint32_t v=0x5a17c0deu^cpu,first=0; unsigned i;
    for(i=0;i<loops;i++) {
        v=(v<<5)|(v>>27); v^=0x9e3779b9u; v+=i;
        if(!(i&0x3fff)) {
            if(bsp) __atomic_add_fetch(&bsp_progress,1,__ATOMIC_RELEASE);
            else __atomic_add_fetch(&jobs[cpu].progress,1,__ATOMIC_RELEASE);
        }
        if(!bsp && i==500000) {
            unsigned guard=0;
            first=__atomic_load_n(&bsp_progress,__ATOMIC_ACQUIRE);
            __atomic_store_n(&jobs[cpu].checkpoint,1,__ATOMIC_RELEASE);
            while(__atomic_load_n(&bsp_progress,__ATOMIC_ACQUIRE)<=first && ++guard<100000000u)
                __asm__ volatile("pause");
            if(guard==100000000u) jobs[cpu].barrier_bad=1;
        }
        if(!bsp && i==1500000) jobs[cpu].overlap=__atomic_load_n(&bsp_progress,__ATOMIC_ACQUIRE)>first && first>0 && !jobs[cpu].barrier_bad;
    }
    return v;
}
static void ap(unsigned cpu)
{
    uint64_t canary=0x534d50415053544bull^cpu;
    jobs[cpu].cpu=shz_smp_this_cpu(); jobs[cpu].physical_apic=physical_apic();
    jobs[cpu].cr3=read_cr3(); jobs[cpu].stack=(uint64_t)&canary;
    private_arch(cpu);
    if(shz_smp_cpu_online(cpu)) for(;;) __asm__ volatile("cli; hlt");
    if(option("smp-return-ap")) return; /* Actual negative control after ONLINE. */
    while(!__atomic_load_n(&release,__ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    unsigned guard=0;
    while(!__atomic_load_n(&bsp_progress,__ATOMIC_ACQUIRE) && ++guard<100000000u) __asm__ volatile("pause");
    if(guard==100000000u) jobs[cpu].barrier_bad=1;
    sti();
    jobs[cpu].result=hash(cpu,2000000,0);
    if(canary!=(0x534d50415053544bull^cpu)) jobs[cpu].overlap=0;
    __atomic_store_n(&jobs[cpu].done,1,__ATOMIC_RELEASE);
    if(!suppress_ipis) {
        /* Fixed IPIs may coalesce in IRR. BSP admits one AP ping at a time
         * and waits for both vector acknowledgements before advancing. */
        while(__atomic_load_n(&ipi_turn,__ATOMIC_ACQUIRE)!=cpu) __asm__ volatile("pause");
        jobs[cpu].send_bad+=shz_smp_send_ipi(0,SHZ_SMP_VEC_RESCHEDULE)!=0;
        jobs[cpu].send_bad+=shz_smp_send_ipi(0,SHZ_SMP_VEC_TLB)!=0;
        __atomic_store_n(&jobs[cpu].ping_done,1,__ATOMIC_RELEASE);
    }
    for(;;) __asm__ volatile("sti; hlt");
}
void kmain(uint64_t bi_pa)
{
    const shz_bootinfo_t *bi=(const shz_bootinfo_t *)(K64_VIRT_BASE+bi_pa);
    unsigned n,i,seen=0; uint32_t first[SHZ_SMP_MAX_CPUS]={0},checkpoints[SHZ_SMP_MAX_CPUS]={0},observed=0;
    uint64_t guard=0;
    const uint64_t initial_cr3=read_cr3();
    memcpy(&boot,bi,sizeof boot); arch_init(); mem_init(&boot);
    memcpy(&firmware,(const void *)p2v(SHZ_SMP_TEST_FIRMWARE_PA),sizeof firmware);
    if(firmware.magic!=SHZ_SMP_TEST_FIRMWARE_MAGIC || firmware.count>32) sa_exit(5);
    for(i=0;i<firmware.count;i++)
        kprintf("SMP-FIRMWARE: base=%llx size=%llx type=%u\n",firmware.range[i].base,firmware.range[i].size,firmware.range[i].type);
    kprintf("SMP-COMPONENT: Kernel64 native AP bootstrap; scheduler integration not exercised\n");
    k_outb(0x21,0xff); k_outb(0xa1,0xff);
    const int invalid_initial=shz_smp_boot_start_with_reader(0,ap,firmware_read,0,0x2000);
    const uint64_t foreign_cr3=pmm_alloc();
    if(!foreign_cr3) sa_exit(5);
    memcpy((void *)p2v(foreign_cr3),(const void *)p2v(kernel_pml4()),PAGE_SIZE);
    write_cr3(foreign_cr3);
    const int invalid_active=shz_smp_boot_start_with_reader(0,ap,firmware_read,0,initial_cr3);
    write_cr3(kernel_pml4()); pmm_free(foreign_cr3);
    sti();
    const int invalid_if=shz_smp_boot_start_with_reader(0,ap,firmware_read,0,initial_cr3);
    cli();
    kprintf("SMP-ADMISSION: initial=%llx final=%llx wrong-initial=%d wrong-active=%d IF-on=%d\n",
            initial_cr3,kernel_pml4(),invalid_initial,invalid_active,invalid_if);
    if(invalid_initial!=-2 || invalid_active!=-2 || invalid_if!=-2 || shz_smp_topology()->count) sa_exit(5);
    const int rc=shz_smp_boot_start_with_reader(0,ap,firmware_read,0,initial_cr3);
    if(option("smp-return-ap")) {
        guard=0;
        while(__atomic_load_n(&shz_smp_cpus[1].state,__ATOMIC_ACQUIRE)!=SHZ_SMP_CPU_FAILED && ++guard<100000000ull)
            __asm__ volatile("pause");
        const unsigned failed=__atomic_load_n(&shz_smp_cpus[1].state,__ATOMIC_ACQUIRE)==SHZ_SMP_CPU_FAILED;
        const unsigned online=shz_smp_online_count();
        const int retained=shz_smp_cpus[1].boot_stack_top!=0 && shz_smp_cpus[1].irq_stack_top!=0 &&
            shz_smp_cpus[1].df_stack_top!=0 && jobs[1].cr3==kernel_pml4() &&
            jobs[1].stack<shz_smp_cpus[1].boot_stack_top && jobs[1].stack>=shz_smp_cpus[1].boot_stack_top-KSTACK_BYTES;
        const int rejected=shz_smp_send_ipi(1,SHZ_SMP_VEC_RESCHEDULE);
        const int retry=shz_smp_boot_start_with_reader(0,ap,firmware_read,0,initial_cr3);
        const int bootinfo_ok=!memcmp(&boot,(const void *)p2v(bi_pa),sizeof boot);
        kprintf("SMP-RETURN-CONTROL: started=%d failed=%u online=%u cpu=%u physical=%u retained=%u rejected=%d retry=%d bootinfo=%u\n",
                rc,failed,online,jobs[1].cpu,jobs[1].physical_apic,retained,rejected,retry,bootinfo_ok);
        const int expected=(rc==2 || rc==-7) && failed && online==1 && jobs[1].cpu==1 && jobs[1].physical_apic==1 &&
                           retained && rejected==-1 && retry==-2 && bootinfo_ok;
        sa_exit(expected?6:7);
    }
    if(rc<0) { kprintf("SMP-COMPONENT: startup failed rc=%d\n",rc); sa_exit(2); }
    n=shz_smp_topology()->count;
    const int repeated=shz_smp_boot_start_with_reader(0,ap,firmware_read,0,initial_cr3);
    const uint64_t bootstrap=*(const volatile uint32_t *)p2v(SHZ_SMP_TRAMPOLINE_PA+0x800);
    const uint64_t *root=(const uint64_t *)p2v(bootstrap);
    const uint64_t *pdpt=(const uint64_t *)p2v(root[0]&0x000ffffffffff000ull);
    const uint64_t *pd=(const uint64_t *)p2v(pdpt[0]&0x000ffffffffff000ull);
    const uint64_t *pt=(const uint64_t *)p2v(pd[0]&0x000ffffffffff000ull);
    unsigned low_pages=0,low_bad=0;
    for(i=0;i<512;i++) low_pages+=(pt[i]&1)!=0;
    /* The bootstrap has a distinct root and only its one retired boot page
     * identity-mapped. High-half kernel entries are the final ones. */
    for(i=1;i<256;i++) low_bad+=root[i]!=0;
    for(i=1;i<512;i++) low_bad+=(pdpt[i]!=0)+(pd[i]!=0);
    low_bad+=(pd[0]&0x80)!=0;
    low_bad+=(pt[SHZ_SMP_TRAMPOLINE_PA/PAGE_SIZE]&0x000ffffffffff000ull)!=SHZ_SMP_TRAMPOLINE_PA;
    for(i=256;i<512;i++) low_bad+=(root[i]&~0x20ull)!=(((const uint64_t *)p2v(kernel_pml4()))[i]&~0x20ull);
    const int bootinfo_ok=!memcmp(&boot,(const void *)p2v(bi_pa),sizeof boot);
    kprintf("SMP-BOOT-PAGES: retired=%x initial=%llx active=%llx bootstrap=%llx low-pages=%u bad=%u retry=%d bootinfo=%u\n",
            SHZ_SMP_TRAMPOLINE_PA,initial_cr3,read_cr3(),bootstrap,low_pages,low_bad,repeated,bootinfo_ok);
    if(repeated!=-2 || bootstrap==initial_cr3 || bootstrap==kernel_pml4() || low_pages!=1 || low_bad || !bootinfo_ok) sa_exit(5);
    while(shz_smp_online_count()!=n && ++guard<100000000ull) __asm__ volatile("pause");
    if(!n || n>SHZ_SMP_MAX_CPUS || shz_smp_online_count()!=n) { kprintf("SMP-COMPONENT: online mismatch\n"); sa_exit(3); }
    private_arch(0);
    k_outb(0x21,0xff); k_outb(0xa1,0xff); /* no legacy device IRQs in this AP-only probe */
    suppress_ipis=option("smp-no-ipi");
    sti();
    __atomic_store_n(&release,1,__ATOMIC_RELEASE);
    /* Work and observe AP progress on the BSP rather than waiting passively. */
    uint32_t v=0x5a17c0deu; unsigned barrier_bad=0;
    for(i=0;i<16000000;i++) {
        unsigned c;
        v=(v<<5)|(v>>27); v^=0x9e3779b9u; v+=i;
        if(!(i&0x3fff)) {
            __atomic_add_fetch(&bsp_progress,1,__ATOMIC_RELEASE);
            for(c=1;c<n;c++) {
                const uint32_t p=__atomic_load_n(&jobs[c].progress,__ATOMIC_ACQUIRE);
                if(first[c] && p>first[c]) observed|=1u<<c;
                if(p) first[c]=p;
            }
        }
        /* Rendezvous within the independent hash workloads keeps evidence
         * valid when the host deschedules one vCPU. Progress counters advance
         * only for actual completed hash iterations, never waiting spins. */
        if(i==500000) {
            unsigned c;
            for(c=1;c<n;c++) {
                guard=0;
                while(!__atomic_load_n(&jobs[c].checkpoint,__ATOMIC_ACQUIRE) && ++guard<100000000ull)
                    __asm__ volatile("pause");
                barrier_bad+=guard==100000000ull;
                checkpoints[c]=__atomic_load_n(&jobs[c].progress,__ATOMIC_ACQUIRE);
            }
        }
        if(i==2000000) {
            unsigned c;
            for(c=1;c<n;c++) {
                guard=0;
                while(__atomic_load_n(&jobs[c].progress,__ATOMIC_ACQUIRE)<=checkpoints[c] && ++guard<100000000ull)
                    __asm__ volatile("pause");
                if(guard==100000000ull) ++barrier_bad;
                else observed|=1u<<c;
            }
        }
    }
    jobs[0].result=v; jobs[0].cpu=shz_smp_this_cpu(); jobs[0].physical_apic=physical_apic();
    jobs[0].cr3=read_cr3(); jobs[0].stack=(uint64_t)&guard; jobs[0].progress=bsp_progress;
    const int ipi_control=suppress_ipis!=0;
    unsigned ipi_bad=0;
    if(!ipi_control) {
        ipi_bad+=shz_smp_send_ipi(0,SHZ_SMP_VEC_RESCHEDULE)!=0;
        ipi_bad+=shz_smp_send_ipi(0,SHZ_SMP_VEC_TLB)!=0;
        guard=0;
        while((__atomic_load_n(&jobs[0].resched_ipis,__ATOMIC_ACQUIRE)!=1 ||
               __atomic_load_n(&jobs[0].tlb_ipis,__ATOMIC_ACQUIRE)!=1) && ++guard<100000000ull)
            __asm__ volatile("pause");
        ipi_bad+=guard==100000000ull;
        for(i=1;i<n;i++) {
            ipi_bad+=shz_smp_send_ipi(i,SHZ_SMP_VEC_RESCHEDULE)!=0;
            ipi_bad+=shz_smp_send_ipi(i,SHZ_SMP_VEC_TLB)!=0;
            guard=0;
            while((__atomic_load_n(&jobs[i].resched_ipis,__ATOMIC_ACQUIRE)!=1 ||
                   __atomic_load_n(&jobs[i].tlb_ipis,__ATOMIC_ACQUIRE)!=1) && ++guard<100000000ull)
                __asm__ volatile("pause");
            ipi_bad+=guard==100000000ull;
            __atomic_store_n(&ipi_turn,i,__ATOMIC_RELEASE);
            guard=0;
            while((__atomic_load_n(&jobs[0].resched_ipis,__ATOMIC_ACQUIRE)!=i+1 ||
                   __atomic_load_n(&jobs[0].tlb_ipis,__ATOMIC_ACQUIRE)!=i+1 ||
                   !__atomic_load_n(&jobs[i].ping_done,__ATOMIC_ACQUIRE)) && ++guard<100000000ull)
                __asm__ volatile("pause");
            ipi_bad+=guard==100000000ull;
        }
    }
    ipi_bad+=shz_smp_send_ipi(SHZ_SMP_MAX_CPUS,SHZ_SMP_VEC_RESCHEDULE)!=-1;
    ipi_bad+=shz_smp_send_ipi(0,0x2f)!=-1;
    ipi_bad+=shz_smp_send_ipi(0,0xff)!=-1;
    guard=0;
    for(;;) {
        seen=0; for(i=1;i<n;i++) seen+=__atomic_load_n(&jobs[i].done,__ATOMIC_ACQUIRE)!=0;
        unsigned received=0;
        for(i=0;i<n;i++) received+=__atomic_load_n(&jobs[i].resched_ipis,__ATOMIC_ACQUIRE)==(i?1:n) &&
                                   __atomic_load_n(&jobs[i].tlb_ipis,__ATOMIC_ACQUIRE)==(i?1:n);
        if((seen==n-1 && (received==n || ipi_control)) || ++guard==100000000ull) break;
        __asm__ volatile("pause");
    }
    unsigned bad=(seen!=n-1)+ipi_bad+barrier_bad;
    for(i=0;i<n;i++) {
        kprintf("SMP-CPU: slot=%u apic=%u actual=%u physical=%u cr3=%llx stack=%llx hash=%x progress=%u overlap=%u observed=%u\n",
                i,shz_smp_cpus[i].apic_id,jobs[i].cpu,jobs[i].physical_apic,jobs[i].cr3,jobs[i].stack,jobs[i].result,
                jobs[i].progress,jobs[i].overlap,(observed>>i)&1);
        if(jobs[i].cpu!=i || jobs[i].physical_apic!=shz_smp_cpus[i].apic_id || jobs[i].cr3!=kernel_pml4()) ++bad;
        if(i && (!jobs[i].overlap || !((observed>>i)&1) ||
           jobs[i].stack>=shz_smp_cpus[i].boot_stack_top ||
           jobs[i].stack<shz_smp_cpus[i].boot_stack_top-KSTACK_BYTES)) ++bad;
        kprintf("SMP-IPI: slot=%u resched=%u tlb=%u irqstack=%llx\n",i,jobs[i].resched_ipis,jobs[i].tlb_ipis,jobs[i].ipi_stack);
        if(jobs[i].resched_ipis!=(i?1:n) || jobs[i].tlb_ipis!=(i?1:n) || jobs[i].send_bad ||
           jobs[i].ipi_stack>=shz_smp_cpus[i].irq_stack_top ||
           jobs[i].ipi_stack<shz_smp_cpus[i].irq_stack_top-KSTACK_BYTES) ++bad;
    }
    cli();
    kprintf("SMP-COMPONENT: CPUs=%u completed=%u bad=%u\n",n,seen,bad);
    sa_exit(bad?4:0);
}
