/* SPDX-License-Identifier: GPL-2.0-only
 * Execute actual mem.c + the actual physical-to-logical CPU provider. Only
 * privileged IRQ/CR3/TLB and the direct-map base are host hardware boundaries.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#define SHZ_STANDALONE 1
#include "../kernel64/k64.h"
#include "../kernel64/smp_boot.h"
static _Thread_local uint64_t host_flags=1ull<<9;
static uint64_t host_irq_save(void) { const uint64_t f=host_flags;host_flags&=~(1ull<<9);return f; }
static void host_irq_restore(uint64_t f) { host_flags=f; }
static void host_write_cr3(uint64_t pa) { (void)pa; }
static void host_invlpg(uint64_t va) { (void)va; }
static void host_evidence(unsigned kind,uint64_t value) { (void)kind;(void)value; }
#define irq_save host_irq_save
#define irq_restore host_irq_restore
#define write_cr3 host_write_cr3
#define invlpg host_invlpg
#define shz_evidence host_evidence
#undef K64_VIRT_BASE
#undef DIRECT_MAP
#define K64_VIRT_BASE 0x30000000ull
#define DIRECT_MAP K64_VIRT_BASE
#include "../kernel64/mem.c"
#include "../kernel64/smp_boot.c"

static _Thread_local unsigned checks;
static unsigned worker_checks;
static int expect_panic;
static sigjmp_buf panic_target;
void kprintf(const char *fmt,...) { (void)fmt; }
void kpanic(const char *fmt,...)
{
    if(expect_panic) siglongjmp(panic_target,1);
    va_list ap;va_start(ap,fmt);vfprintf(stderr,fmt,ap);va_end(ap);fputc('\n',stderr);_Exit(4);
}
#define CHECK(x) do { ++checks;if(!(x)){fprintf(stderr,"FAIL line%u: %s\n",__LINE__,#x);exit(1);} } while(0)
enum { CPUS=4,ROUNDS=600,HOST_BYTES=32*1024*1024 };
static int linux_cpu[CPUS];
static shz_bootinfo_t bi;
static pthread_barrier_t start;
static pthread_mutex_t claims_lock=PTHREAD_MUTEX_INITIALIZER;
static unsigned page_claim[HOST_BYTES/PAGE_SIZE];
static struct { uintptr_t first,last; } heap_claim[CPUS];

static void pin(int cpu)
{
    cpu_set_t mask;CPU_ZERO(&mask);CPU_SET(cpu,&mask);
    CHECK(pthread_setaffinity_np(pthread_self(),sizeof mask,&mask)==0);
}
static void setup(void)
{
    cpu_set_t allowed;unsigned count=0;CHECK(sched_getaffinity(0,sizeof allowed,&allowed)==0);
    memset(&topology,0,sizeof topology);
    for(int cpu=0;cpu<CPU_SETSIZE && count<CPUS;cpu++) if(CPU_ISSET(cpu,&allowed)) {
        pin(cpu);const unsigned raw=initial_apic_id();int duplicate=0;
        for(unsigned i=0;i<count;i++) duplicate|=topology.apic_id[i]==raw;
        if(!duplicate) { linux_cpu[count]=cpu;topology.apic_id[count++]=raw; }
    }
    CHECK(count==CPUS);topology.count=CPUS;topology.bsp_index=0;pin(linux_cpu[0]);
    CHECK(shz_smp_this_cpu()==0);
    CHECK(mmap((void *)K64_VIRT_BASE,HOST_BYTES,PROT_READ|PROT_WRITE,
               MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void *)K64_VIRT_BASE);
    shz_memholes_t *holes=(void *)(K64_VIRT_BASE+SHZ_MEMHOLES_GPA);
    holes->magic=SHZ_MEMHOLES_MAGIC;holes->count=2;
    holes->hole[0].gpa=0x800000;holes->hole[0].size=PAGE_SIZE;
    holes->hole[1].gpa=PMM_BASE+200*PAGE_SIZE;holes->hole[1].size=2*PAGE_SIZE;
    holes->check=shz_memholes_sum(holes);
    bi.ram_size=HOST_BYTES;bi.initrd_gpa=PMM_BASE+128*PAGE_SIZE;bi.initrd_size=3*PAGE_SIZE;
    mem_init(&bi);CHECK(host_flags==(1ull<<9));CHECK(mem_probe_ok);
    CHECK(!shz_cpu_pmm_page_owned(bi.initrd_gpa,&bi));
    CHECK(!shz_cpu_pmm_page_owned(holes->hole[1].gpa,&bi));
}
static void claim(unsigned cpu,uint64_t pa,unsigned pages,void *heap,size_t bytes)
{
    const uintptr_t first=(uintptr_t)heap,last=first+bytes;
    CHECK(pthread_mutex_lock(&claims_lock)==0);
    if(pa) for(unsigned i=0;i<pages;i++) {
        const uint64_t index=pa/PAGE_SIZE+i;
        CHECK(index<HOST_BYTES/PAGE_SIZE && !page_claim[index]);page_claim[index]=cpu+1;
    }
    if(heap) {
        CHECK(!(first&15) && first>=K64_VIRT_BASE+HEAP_PA && last<=K64_VIRT_BASE+PMM_BASE);
        CHECK(!(first<K64_VIRT_BASE+0x801000 && last>K64_VIRT_BASE+0x800000));
        for(unsigned i=0;i<CPUS;i++) CHECK(!heap_claim[i].first || last<=heap_claim[i].first || first>=heap_claim[i].last);
        CHECK(!heap_claim[cpu].first);heap_claim[cpu].first=first;heap_claim[cpu].last=last;
    }
    CHECK(pthread_mutex_unlock(&claims_lock)==0);
}
static void unclaim(unsigned cpu,uint64_t pa,unsigned pages,void *heap)
{
    CHECK(pthread_mutex_lock(&claims_lock)==0);
    if(pa) for(unsigned i=0;i<pages;i++) {
        const uint64_t index=pa/PAGE_SIZE+i;CHECK(page_claim[index]==cpu+1);page_claim[index]=0;
    }
    if(heap) { CHECK(heap_claim[cpu].first==(uintptr_t)heap);heap_claim[cpu].first=heap_claim[cpu].last=0; }
    CHECK(pthread_mutex_unlock(&claims_lock)==0);
}
static void *worker(void *argument)
{
    const unsigned cpu=(unsigned)(uintptr_t)argument;pin(linux_cpu[cpu]);CHECK(shz_smp_this_cpu()==cpu);
    const int barrier=pthread_barrier_wait(&start);CHECK(!barrier || barrier==PTHREAD_BARRIER_SERIAL_THREAD);
    for(unsigned round=0;round<ROUNDS;round++) {
        const unsigned pages=1+round%7;const size_t bytes=33+(round*173+cpu*31)%4000;
        const unsigned char pattern=(unsigned char)(1+cpu+round%200);
        const uint64_t single=pmm_alloc(),run=pmm_alloc_contig(pages);
        void *heap=kzalloc(bytes);CHECK(single && run && heap && host_flags==(1ull<<9));
        claim(cpu,single,1,heap,bytes);claim(cpu,run,pages,0,0);
        for(unsigned i=0;i<PAGE_SIZE;i++) CHECK(!((unsigned char *)p2v(single))[i]);
        for(unsigned i=0;i<pages*PAGE_SIZE;i++) CHECK(!((unsigned char *)p2v(run))[i]);
        for(size_t i=0;i<bytes;i++) CHECK(!((unsigned char *)heap)[i]);
        CHECK(shz_cpu_pmm_page_owned(single,&bi) && shz_cpu_pmm_page_owned(run,&bi));
        memset((void *)p2v(single),pattern,PAGE_SIZE);memset((void *)p2v(run),pattern,pages*PAGE_SIZE);memset(heap,pattern,bytes);
        if(!(round&7)) sched_yield();
        CHECK(((unsigned char *)p2v(single))[0]==pattern && ((unsigned char *)p2v(single))[PAGE_SIZE-1]==pattern);
        CHECK(((unsigned char *)p2v(run))[0]==pattern && ((unsigned char *)p2v(run))[pages*PAGE_SIZE-1]==pattern);
        CHECK(((unsigned char *)heap)[0]==pattern && ((unsigned char *)heap)[bytes-1]==pattern);
        unclaim(cpu,single,1,heap);unclaim(cpu,run,pages,0);
        pmm_free(single);pmm_free_contig(run,pages);kfree(heap);CHECK(host_flags==(1ull<<9));
    }
    __atomic_add_fetch(&worker_checks,checks,__ATOMIC_RELAXED);return 0;
}
static void concurrent(void)
{
    pthread_t threads[CPUS];const uint64_t free_before=pmm_free_count();const size_t heap_before=kheap_used();
    CHECK(pthread_barrier_init(&start,0,CPUS)==0);
    for(unsigned i=0;i<CPUS;i++) CHECK(pthread_create(&threads[i],0,worker,(void *)(uintptr_t)i)==0);
    for(unsigned i=0;i<CPUS;i++) CHECK(pthread_join(threads[i],0)==0);
    CHECK(pmm_free_count()==free_before && kheap_used()==heap_before);
    for(unsigned i=0;i<HOST_BYTES/PAGE_SIZE;i++) CHECK(!page_claim[i]);
    size_t available=0;for(struct hblock *b=heap_head;b;b=b->next) { CHECK(b->magic==HMAGIC);if(!b->used) available+=b->size; }
    CHECK(available==kheap_total());
    printf("real concurrent allocator owners: %u CPUs, %u rounds each, exact page/heap conservation\n",CPUS,ROUNDS);
}
static void rejected_free(uint64_t pa,unsigned pages,int contiguous)
{
    const pid_t child=fork();CHECK(child>=0);
    if(!child) {
        uint8_t snapshot[sizeof page_map];memcpy(snapshot,page_map,sizeof snapshot);const uint64_t before=pmm_free_pages;
        expect_panic=1;
        if(!sigsetjmp(panic_target,1)) {
            if(contiguous) pmm_free_contig(pa,pages);else pmm_free(pa);
            _Exit(1);
        }
        _Exit(pmm_free_pages==before && !memcmp(snapshot,page_map,sizeof snapshot)?0:2);
    }
    int status;CHECK(waitpid(child,&status,0)==child);CHECK(WIFEXITED(status) && WEXITSTATUS(status)==0);
}
static void reservations(void)
{
    rejected_free(bi.initrd_gpa,1,0);rejected_free(PMM_BASE+200*PAGE_SIZE,1,0);
    uint64_t retained[256];unsigned n=0;uint64_t pa;
    do { pa=pmm_alloc();CHECK(pa && n<256);retained[n++]=pa; } while(pa!=bi.initrd_gpa-PAGE_SIZE);
    rejected_free(pa,2,1); /* valid allocated prefix must not be cleared before reserved tail denial */
    for(unsigned i=0;i<n;i++) pmm_free(retained[i]);
}
static void bounds(void)
{
    const uint64_t free_before=pmm_free_count();const size_t heap_before=kheap_used();
    CHECK(!kmalloc(SIZE_MAX) && !kzalloc(SIZE_MAX-1));CHECK(!pmm_alloc_contig(0) && !pmm_alloc_contig(UINT32_MAX));
    rejected_free(PMM_BASE+1,1,0);rejected_free(ram_top,1,0);rejected_free(UINT64_MAX&~4095ull,UINT32_MAX,1);
    uint64_t pa=pmm_alloc_contig(4);CHECK(pa);pmm_free_contig(pa+PAGE_SIZE,2);
    CHECK(shz_cpu_pmm_page_owned(pa,&bi) && !shz_cpu_pmm_page_owned(pa+PAGE_SIZE,&bi));
    pmm_free(pa);pmm_free(pa+3*PAGE_SIZE);rejected_free(pa,1,0);
    pmm_free_contig(PMM_BASE,0);kfree(0);void *zero=kmalloc(0);CHECK(zero);kfree(zero);
    CHECK(pmm_free_count()==free_before && kheap_used()==heap_before && host_flags==(1ull<<9));
}
static void rejected_heap(void *p)
{
    const pid_t child=fork();CHECK(child>=0);
    if(!child) {
        const size_t before=heap_used_bytes;expect_panic=1;
        if(!sigsetjmp(panic_target,1)) { kfree(p);_Exit(1); }
        _Exit(heap_used_bytes==before?0:2);
    }
    int status;CHECK(waitpid(child,&status,0)==child);CHECK(WIFEXITED(status) && WEXITSTATUS(status)==0);
}
static void heap_negatives(void)
{
    void *p=kmalloc(256);CHECK(p);rejected_heap((char *)p+1);rejected_heap((void *)(K64_VIRT_BASE+PMM_BASE));
    struct hblock *fake=(struct hblock *)p;fake->magic=HMAGIC;fake->used=1;fake->size=16;fake->next=0;
    rejected_heap(fake+1);kfree(p);rejected_heap(p);
}
static void observer(void)
{
    const uint64_t pa=pmm_alloc();CHECK(pa && shz_cpu_pmm_page_owned(pa,&bi));
    CHECK(!shz_cpu_pmm_page_owned(pa,0) && !shz_cpu_pmm_page_owned(pa+1,&bi));
    CHECK(!shz_cpu_pmm_page_owned(ram_top,&bi) && !shz_cpu_pmm_page_owned(UINT64_MAX-4095,&bi));
    shz_bootinfo_t bad=bi;bad.initrd_gpa=pa;bad.initrd_size=PAGE_SIZE;CHECK(!shz_cpu_pmm_page_owned(pa,&bad));
    bad.initrd_gpa=pa+4095;bad.initrd_size=1;CHECK(!shz_cpu_pmm_page_owned(pa,&bad));
    bad.initrd_gpa=UINT64_MAX-1;bad.initrd_size=4;CHECK(!shz_cpu_pmm_page_owned(pa,&bad));
    pmm_free(pa);CHECK(!shz_cpu_pmm_page_owned(pa,&bi));
    /* An unavailable bit without allocation provenance cannot authorize a PT. */
    bit_set((pa-PMM_BASE)/PAGE_SIZE);CHECK(!shz_cpu_pmm_page_owned(pa,&bi));bit_clr((pa-PMM_BASE)/PAGE_SIZE);
    const uint64_t flags=host_irq_save();uint64_t another=pmm_alloc();CHECK(another && !host_flags);
    pmm_free(another);CHECK(!host_flags);host_irq_restore(flags);CHECK(host_flags==(1ull<<9));
}
static void identity(void)
{
    const unsigned raw=topology.apic_id[0];const uint64_t free_before=pmm_free_pages;const size_t heap_before=heap_used_bytes;
    topology.count=1;topology.apic_id[0]=(raw+1)&255;CHECK(shz_smp_this_cpu()==SHZ_SMP_MAX_CPUS);
    CHECK(!pmm_alloc() && !pmm_alloc_contig(2) && !kmalloc(32) && !kzalloc(32));
    CHECK(!shz_cpu_pmm_page_owned(kernel_pml4(),&bi));
    CHECK(pmm_free_pages==free_before && heap_used_bytes==heap_before && host_flags==(1ull<<9));
    topology.apic_id[0]=raw;topology.count=CPUS;
}
int main(int argc,char **argv)
{
    CHECK(argc==2);setup();
    if(!strcmp(argv[1],"concurrent")) concurrent();else if(!strcmp(argv[1],"reservations")) reservations();
    else if(!strcmp(argv[1],"bounds")) bounds();else if(!strcmp(argv[1],"identity")) identity();
    else if(!strcmp(argv[1],"heap-negatives")) heap_negatives();else if(!strcmp(argv[1],"observer")) observer();else CHECK(0);
    printf("PASS actual PMM/heap %s: %u checks\n",argv[1],checks+worker_checks);return 0;
}
