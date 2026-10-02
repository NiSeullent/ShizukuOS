/* SPDX-License-Identifier: GPL-2.0-only
 * Actual Kernel32 allocator host fixture. Fixed low private mappings stand in
 * for the guest's contiguous RAM; IRQ state is thread-local. No physical AP,
 * paging hardware or Windows execution is modeled as passing.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../abi/shz_abi.h"
#define K32_H
#define PAGE_SIZE 4096u
#define PTE_P 1u
#define PTE_W 2u
#define PTE_U 4u
static _Thread_local uint32_t local_flags = 0x202;
static uint32_t irq_save(void) { uint32_t f=local_flags;local_flags&=~0x200u;return f; }
static void irq_restore(uint32_t f) { local_flags=f; }
static void write_cr3(uint32_t p) { (void)p; }
static uint32_t read_cr0(void) { return 0; }
static void write_cr0(uint32_t p) { (void)p; }
static void invlpg(uint32_t p) { (void)p; }
static void assertion_failed(const char *what,int line);
#define KASSERT(c) do { if(!(c)) assertion_failed(#c,__LINE__); } while(0)
#include "../kernel32/mem.c"

static int expected_assert;
static unsigned char *heap_snapshot;
static size_t used_snapshot;
static void assertion_failed(const char *what,int line) {
    if(expected_assert) {
        _Exit(heap_used_bytes==used_snapshot &&
              !memcmp(heap_snapshot,(void *)(uintptr_t)HEAP_BASE,HEAP_SIZE)?0:4);
    }
    fprintf(stderr,"ACTUAL_KERNEL_ASSERT line=%d %s\n",line,what);_Exit(3);
}

enum { OWNERS=6, EPOCHS=1200, TEST_PAGES=256 };
static pthread_barrier_t barrier;
static uintptr_t returned[OWNERS];
static unsigned failures,checks;
static int heap_mode;
static void check(int condition) { ++checks;if(!condition)++failures; }
static void synchronize(void) {
    int r=pthread_barrier_wait(&barrier);
    if(r && r!=PTHREAD_BARRIER_SERIAL_THREAD) abort();
}
static void *actor(void *arg) {
    unsigned id=(unsigned)(uintptr_t)arg;
    for(unsigned epoch=0;epoch<EPOCHS;epoch++) {
        synchronize();
        returned[id]=heap_mode?(uintptr_t)kmalloc(128):(uintptr_t)pmm_alloc();
        synchronize();
        if(!id) {
            for(unsigned i=0;i<OWNERS;i++) {
                check(returned[i]!=0);
                for(unsigned j=0;j<i;j++) check(returned[i]!=returned[j]);
                if(!heap_mode && returned[i]) {
                    const unsigned char *p=(const void *)returned[i];
                    unsigned clean=1;
                    for(unsigned k=0;k<PAGE_SIZE;k++) clean&=p[k]==0;
                    check(clean);
                }
            }
            check(heap_mode?kheap_used()==OWNERS*128:pmm_free_count()==TEST_PAGES-OWNERS);
            for(unsigned i=0;i<OWNERS;i++) if(returned[i])
                memset((void *)returned[i],(int)(0x31+i),128);
            for(unsigned i=0;i<OWNERS;i++) if(returned[i]) {
                const unsigned char *p=(const void *)returned[i];
                unsigned good=1;
                for(unsigned k=0;k<128;k++) good&=p[k]==0x31+i;
                check(good);
            }
            /* A duplicate returned address is freed only once. This is a
             * failure-recovery fixture, not a legal duplicate free caller. */
            for(unsigned i=0;i<OWNERS;i++) {
                unsigned distinct=returned[i]!=0;
                for(unsigned j=0;j<i;j++) if(returned[i]==returned[j]) distinct=0;
                if(distinct) {
                    if(heap_mode) kfree((void *)returned[i]);
                    else pmm_free((uint32_t)returned[i]);
                }
            }
            check(heap_mode?kheap_used()==0:pmm_free_count()==TEST_PAGES);
        }
        synchronize();
        if(local_flags!=0x202) abort();
    }
    return 0;
}

/* Checking ownership is separate from allocator ownership. No allocator call
 * runs while ledger_mutex is held. Retire a checked payload before issuing its
 * free: retaining it until free returns would falsely reject legal immediate
 * reuse by another caller. Payload writes/checks belong to their actual actor;
 * the ledger never allocates or frees on an actor's behalf. */
struct live_span { uintptr_t base; size_t bytes; };
struct owner_totals { unsigned checks,failures,allocations,frees,epochs,if_on,if_off,span_checks; };
static struct live_span live[OWNERS];
static struct owner_totals totals[OWNERS];
static pthread_mutex_t ledger_mutex=PTHREAD_MUTEX_INITIALIZER;
static int mixed_stop;
static unsigned active_alloc,active_free,peak_calls,cross_calls;
static _Thread_local int ledger_owned;
static void ledger_enter(void) {
    if(pthread_mutex_lock(&ledger_mutex)) abort();
    ledger_owned=1;
}
static void ledger_leave(void) {
    ledger_owned=0;
    if(pthread_mutex_unlock(&ledger_mutex)) abort();
}
static void owned_check(struct owner_totals *t,int condition) {
    ++t->checks;if(!condition) ++t->failures;
}
static void call_enter(int allocating) {
    if(ledger_owned) abort();
    unsigned *own=allocating?&active_alloc:&active_free;
    unsigned *other=allocating?&active_free:&active_alloc;
    unsigned count=__atomic_add_fetch(own,1,__ATOMIC_SEQ_CST)+
                   __atomic_load_n(other,__ATOMIC_SEQ_CST);
    unsigned peak=__atomic_load_n(&peak_calls,__ATOMIC_RELAXED);
    while(count>peak && !__atomic_compare_exchange_n(&peak_calls,&peak,count,0,
                                                   __ATOMIC_RELAXED,__ATOMIC_RELAXED)) { }
    if(__atomic_load_n(other,__ATOMIC_SEQ_CST))
        __atomic_add_fetch(&cross_calls,1,__ATOMIC_RELAXED);
}
static void call_leave(int allocating) {
    __atomic_sub_fetch(allocating?&active_alloc:&active_free,1,__ATOMIC_SEQ_CST);
}
static int ledger_admit(unsigned id,unsigned epoch,uintptr_t base,size_t bytes,
                        struct owner_totals *t) {
    uintptr_t lo=heap_mode?HEAP_BASE:PMM_BASE;
    uintptr_t hi=lo+(heap_mode?HEAP_SIZE:TEST_PAGES*PAGE_SIZE);
    ledger_enter();
    int valid=base>=lo && base<hi && bytes<=hi-base;
    owned_check(t,valid);
    for(unsigned i=0;i<OWNERS;i++) if(live[i].base) {
        int separate=base+bytes<=live[i].base || live[i].base+live[i].bytes<=base;
        owned_check(t,separate);++t->span_checks;valid&=separate;
    }
    if(valid) live[id]=(struct live_span){base,bytes};
    else {
        mixed_stop=1;
        fprintf(stderr,"MIXED_LIVE_REFUSAL owner=%u epoch=%u address=%lx bytes=%zu\n",
                id,epoch,(unsigned long)base,bytes);
    }
    ledger_leave();return valid;
}
static unsigned char pattern(unsigned id,unsigned epoch,size_t byte) {
    return (unsigned char)((id*73u+epoch*17u+byte*3u)^(byte>>8));
}
static void mixed_counts(struct owner_totals *t,uint32_t flags) {
    if(ledger_owned) abort();
    uint32_t pages=pmm_free_count();
    owned_check(t,local_flags==flags);owned_check(t,pages<=TEST_PAGES);
    size_t bytes=kheap_used();
    owned_check(t,local_flags==flags);owned_check(t,bytes<=HEAP_SIZE);
}
static void *mixed_actor(void *arg) {
    unsigned id=(unsigned)(uintptr_t)arg;
    struct owner_totals t={0};
    const size_t sizes[]={1,17,63,128,511,1024,3073,8191};
    synchronize();
    for(unsigned epoch=0;epoch<EPOCHS;epoch++) {
        ledger_enter();int stop=mixed_stop;ledger_leave();
        if(stop) break;
        uint32_t flags=((epoch+id)&1)?2u:0x202u;
        local_flags=flags;
        if(flags&0x200u) ++t.if_on;else ++t.if_off;
        size_t bytes=heap_mode?sizes[(epoch*3u+id)%8]:PAGE_SIZE;
        call_enter(1);
        uintptr_t base=heap_mode?(uintptr_t)kmalloc(bytes):(uintptr_t)pmm_alloc();
        call_leave(1);
        owned_check(&t,local_flags==flags);owned_check(&t,base!=0);
        mixed_counts(&t,flags);
        if(!base) break;
        ++t.allocations;
        if(!ledger_admit(id,epoch,base,bytes,&t)) break;
        unsigned char *p=(void *)base;
        if(!heap_mode) {
            unsigned clean=1;
            for(size_t i=0;i<bytes;i++) clean&=p[i]==0;
            owned_check(&t,clean);
        }
        for(size_t i=0;i<bytes;i++) p[i]=pattern(id,epoch,i);
        /* Other actors can allocate/free while this owner keeps its payload. */
        if((epoch+id)%3) sched_yield();
        unsigned intact=1;
        for(size_t i=0;i<bytes;i++) intact&=p[i]==pattern(id,epoch,i);
        owned_check(&t,intact);
        ledger_enter();
        owned_check(&t,live[id].base==base && live[id].bytes==bytes);
        live[id]=(struct live_span){0,0};
        ledger_leave();
        call_enter(0);
        if(heap_mode) kfree((void *)base);else pmm_free((uint32_t)base);
        call_leave(0);
        ++t.frees;owned_check(&t,local_flags==flags);++t.epochs;
        mixed_counts(&t,flags);
    }
    totals[id]=t; /* Single writer; main observes only after pthread_join. */
    return 0;
}
static int mixed_run(const char *mode) {
    pthread_t threads[OWNERS];
    for(unsigned i=0;i<OWNERS;i++)
        if(pthread_create(&threads[i],0,mixed_actor,(void *)(uintptr_t)i)) return 2;
    for(unsigned i=0;i<OWNERS;i++) if(pthread_join(threads[i],0)) return 2;
    unsigned allocations=0,frees=0,span_checks=0;
    for(unsigned i=0;i<OWNERS;i++) {
        checks+=totals[i].checks;failures+=totals[i].failures;
        allocations+=totals[i].allocations;frees+=totals[i].frees;
        span_checks+=totals[i].span_checks;
        check(totals[i].epochs==EPOCHS && totals[i].allocations==totals[i].frees);
        check(totals[i].if_on==EPOCHS/2 && totals[i].if_off==EPOCHS/2);
        check(live[i].base==0);
    }
    check(!mixed_stop);check(active_alloc==0 && active_free==0);
    check(peak_calls>=2 && cross_calls>0);
    uint32_t pages=pmm_free_count();check(local_flags==0x202);check(pages==TEST_PAGES);
    size_t used=kheap_used();check(local_flags==0x202);check(used==0);
    printf("K32_MEMORY_ACTUAL_C mode=%s owners=%u epochs=%u checks=%u failures=%u "
           "allocations=%u frees=%u peak_host_call_intervals=%u overlapping_alloc_free_intervals=%u "
           "live_span_comparisons=%u "
           "IF=on-off-preserved ledger_allocator_calls=0; host-only\n",
           mode,OWNERS,EPOCHS,checks,failures,allocations,frees,peak_calls,cross_calls,span_checks);
    return failures?1:0;
}
static void mapping(uintptr_t base,size_t bytes) {
    void *p=mmap((void *)base,bytes,PROT_READ|PROT_WRITE,
                 MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    if(p!=(void *)base) { perror("private low mapping");exit(2); }
}
static void rejected_pointer(void *p) {
    memcpy(heap_snapshot,(void *)(uintptr_t)HEAP_BASE,HEAP_SIZE);
    used_snapshot=heap_used_bytes;
    pid_t child=fork();
    if(child<0) _Exit(2);
    if(!child) { expected_assert=1;kfree(p);_Exit(1); }
    int status=0;
    if(waitpid(child,&status,0)!=child) _Exit(2);
    check(WIFEXITED(status) && WEXITSTATUS(status)==0);
}
static void guards(void) {
    heap_snapshot=malloc(HEAP_SIZE);
    if(!heap_snapshot) _Exit(2);
    const size_t bad_sizes[]={0,SIZE_MAX,SIZE_MAX-7,HEAP_SIZE};
    for(unsigned i=0;i<sizeof bad_sizes/sizeof bad_sizes[0];i++) {
        memcpy(heap_snapshot,(void *)(uintptr_t)HEAP_BASE,HEAP_SIZE);
        used_snapshot=heap_used_bytes;
        void *p=kmalloc(bad_sizes[i]);
        check(p==0);
        check(heap_used_bytes==used_snapshot &&
              !memcmp(heap_snapshot,(void *)(uintptr_t)HEAP_BASE,HEAP_SIZE));
        if(p) kfree(p);
    }
    void *real=kmalloc(256);check(real!=0);
    struct hblock *fake=(void *)((uintptr_t)real+64);
    *fake=(struct hblock){.size=16,.used=1,.next=0,.magic=HMAGIC};
    rejected_pointer(fake+1);
    rejected_pointer((void *)(uintptr_t)HEAP_BASE);
    kfree(real);check(kheap_used()==0);
    free(heap_snapshot);
}
static void exhaustion(void) {
    uint32_t pages[TEST_PAGES];
    for(unsigned i=0;i<TEST_PAGES;i++) {
        pages[i]=pmm_alloc();check(pages[i]!=0);
        for(unsigned j=0;j<i;j++) check(pages[i]!=pages[j]);
    }
    check(pmm_free_count()==0);check(pmm_alloc()==0);
    for(unsigned i=0;i<TEST_PAGES;i++) pmm_free(pages[(i*17)%TEST_PAGES]);
    check(pmm_free_count()==TEST_PAGES);
    void *blocks[HEAP_SIZE/PAGE_SIZE+1];
    unsigned count=0;
    while(count<sizeof blocks/sizeof blocks[0]) {
        void *p=kmalloc(PAGE_SIZE);
        if(!p) break;
        blocks[count++]=p;
    }
    check(count>400 && count<sizeof blocks/sizeof blocks[0]);
    check(kmalloc(PAGE_SIZE)==0);
    for(unsigned i=0;i<count;i++) {
        for(unsigned j=0;j<i;j++)
            check((uintptr_t)blocks[i]+PAGE_SIZE<=(uintptr_t)blocks[j] ||
                  (uintptr_t)blocks[j]+PAGE_SIZE<=(uintptr_t)blocks[i]);
    }
    for(unsigned i=0;i<count;i+=2) kfree(blocks[i]);
    for(unsigned i=1;i<count;i+=2) kfree(blocks[i]);
    check(kheap_used()==0);
    void *large=kmalloc(HEAP_SIZE/2);check(large!=0);kfree(large);
    local_flags=2;
    uint32_t page=pmm_alloc();check(local_flags==2);pmm_free(page);
    void *p=kmalloc(128);check(local_flags==2);kfree(p);check(local_flags==2);
    local_flags=0x202;
}
int main(int argc,char **argv) {
    if(argc!=2 || (strcmp(argv[1],"pmm") && strcmp(argv[1],"heap") && strcmp(argv[1],"guards") &&
                  strcmp(argv[1],"mixed-pmm") && strcmp(argv[1],"mixed-heap"))) return 2;
    heap_mode=!strcmp(argv[1],"heap") || !strcmp(argv[1],"mixed-heap");
    struct rlimit no_core={0,0};
    if(setrlimit(RLIMIT_CORE,&no_core)) return 2;
    mapping(HEAP_BASE,HEAP_SIZE);
    mapping(PMM_BASE,TEST_PAGES*PAGE_SIZE);
    pmm_pages=pmm_free_pages=TEST_PAGES;pmm_hint=0;
    memset(page_map,0,sizeof page_map);heap_init();
    if(!strcmp(argv[1],"guards")) {
        guards();exhaustion();
        printf("K32_MEMORY_ACTUAL_C mode=guards checks=%u failures=%u; host-only\n",checks,failures);
        return failures?1:0;
    }
    if(pthread_barrier_init(&barrier,0,OWNERS)) return 2;
    if(!strncmp(argv[1],"mixed-",6)) return mixed_run(argv[1]);
    pthread_t threads[OWNERS];
    for(unsigned i=0;i<OWNERS;i++)
        if(pthread_create(&threads[i],0,actor,(void *)(uintptr_t)i)) return 2;
    for(unsigned i=0;i<OWNERS;i++) if(pthread_join(threads[i],0)) return 2;
    printf("K32_MEMORY_ACTUAL_C mode=%s owners=%u epochs=%u checks=%u failures=%u IRQ=restored; host-only\n",
           argv[1],OWNERS,EPOCHS,checks,failures);
    return failures?1:0;
}
