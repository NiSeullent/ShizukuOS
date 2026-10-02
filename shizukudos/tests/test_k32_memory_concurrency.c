/* SPDX-License-Identifier: GPL-2.0-only
 * Actual Kernel32 allocator host fixture. Fixed low private mappings stand in
 * for the guest's contiguous RAM; IRQ state is thread-local. No physical AP,
 * paging hardware or Windows execution is modeled as passing.
 */
#define _GNU_SOURCE
#include <pthread.h>
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
    if(argc!=2 || (strcmp(argv[1],"pmm") && strcmp(argv[1],"heap") && strcmp(argv[1],"guards"))) return 2;
    heap_mode=!strcmp(argv[1],"heap");
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
    pthread_t threads[OWNERS];
    for(unsigned i=0;i<OWNERS;i++)
        if(pthread_create(&threads[i],0,actor,(void *)(uintptr_t)i)) return 2;
    for(unsigned i=0;i<OWNERS;i++) if(pthread_join(threads[i],0)) return 2;
    printf("K32_MEMORY_ACTUAL_C mode=%s owners=%u epochs=%u checks=%u failures=%u IRQ=restored; host-only\n",
           argv[1],OWNERS,EPOCHS,checks,failures);
    return failures?1:0;
}
