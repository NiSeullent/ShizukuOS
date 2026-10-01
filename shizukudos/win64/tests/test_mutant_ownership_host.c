/* SPDX-License-Identifier: GPL-2.0-only
 * Full production object manager + exact mutant syscall cases, with a bounded
 * host scheduler. Kernel objects, handle tables and wait blocks are genuine. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
typedef struct thread thread_t;
typedef struct process process_t;
typedef struct kobject kobject_t;
#define OB_SOCKET 0x40
#define OB_KEY 0x10
#define OB_TOKEN 0x20
#define OB_IS_IPC(t) ((t) >= 0x60 && (t) < 0x70)
#define MAX_HANDLES 4096
#define TICK_US 1000
#define SYS_NtCreateMutant 1
#define SYS_NtReleaseMutant 2
#define KASSERT(x) do { if (!(x)) { fprintf(stderr,"ASSERT %s:%d: %s\n",__FILE__,__LINE__,#x); exit(2); } } while (0)
#include "mutant_structures.inc"
typedef struct { kobject_t *obj; uint32_t access, inherit; } handle_entry_t;
struct process { handle_entry_t handles[MAX_HANDLES]; unsigned handle_count; kobject_t *object; };
struct thread {
    process_t *proc; kobject_t *object; void *wait_multi;
    int wait_result; uint64_t wake_tick; int64_t exit_code;
    uint64_t create_tick, exit_tick, user_ticks, kernel_ticks, cycles;
};
static thread_t *current;
static unsigned irq_on = 1, frees, wakes, checks, live;
static int copy_failure;
static void (*block_hook)(void);
static kobject_t *must_be_unsignaled_at_wake;
static uint64_t irq_save(void) { uint64_t old = irq_on; irq_on = 0; return old; }
static void irq_restore(uint64_t old) { irq_on = (unsigned)old; }
static void *kzalloc(size_t bytes) { void *p = calloc(1, bytes); if (p) ++live; return p; }
static void kfree(void *p) { if (p) { ++frees; KASSERT(live); --live; free(p); } }
static thread_t *thread_current(void) { return current; }
static uint64_t ticks_now(void) { return 100; }
static void thread_wake(thread_t *t) {
    KASSERT(!irq_on && t && t->wait_multi);
    if (must_be_unsignaled_at_wake) KASSERT(!must_be_unsignaled_at_wake->signaled);
    ++wakes;
}
static void thread_block_current(void);
static void kprintf(const char *fmt, ...) { va_list ap; va_start(ap,fmt); vfprintf(stderr,fmt,ap); va_end(ap); }
void reg_key_object_free(kobject_t *o) { (void)o; }
void token_object_free(kobject_t *o) { (void)o; }
void net_socket_handle_closing(kobject_t *o) { (void)o; }
void ntdrv_device_handle_closing(kobject_t *o) { (void)o; }
void file_object_closed(kobject_t *o);
void ob_release_check(kobject_t *o);
static int copy_from_user(process_t *p, void *out, uint64_t in, size_t len) {
    (void)p; if (!in) return 1; memcpy(out,(void *)(uintptr_t)in,len); return 0;
}
static int copy_to_user(process_t *p, uint64_t out, const void *in, size_t len) {
    (void)p; if (!out || copy_failure) return 1; memcpy((void *)(uintptr_t)out,in,len); return 0;
}
static int utf16_to_utf8(const uint16_t *in, size_t n, char *out, size_t cap) {
    size_t i; if (n >= cap) return -1; for (i=0;i<n;++i) { if (in[i]>127) return -1; out[i]=(char)in[i]; }
    out[n]=0; return (int)n;
}
#include "mutant_production.inc"
static void thread_block_current(void) {
    thread_t *saved = current; KASSERT(!irq_on && block_hook); block_hook(); current = saved;
}
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(2); } } while (0)
static process_t pa, pb;
static thread_t owner, waiter, other;
static kobject_t *hook_mutant;
static uint64_t hook_handle;
static uint64_t create(process_t *p, int initial, const char *name) {
    uint16_t wide[48]; struct ustr u = {0}; struct objattr oa = {0}; uint64_t h=0;
    if (name) { size_t i,n=strlen(name); CHECK(n<48); for(i=0;i<n;++i)wide[i]=(uint8_t)name[i];
        u.length=(uint16_t)(n*2);u.buffer=(uintptr_t)wide;oa.name=(uintptr_t)&u; }
    CHECK(mutant_syscall(p,SYS_NtCreateMutant,(uintptr_t)&h,0x1fffff,name?(uintptr_t)&oa:0,initial)==STATUS_SUCCESS);
    return h;
}
static int32_t release(process_t *p, uint64_t h, int32_t *previous) {
    return mutant_syscall(p,SYS_NtReleaseMutant,h,(uintptr_t)previous,0,0);
}
static int32_t wait_one(process_t *p, uint64_t h, int64_t timeout) {
    kobject_t *o; int32_t st = handle_ref(p,h,OB_MUTANT,&o,0);
    if(st)return st;
    st=ob_wait(p,&o,1,0,timeout,0); ob_deref(o); return st;
}
static void abandon_hook(void) { current=&owner; thread_object_signal(&owner); }
static void release_hook(void) {
    current=&owner; CHECK(release(&pa,hook_handle,0)==STATUS_SUCCESS);
}
static uint64_t insert(process_t *p, kobject_t *o) {
    uint32_t h=0;CHECK(handle_insert(p,o,0x1fffff,&h)==STATUS_SUCCESS);return h;
}
static void setup(void) {
    memset(&pa,0,sizeof pa);memset(&pb,0,sizeof pb);memset(&owner,0,sizeof owner);
    memset(&waiter,0,sizeof waiter);memset(&other,0,sizeof other);
    owner.proc=&pa;waiter.proc=&pb;other.proc=&pa;current=&owner;
}
static void counterfactual(void) {
    uint64_t h; setup();h=create(&pa,0,0);CHECK(wait_one(&pa,h,0)==STATUS_SUCCESS);
    thread_object_signal(&owner);current=&waiter;
    CHECK(wait_one(&pa,h,0)==STATUS_ABANDONED_WAIT_0);
    CHECK(release(&pa,h,0)==STATUS_SUCCESS);CHECK(handle_close(&pa,h)==STATUS_SUCCESS);
}
int main(int argc, char **argv) {
    uint64_t h,h2,hb; kobject_t *o; int32_t previous; unsigned before;
    (void)argv;
    if(argc>1) { counterfactual(); puts("unexpected old-source abandonment success"); return 1; }
    setup();h=create(&pa,0,0);o=handle_lookup(&pa,h,OB_MUTANT);CHECK(o&&o->refs==1);
    CHECK(wait_one(&pa,h,0)==STATUS_SUCCESS && o->refs==2 && o->u.mutant.recursion==1);
    CHECK(wait_one(&pa,h,0)==STATUS_SUCCESS && o->refs==2 && o->u.mutant.recursion==2);
    current=&other;CHECK(release(&pa,h,0)==STATUS_MUTANT_NOT_OWNED && o->refs==2);
    CHECK(wait_one(&pa,h,0)==STATUS_TIMEOUT);
    current=&owner;CHECK(release(&pa,h,&previous)==STATUS_SUCCESS && previous==-1 && o->refs==2);
    CHECK(release(&pa,h,&previous)==STATUS_SUCCESS && previous==0 && o->refs==1 && !o->u.mutant.owner);
    CHECK(release(&pa,h,0)==STATUS_MUTANT_NOT_OWNED);CHECK(handle_close(&pa,h)==STATUS_SUCCESS);

    /* Initial owner survives closing its only handle, and named cross-process
     * reopening reaches that same object rather than a fresh signaled one. */
    h=create(&pa,1,"owned-closed");o=handle_lookup(&pa,h,OB_MUTANT);CHECK(o->refs==2);
    before=frees;CHECK(handle_close(&pa,h)==STATUS_SUCCESS && frees==before && o->refs==1);
    current=&waiter;h2=0;
    { uint16_t name[]={'o','w','n','e','d','-','c','l','o','s','e','d'};
      struct ustr u={sizeof name,sizeof name,0,(uintptr_t)name};struct objattr oa={0};oa.name=(uintptr_t)&u;
      CHECK(mutant_syscall(&pb,SYS_NtCreateMutant,(uintptr_t)&h2,0x1fffff,(uintptr_t)&oa,1)==(int32_t)0x40000000); }
    CHECK(handle_lookup(&pb,h2,OB_MUTANT)==o && o->u.mutant.owner==&owner && o->refs==2);
    CHECK(wait_one(&pb,h2,0)==STATUS_TIMEOUT);
    owner.object=ob_create(OB_THREAD,0);must_be_unsignaled_at_wake=owner.object;
    block_hook=abandon_hook;before=wakes;
    CHECK(wait_one(&pb,h2,INT64_MAX)==STATUS_ABANDONED_WAIT_0 && wakes==before+1);
    CHECK(owner.object->signaled && o->u.mutant.owner==&waiter && o->refs==2 && !o->u.mutant.abandoned);
    must_be_unsignaled_at_wake=0;
    CHECK(wait_one(&pb,h2,0)==STATUS_SUCCESS && o->u.mutant.recursion==2 && o->refs==2);
    CHECK(release(&pb,h2,0)==STATUS_SUCCESS && release(&pb,h2,0)==STATUS_SUCCESS);
    CHECK(handle_close(&pb,h2)==STATUS_SUCCESS);ob_deref(owner.object);owner.object=0;

    /* No handles or wait references remain: thread exit must retire the
     * unnamed object using its ownership reference exactly once. */
    current=&owner;h=create(&pa,0,0);o=handle_lookup(&pa,h,OB_MUTANT);
    CHECK(wait_one(&pa,h,0)==STATUS_SUCCESS);CHECK(handle_close(&pa,h)==STATUS_SUCCESS);
    before=frees;thread_object_signal(&owner);CHECK(frees==before+1);
    memset(&owner,0,sizeof owner);owner.proc=&pa;current=&owner;
    thread_object_signal(&owner);CHECK(frees==before+1); /* reused task slot */

    /* WaitAll handoff changes the ownership list while exit is traversing it. */
    h=create(&pa,1,0);h2=create(&pa,1,0);o=handle_lookup(&pa,h,OB_MUTANT);
    hb=insert(&pb,o);
    { kobject_t *pair[2]={o,handle_lookup(&pa,h2,OB_MUTANT)};
      current=&waiter;block_hook=abandon_hook;before=wakes;
      CHECK(ob_wait(&pb,pair,2,1,INT64_MAX,0)==STATUS_ABANDONED_WAIT_0 && wakes==before+1);
      CHECK(pair[0]->u.mutant.owner==&waiter && pair[1]->u.mutant.owner==&waiter);
      CHECK(release(&pa,h,0)==STATUS_SUCCESS && release(&pa,h2,0)==STATUS_SUCCESS); }
    CHECK(handle_close(&pb,hb)==STATUS_SUCCESS && handle_close(&pa,h)==STATUS_SUCCESS && handle_close(&pa,h2)==STATUS_SUCCESS);

    /* Normal final release transfers ownership while preserving both refs. */
    current=&owner;h=create(&pa,1,0);hook_handle=h;hook_mutant=handle_lookup(&pa,h,OB_MUTANT);
    hb=insert(&pb,hook_mutant);
    current=&waiter;block_hook=release_hook;
    CHECK(wait_one(&pb,hb,INT64_MAX)==STATUS_SUCCESS && hook_mutant->refs==3);
    CHECK(release(&pb,hb,0)==STATUS_SUCCESS && hook_mutant->refs==2);
    CHECK(handle_close(&pa,h)==STATUS_SUCCESS && handle_close(&pb,hb)==STATUS_SUCCESS);

    /* Failed syscall publication must not leak an unseen owned object. */
    current=&owner;before=live;copy_failure=1;
    CHECK(mutant_syscall(&pa,SYS_NtCreateMutant,(uintptr_t)&h,0x1fffff,0,1)==STATUS_ACCESS_VIOLATION);
    copy_failure=0;CHECK(live==before && pa.handle_count==0);
    { unsigned i;for(i=0;i<MAX_HANDLES;++i)pa.handles[i].obj=(kobject_t *)(uintptr_t)1;
      CHECK(mutant_syscall(&pa,SYS_NtCreateMutant,(uintptr_t)&h,0x1fffff,0,1)==STATUS_NO_MEMORY);
      memset(pa.handles,0,sizeof pa.handles);CHECK(live==before); }
    CHECK(mutant_syscall(&pa,SYS_NtReleaseMutant,3,0,0,0)==STATUS_INVALID_HANDLE);
    o=ob_create(OB_EVENT,"type-conflict");h=insert(&pa,o);ob_deref(o);
    { uint16_t name[]={'t','y','p','e','-','c','o','n','f','l','i','c','t'};
      struct ustr u={sizeof name,sizeof name,0,(uintptr_t)name};struct objattr oa={0};oa.name=(uintptr_t)&u;
      CHECK(mutant_syscall(&pa,SYS_NtCreateMutant,(uintptr_t)&h2,0x1fffff,(uintptr_t)&oa,1)==STATUS_OBJECT_TYPE_MISMATCH); }
    CHECK(handle_close(&pa,h)==STATUS_SUCCESS);CHECK(live==0 && irq_on);
    printf("MUTANT-OWNERSHIP-HOST:%u checks PASS; actual refs/handles/waits/syscalls/exit, no VM\n",checks);
    return 0;
}
