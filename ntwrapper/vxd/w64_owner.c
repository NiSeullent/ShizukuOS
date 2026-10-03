/* SPDX-License-Identifier: GPL-2.0-only -- NTWRAP9X W64 derived owner identity; contract in w64_owner.h. */
#include "w64_owner.h"
#include "bridge.h"

#ifndef NTWV_ERROR_ACCESS_DENIED
#define NTWV_ERROR_ACCESS_DENIED 5u
#endif

struct owner {
    uint32_t process, vm, generation, token;    /* process==0: free */
};
static struct owner owners[NTWV_W64_OWNER_SLOTS];
static uint32_t system_vm_handle, next_token = 1, issued;
static uint32_t deferred[NTWV_W64_OWNER_DEFERRED], deferred_overflow;
/* Live NTWRAP9X handle count per tagProcess; guarded by the bound interrupt lock only. */
static struct { uint32_t process, refs; } handles[NTWV_W64_OWNER_HANDLE_PROCS];
static uintptr_t (*lock_enter)(void *);
static void (*lock_leave)(void *, uintptr_t);

void ntwv_w64_owner_bind_system_vm(uint32_t system_vm)
{
    __atomic_store_n(&system_vm_handle, system_vm, __ATOMIC_RELEASE);
}

void ntwv_w64_owner_bind_lock(uintptr_t (*enter)(void *opaque), void (*leave)(void *opaque, uintptr_t saved))
{
    lock_leave = leave;
    __atomic_store_n(&lock_enter, enter, __ATOMIC_RELEASE);
}

uint32_t ntwv_w64_owner_handle_open(uint32_t vm, uint32_t process)
{
    uintptr_t saved;
    uint32_t i, free_slot = NTWV_W64_OWNER_HANDLE_PROCS, result = NTWV_ERROR_BUSY;
    uintptr_t (*enter)(void *) = __atomic_load_n(&lock_enter, __ATOMIC_ACQUIRE);
    const uint32_t sys = __atomic_load_n(&system_vm_handle, __ATOMIC_ACQUIRE);
    if (!enter || !lock_leave || !sys || vm != sys || !process)
        return NTWV_ERROR_ACCESS_DENIED;
    saved = enter(0);
    for (i = 0; i < NTWV_W64_OWNER_HANDLE_PROCS; ++i) {
        if (handles[i].process == process) {
            if (handles[i].refs != UINT32_MAX) {
                ++handles[i].refs;
                result = 0;
            }
            free_slot = NTWV_W64_OWNER_HANDLE_PROCS;
            break;
        }
        if (!handles[i].process && free_slot == NTWV_W64_OWNER_HANDLE_PROCS)
            free_slot = i;
    }
    if (free_slot != NTWV_W64_OWNER_HANDLE_PROCS) {
        handles[free_slot].process = process;
        handles[free_slot].refs = 1;
        result = 0;
    }
    lock_leave(0, saved);
    return result;
}

void ntwv_w64_owner_handle_close(uint32_t process)
{
    uintptr_t saved;
    uint32_t i, last = 1;
    uintptr_t (*enter)(void *) = __atomic_load_n(&lock_enter, __ATOMIC_ACQUIRE);
    if (!process)
        return;
    if (enter && lock_leave) {
        saved = enter(0);
        for (i = 0; i < NTWV_W64_OWNER_HANDLE_PROCS; ++i)
            if (handles[i].process == process) {
                last = --handles[i].refs == 0;
                if (last)
                    handles[i].process = 0;
                break;
            }
        lock_leave(0, saved);
    }
    if (last)                                   /* last handle, or a close we never counted: fail closed */
        ntwv_w64_owner_departed(process);
}

uint32_t ntwv_w64_owner_handles(uint32_t process)
{
    uintptr_t saved;
    uint32_t i, refs = 0;
    uintptr_t (*enter)(void *) = __atomic_load_n(&lock_enter, __ATOMIC_ACQUIRE);
    if (!process || !enter || !lock_leave)
        return 0;
    saved = enter(0);
    for (i = 0; i < NTWV_W64_OWNER_HANDLE_PROCS; ++i)
        if (handles[i].process == process) {
            refs = handles[i].refs;
            break;
        }
    lock_leave(0, saved);
    return refs;
}

/* The LE packer accepts only relocations whose target lies inside .text/.data. Clang's loop strength reduction
 * can address owners[] as (end-of-array + negative index), i.e. a displacement past .data; the empty asm keeps
 * every element address computed from the array base. */
static struct owner *owner_at(uint32_t i)
{
    struct owner *o = &owners[i];
    __asm__("" : "+r"(o));
    return o;
}

static void clear_owner(struct owner *o)
{
    o->process = o->vm = o->generation = o->token = 0;
}

static void retire_all(void)
{
    uint32_t i;
    for (i = 0; i < NTWV_W64_OWNER_SLOTS; ++i)
        clear_owner(owner_at(i));
}

static void retire(uint32_t process)
{
    uint32_t i;
    for (i = 0; i < NTWV_W64_OWNER_SLOTS; ++i)
        if (owner_at(i)->process == process)
            clear_owner(owner_at(i));
}

static void drain_departures(void)
{
    uint32_t i, process;
    if (__atomic_exchange_n(&deferred_overflow, 0u, __ATOMIC_ACQ_REL))
        retire_all();
    for (i = 0; i < NTWV_W64_OWNER_DEFERRED; ++i)
        if ((process = __atomic_exchange_n(&deferred[i], 0u, __ATOMIC_ACQ_REL)) != 0)
            retire(process);
}

void ntwv_w64_owner_departed(uint32_t process)
{
    uint32_t i, expected;
    if (!process)
        return;
    for (i = 0; i < NTWV_W64_OWNER_DEFERRED; ++i) {
        expected = 0;
        if (__atomic_compare_exchange_n(&deferred[i], &expected, process, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) ||
            expected == process)
            return;
    }
    __atomic_store_n(&deferred_overflow, 1u, __ATOMIC_RELEASE);   /* fail closed: retire everyone */
}

uint32_t ntwv_w64_owner_derive(uint32_t vm, uint32_t process, uint32_t channel_generation, uint32_t *capability)
{
    uint32_t i, free_slot = NTWV_W64_OWNER_SLOTS;
    const uint32_t sys = __atomic_load_n(&system_vm_handle, __ATOMIC_ACQUIRE);
    if (!capability)
        return NTWV_ERROR_INVALID_PARAMETER;
    *capability = 0;
    drain_departures();
    /* Win32 DIOC callers run in the system VM; a DOS VM or an unbound service has no derivable process owner. */
    if (!sys || vm != sys || !process || !channel_generation)
        return NTWV_ERROR_ACCESS_DENIED;
    /* Only a process holding a recorded live NTWRAP9X handle has an identity; its last close retires it. */
    if (!ntwv_w64_owner_handles(process))
        return NTWV_ERROR_ACCESS_DENIED;
    for (i = 0; i < NTWV_W64_OWNER_SLOTS; ++i) {
        if (owner_at(i)->process == process) {
            if (owner_at(i)->vm == vm && owner_at(i)->generation == channel_generation) {
                *capability = SHZ_W64_OWNER_CAP_DERIVED | owner_at(i)->token;
                return 0;
            }
            /* Same tag under another channel generation: the old identity is dead; issue a new one here. */
            owner_at(i)->process = owner_at(i)->vm = owner_at(i)->generation = owner_at(i)->token = 0;
        }
        if (!owner_at(i)->process && free_slot == NTWV_W64_OWNER_SLOTS)
            free_slot = i;
    }
    if (free_slot == NTWV_W64_OWNER_SLOTS)
        return NTWV_ERROR_BUSY;
    if (next_token == 0 || next_token > SHZ_W64_OWNER_CAP_TOKEN)
        return NTWV_ERROR_ACCESS_DENIED;                       /* exhausted: never wrap or reissue */
    owner_at(free_slot)->process = process;
    owner_at(free_slot)->vm = vm;
    owner_at(free_slot)->generation = channel_generation;
    owner_at(free_slot)->token = next_token++;
    ++issued;
    *capability = SHZ_W64_OWNER_CAP_DERIVED | owner_at(free_slot)->token;
    return 0;
}

void ntwv_w64_owner_stamp(shz_msg_hdr_t *header, int stamp, uint32_t capability)
{
    if (!header)
        return;
    header->capability_id = stamp && shz_w64_owner_cap_derived(capability) ? capability :
                            (stamp ? 0u : (header->capability_id & ~SHZ_W64_OWNER_CAP_DERIVED));
}

void ntwv_w64_owner_reset_locked(void)
{
    uint32_t i;
    retire_all();
    for (i = 0; i < NTWV_W64_OWNER_DEFERRED; ++i)
        __atomic_store_n(&deferred[i], 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&deferred_overflow, 0u, __ATOMIC_RELEASE);
}

int ntwv_w64_owner_cap_live(uint32_t capability)
{
    uint32_t i;
    if (!shz_w64_owner_cap_derived(capability))
        return 0;
    drain_departures();
    for (i = 0; i < NTWV_W64_OWNER_SLOTS; ++i)
        if (owner_at(i)->process && owner_at(i)->token == (capability & SHZ_W64_OWNER_CAP_TOKEN))
            return 1;
    return 0;
}

uint32_t ntwv_w64_owner_live(void)
{
    uint32_t i, n = 0;
    for (i = 0; i < NTWV_W64_OWNER_SLOTS; ++i)
        n += owner_at(i)->process != 0;
    return n;
}
uint32_t ntwv_w64_owner_issued(void) { return issued; }
