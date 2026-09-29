/* SPDX-License-Identifier: GPL-2.0-only
 * ReactOS-reference derivative, distributed under GNU GPL version 2.
 * Behavior adapted from ReactOS dll/ntdll/ldr/ldrinit.c LdrpInitializeTls,
 * LdrpAllocateTls and LdrpFreeTls at 9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8
 * (Alex Ionescu, Aleksey Bragin) and dll/ntdll/ldr/ldrutils.c
 * LdrpCallTlsInitializers. Wine dlls/ntdll/loader.c alloc_tls_slot,
 * alloc_thread_tls and call_tls_callbacks at
 * df15af3652511150490934682202d45af892f887 were compared and not copied.
 * One-Core-API-Source ldrinit.c at 9eb3c31de9460c1ccce3f6a10c9c4a704f032514
 * was located; its body was not copied.
 *
 * Port differences: explicit allocator, no PEB/TEB, SizeOfZeroFill is applied
 * (the pinned ReactOS LdrpAllocateTls copies only End-Start), Characteristics
 * in the on-disk directory are rejected unless zero instead of being reused
 * as the index, and registration fails while a thread is live.
 */
#include "tls.h"
struct ntwtls_module {
    void *module;
    const uint8_t *raw;
    uint32_t raw_bytes, zero_fill, index, callback_count, alignment;
    uint32_t *index_slot;
    ntwtls_callback callbacks[NTWTLS_MAX_CALLBACKS];
};
struct ntwtls_process {
    ntwtls_services services;
    struct ntwtls_module modules[NTWTLS_MAX_MODULES];
    uint32_t count, live_threads;
};
struct ntwtls_thread {
    void *slots[NTWTLS_MAX_MODULES];
    void *bases[NTWTLS_MAX_MODULES];
    uint32_t block_bytes[NTWTLS_MAX_MODULES];
    uint32_t count;
    int live;
};
static uint32_t tls_alignment(uint32_t characteristics) {
    uint32_t nibble = (characteristics >> 20) & 0xFu;
    /* MSVC stores section-style alignment here. Other bits stay rejected. */
    if (characteristics & ~0x00F00000u) return 0;
    if (nibble == 0) return 1;
    if (nibble > 13) return 0;
    return 1u << (nibble - 1);
}
size_t ntwtls_process_size(void) { return sizeof(ntwtls_process); }
size_t ntwtls_thread_size(void) { return sizeof(ntwtls_thread); }
static int services_ok(const ntwtls_services *services) {
    return services && services->allocate && services->release;
}
int ntwtls_process_init(ntwtls_process *process, const ntwtls_services *services) {
    if (!process || !services_ok(services)) return NTWTLS_INVALID;
    process->services = *services;
    process->count = 0;
    process->live_threads = 0;
    return NTWTLS_OK;
}
static void release_block(ntwtls_process *process, void *block, uint32_t bytes) {
    if (block) process->services.release(process->services.user, block, bytes);
}
static int register_module(ntwtls_process *process, const ntwtls_image *image, uint32_t *out_index, int allow_live) {
    struct ntwtls_module *module;
    uint32_t callbacks = 0, total, index, n;
    if (!process || !services_ok(&process->services) || !image || !out_index || !image->module)
        return NTWTLS_INVALID;
    if (process->live_threads && !allow_live) return NTWTLS_BUSY;
    if (process->count >= NTWTLS_MAX_MODULES) return NTWTLS_LIMIT;
    if (!image->index_slot) return NTWTLS_INVALID;
    if (!tls_alignment(image->characteristics)) return NTWTLS_INVALID;
    if ((uintptr_t)image->index_slot % sizeof(uint32_t) != 0) return NTWTLS_INVALID;
    if (image->raw_bytes && !image->raw) return NTWTLS_INVALID;
    if (image->raw_bytes > NTWTLS_MAX_BLOCK || image->zero_fill > NTWTLS_MAX_BLOCK)
        return NTWTLS_LIMIT;
    total = image->raw_bytes + image->zero_fill;
    if (total < image->raw_bytes || total > NTWTLS_MAX_BLOCK) return NTWTLS_LIMIT;
    if (image->callbacks) {
        for (; image->callbacks[callbacks]; ++callbacks) {
            if (callbacks >= NTWTLS_MAX_CALLBACKS) return NTWTLS_LIMIT;
        }
    }
    if (!total && !callbacks) return NTWTLS_INVALID;
    for (n = 0; n < process->count; ++n)
        if (process->modules[n].index_slot == image->index_slot) return NTWTLS_INVALID;
    module = &process->modules[process->count];
    index = process->count;
    module->alignment = tls_alignment(image->characteristics);
    module->module = image->module;
    module->raw = image->raw;
    module->raw_bytes = image->raw_bytes;
    module->zero_fill = image->zero_fill;
    module->index = index;
    module->index_slot = image->index_slot;
    module->callback_count = callbacks;
    for (n = 0; n < callbacks; ++n) module->callbacks[n] = image->callbacks[n];
    *image->index_slot = index;
    ++process->count;
    *out_index = index;
    return NTWTLS_OK;
}
int ntwtls_register(ntwtls_process *process, const ntwtls_image *image, uint32_t *out_index) {
    return register_module(process, image, out_index, 0);
}
int ntwtls_register_late(ntwtls_process *process, const ntwtls_image *image, uint32_t *out_index) {
    return register_module(process, image, out_index, 1);
}
int ntwtls_thread_extend(ntwtls_process *process, ntwtls_thread *thread) {
    if (!process || !services_ok(&process->services) || !thread || !thread->live) return NTWTLS_INVALID;
    while (thread->count < process->count) {
        struct ntwtls_module *module = &process->modules[thread->count];
        uint32_t bytes = module->raw_bytes + module->zero_fill, i, alloc_size, align;
        uint8_t *block, *aligned;
        if (bytes) {
            align = module->alignment ? module->alignment : 1;
            alloc_size = bytes + align - 1;
            block = process->services.allocate(process->services.user, alloc_size);
            if (!block) return NTWTLS_NO_MEMORY;
            aligned = (uint8_t *)(((uintptr_t)block + align - 1) & ~(uintptr_t)(align - 1));
            for (i = 0; i < module->raw_bytes; ++i) aligned[i] = module->raw[i];
            for (i = 0; i < module->zero_fill; ++i) aligned[module->raw_bytes + i] = 0;
            thread->bases[thread->count] = block;
            thread->slots[thread->count] = aligned;
            thread->block_bytes[thread->count] = alloc_size;
        }
        thread->count++;
    }
    return NTWTLS_OK;
}
int ntwtls_thread_init(ntwtls_process *process, ntwtls_thread *thread) {
    uint32_t n;
    if (!process || !services_ok(&process->services) || !thread || thread->live)
        return NTWTLS_INVALID;
    for (n = 0; n < NTWTLS_MAX_MODULES; ++n) {
        thread->slots[n] = 0;
        thread->bases[n] = 0;
        thread->block_bytes[n] = 0;
    }
    thread->count = process->count;
    for (n = 0; n < process->count; ++n) {
        struct ntwtls_module *module = &process->modules[n];
        uint32_t bytes = module->raw_bytes + module->zero_fill, i, alloc_size, align;
        uint8_t *block, *aligned;
        if (!bytes) continue;
        align = module->alignment ? module->alignment : 1;
        alloc_size = bytes + align - 1;
        block = process->services.allocate(process->services.user, alloc_size);
        if (!block) {
            for (i = 0; i < n; ++i) release_block(process, thread->bases[i], thread->block_bytes[i]);
            return NTWTLS_NO_MEMORY;
        }
        aligned = (uint8_t *)(((uintptr_t)block + align - 1) & ~(uintptr_t)(align - 1));
        for (i = 0; i < module->raw_bytes; ++i) aligned[i] = module->raw[i];
        for (i = 0; i < module->zero_fill; ++i) aligned[module->raw_bytes + i] = 0;
        thread->bases[n] = block;
        thread->slots[n] = aligned;
        thread->block_bytes[n] = alloc_size;
    }
    thread->live = 1;
    ++process->live_threads;
    return NTWTLS_OK;
}
int ntwtls_call(ntwtls_process *process, ntwtls_thread *thread, uint32_t reason) {
    uint32_t n, c;
    if (!process || !thread || !thread->live || thread->count != process->count)
        return NTWTLS_INVALID;
    if (reason > NTWTLS_THREAD_DETACH) return NTWTLS_INVALID;
    for (n = 0; n < process->count; ++n) {
        struct ntwtls_module *module = &process->modules[n];
        for (c = 0; c < module->callback_count; ++c)
            module->callbacks[c](module->module, reason, 0);
    }
    return NTWTLS_OK;
}
int ntwtls_thread_fini(ntwtls_process *process, ntwtls_thread *thread) {
    uint32_t n;
    if (!process || !services_ok(&process->services) || !thread || !thread->live)
        return NTWTLS_INVALID;
    for (n = 0; n < thread->count; ++n)
        release_block(process, thread->bases[n], thread->block_bytes[n]);
    thread->live = 0;
    if (process->live_threads) --process->live_threads;
    return NTWTLS_OK;
}
uint32_t ntwtls_module_count(const ntwtls_process *process) {
    return process ? process->count : 0;
}
void *ntwtls_slot(const ntwtls_thread *thread, uint32_t index) {
    if (!thread || !thread->live || index >= thread->count) return 0;
    return thread->slots[index];
}
