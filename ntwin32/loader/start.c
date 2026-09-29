/* SPDX-License-Identifier: GPL-2.0-only
 * Process-start TLS sequence: register the mapped image, allocate its TLS
 * block, then call PROCESS_ATTACH callbacks. Subsystem bytes are not touched.
 */
#include "start.h"
int ntw_loader_start(uint8_t *image, const ntw_placed *placed, ntwtls_process *process,
                     ntwtls_thread *thread, const ntwtls_services *services, int execute,
                     void **slot_out) {
    ntwtls_callback callbacks[32];
    ntwtls_image info;
    uint32_t index = 0xffffffffu, n;
    int status;
    if (!image || !placed || !process || !thread || !services || !placed->tls.present)
        return NTWTLS_INVALID;
    if (ntwtls_process_init(process, services) != NTWTLS_OK) return NTWTLS_INVALID;
    for (n = 0; n < placed->tls.callback_count; ++n) {
        uint32_t va = placed->tls.callback_vas[n];
        uint32_t base = placed->actual_base;
        if (va < base || va - base >= placed->size_of_image) return NTWTLS_INVALID;
        callbacks[n] = (ntwtls_callback)(void *)(image + (va - base));
    }
    callbacks[n] = 0;
    info.module = image;
    info.raw = placed->tls.raw;
    info.raw_bytes = placed->tls.raw_bytes;
    info.zero_fill = placed->tls.zero_fill;
    info.index_slot = placed->tls.index_slot;
    info.callbacks = placed->tls.callback_count ? callbacks : 0;
    info.characteristics = placed->tls.characteristics;
    status = ntwtls_register(process, &info, &index);
    if (status != NTWTLS_OK) return status;
    status = ntwtls_thread_init(process, thread);
    if (status != NTWTLS_OK) return status;
    if (slot_out) *slot_out = ntwtls_slot(thread, index);
    if (!execute) return NTWTLS_OK;
    return ntwtls_call(process, thread, NTWTLS_PROCESS_ATTACH);
}
