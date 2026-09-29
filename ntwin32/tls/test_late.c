/* SPDX-License-Identifier: GPL-2.0-only */
#include "tls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void *alloc(void *user, size_t bytes) { (void)user; return malloc(bytes); }
static void release(void *user, void *memory, size_t bytes) { (void)user; (void)bytes; free(memory); }
static int saw;
static void NTWTLS_CALLBACK cb(void *module, uint32_t reason, void *reserved) {
    (void)module; (void)reserved;
    if (reason == NTWTLS_PROCESS_ATTACH) saw = 1;
}
int main(void) {
    unsigned char raw[4] = {1, 2, 3, 4};
    uint32_t index_slot = 99, late_slot = 77, index = 9, late = 9;
    ntwtls_process *process = malloc(ntwtls_process_size());
    ntwtls_thread *thread = malloc(ntwtls_thread_size());
    ntwtls_services services = {0, alloc, release};
    ntwtls_callback callbacks[2] = {cb, 0};
    ntwtls_image image = {raw, raw, 4, 0, &index_slot, 0, 0};
    ntwtls_image added = {raw, raw, 4, 0, &late_slot, callbacks, 0};
    if (!process || !thread) return 2;
    memset(process, 0, ntwtls_process_size());
    memset(thread, 0, ntwtls_thread_size());
    if (ntwtls_process_init(process, &services) != NTWTLS_OK) return 3;
    if (ntwtls_register(process, &image, &index) != NTWTLS_OK || index != 0) return 4;
    if (ntwtls_thread_init(process, thread) != NTWTLS_OK) return 5;
    if (ntwtls_register(process, &added, &late) != NTWTLS_BUSY) return 6;
    if (ntwtls_register_late(process, &added, &late) != NTWTLS_OK || late != 1) return 7;
    if (ntwtls_thread_extend(process, thread) != NTWTLS_OK) return 8;
    if (!ntwtls_slot(thread, 1) || ((unsigned char *)ntwtls_slot(thread, 1))[0] != 1) return 9;
    if (ntwtls_call(process, thread, NTWTLS_PROCESS_ATTACH) != NTWTLS_OK || !saw) return 10;
    printf("{\"passed\":true,\"tls_late\":true}\n");
    return 0;
}
