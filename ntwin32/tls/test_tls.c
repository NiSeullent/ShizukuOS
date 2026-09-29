/* SPDX-License-Identifier: GPL-2.0-only
 * Host contract for static TLS slot init and callback order.
 */
#include "tls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int checks, failures;
static void expect(int cond, const char *text, int line) {
    ++checks;
    if (!cond) {
        fprintf(stderr, "line %d: %s\n", line, text);
        ++failures;
    }
}
#define C(x) expect((x), #x, __LINE__)
static void *allocate(void *user, size_t bytes) {
    int *fail = user;
    void *memory;
    if (fail && *fail) { *fail = 0; return NULL; }
    memory = malloc(bytes);
    C(memory != NULL);
    return memory;
}
static void release(void *user, void *memory, size_t bytes) {
    (void)user; (void)bytes;
    free(memory);
}
static unsigned calls;
static uint32_t seen_reason[8];
static void *seen_module[8];
static void *seen_reserved[8];
static void NTWTLS_CALLBACK record(void *module, uint32_t reason, void *reserved) {
    if (calls < 8) {
        seen_module[calls] = module;
        seen_reason[calls] = reason;
        seen_reserved[calls] = reserved;
    }
    ++calls;
}
int main(void) {
    ntwtls_process *process = calloc(1, ntwtls_process_size());
    ntwtls_thread *thread = calloc(1, ntwtls_thread_size());
    ntwtls_services services = {0, allocate, release};
    uint8_t raw[] = {0x11, 0x22, 0x33, 0x44};
    uint32_t index_a = 0xffffffffu, index_b = 0xffffffffu, observed = 99;
    ntwtls_callback callbacks_a[] = {record, record, 0};
    ntwtls_callback callbacks_b[] = {record, 0};
    ntwtls_image image;
    int marker = 1, sentinel = 7;
    uint8_t *block;
    C(process != NULL && thread != NULL);
    C(ntwtls_process_init(NULL, &services) == NTWTLS_INVALID);
    C(ntwtls_process_init(process, NULL) == NTWTLS_INVALID);
    C(ntwtls_process_init(process, &services) == NTWTLS_OK);
    memset(&image, 0, sizeof image);
    image.module = &marker;
    image.index_slot = &index_a;
    C(ntwtls_register(process, &image, &observed) == NTWTLS_INVALID && observed == 99);
    image.characteristics = 1;
    image.raw = raw;
    image.raw_bytes = 4;
    C(ntwtls_register(process, &image, &observed) == NTWTLS_INVALID);
    image.characteristics = 0;
    image.raw = NULL;
    C(ntwtls_register(process, &image, &observed) == NTWTLS_INVALID);
    image.raw = raw;
    image.raw_bytes = 4;
    image.zero_fill = 4;
    image.callbacks = callbacks_a;
    C(ntwtls_register(process, &image, &observed) == NTWTLS_OK && observed == 0 && index_a == 0);
    image.module = &sentinel;
    image.raw_bytes = 0;
    image.raw = NULL;
    image.zero_fill = 0;
    image.callbacks = callbacks_b;
    image.index_slot = &index_b;
    C(ntwtls_register(process, &image, &observed) == NTWTLS_OK && observed == 1 && index_b == 1);
    C(ntwtls_register(process, &image, &observed) == NTWTLS_INVALID);
    C(ntwtls_thread_init(process, thread) == NTWTLS_OK);
    C(ntwtls_register(process, &image, &observed) == NTWTLS_BUSY);
    block = ntwtls_slot(thread, 0);
    C(block && block[0] == 0x11 && block[1] == 0x22 && block[2] == 0x33 && block[3] == 0x44);
    C(block[4] == 0 && block[5] == 0 && block[6] == 0 && block[7] == 0);
    C(ntwtls_slot(thread, 1) == NULL);
    calls = 0;
    C(ntwtls_call(process, thread, NTWTLS_PROCESS_ATTACH) == NTWTLS_OK && calls == 3);
    C(seen_module[0] == &marker && seen_module[1] == &marker && seen_module[2] == &sentinel);
    C(seen_reason[0] == 1 && seen_reason[1] == 1 && seen_reason[2] == 1);
    C(seen_reserved[0] == NULL && seen_reserved[2] == NULL);
    calls = 0;
    C(ntwtls_call(process, thread, NTWTLS_THREAD_DETACH) == NTWTLS_OK && calls == 3 && seen_reason[0] == 3);
    C(ntwtls_call(process, thread, 4) == NTWTLS_INVALID);
    C(ntwtls_thread_fini(process, thread) == NTWTLS_OK);
    C(ntwtls_slot(thread, 0) == NULL);
    C(ntwtls_module_count(process) == 2);
    free(process);
    free(thread);
    if (failures) {
        fprintf(stderr, "{\"passed\":false,\"checks\":%d,\"failures\":%d}\n", checks, failures);
        return 1;
    }
    printf("{\"passed\":true,\"checks\":%d,\"callbacks\":%u,\"modules\":2,\"zero_fill\":4,"
           "\"callback_order\":[\"a\",\"a\",\"b\"]}\n", checks, calls);
    return 0;
}
