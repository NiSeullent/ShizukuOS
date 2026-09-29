/* SPDX-License-Identifier: GPL-2.0-only
 * Portable static-TLS contract. This is not a claim that the Win98 loader
 * calls it, and it does not strip or rewrite an IMAGE_TLS_DIRECTORY.
 * See PROVENANCE.md.
 */
#ifndef NTW_TLS_H
#define NTW_TLS_H
#include <stddef.h>
#include <stdint.h>
#define NTWTLS_MAX_MODULES 64u
#define NTWTLS_MAX_CALLBACKS 32u
#define NTWTLS_MAX_BLOCK (16u * 1024u * 1024u)
#define NTWTLS_PROCESS_DETACH 0u
#define NTWTLS_PROCESS_ATTACH 1u
#define NTWTLS_THREAD_ATTACH 2u
#define NTWTLS_THREAD_DETACH 3u
enum ntwtls_status { NTWTLS_OK = 0, NTWTLS_INVALID = -1, NTWTLS_NO_MEMORY = -2,
    NTWTLS_LIMIT = -3, NTWTLS_BUSY = -4 };
#if defined(__i386__)
#define NTWTLS_CALLBACK __attribute__((stdcall))
#else
#define NTWTLS_CALLBACK
#endif
typedef void (NTWTLS_CALLBACK *ntwtls_callback)(void *module, uint32_t reason, void *reserved);
typedef struct ntwtls_services {
    void *user;
    void *(*allocate)(void *user, size_t bytes);
    void (*release)(void *user, void *memory, size_t bytes);
} ntwtls_services;
typedef struct ntwtls_image {
    void *module;
    const uint8_t *raw;
    uint32_t raw_bytes;
    uint32_t zero_fill;
    uint32_t *index_slot;
    const ntwtls_callback *callbacks;
    uint32_t characteristics;
} ntwtls_image;
typedef struct ntwtls_process ntwtls_process;
typedef struct ntwtls_thread ntwtls_thread;
int ntwtls_process_init(ntwtls_process *process, const ntwtls_services *services);
int ntwtls_register(ntwtls_process *process, const ntwtls_image *image, uint32_t *out_index);
int ntwtls_register_late(ntwtls_process *process, const ntwtls_image *image, uint32_t *out_index);
int ntwtls_thread_init(ntwtls_process *process, ntwtls_thread *thread);
int ntwtls_thread_extend(ntwtls_process *process, ntwtls_thread *thread);
int ntwtls_call(ntwtls_process *process, ntwtls_thread *thread, uint32_t reason);
int ntwtls_thread_fini(ntwtls_process *process, ntwtls_thread *thread);
uint32_t ntwtls_module_count(const ntwtls_process *process);
void *ntwtls_slot(const ntwtls_thread *thread, uint32_t index);
size_t ntwtls_process_size(void);
size_t ntwtls_thread_size(void);
#endif
