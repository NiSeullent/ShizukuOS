/* SPDX-License-Identifier: GPL-2.0-only
 * Private Kernel64/ntdll loader protocol. These are not Windows NT APIs.
 * PREPARE writes a header followed by Count actual PEB entry addresses. ntdll
 * invokes callbacks while the images remain mapped, then COMMIT retires them.
 */
#ifndef SHZ_LOADER_PROTOCOL_H
#define SHZ_LOADER_PROTOCOL_H
#include <stdint.h>
#define SHZ_LDR_ADDREF 0u
#define SHZ_LDR_PIN 1u
#define SHZ_LDR_PREPARE 2u
#define SHZ_LDR_RETIRE_MAX 1024u
typedef struct {
    uint64_t Token;
    uint32_t Count, Reserved;
    uint64_t Entries[];
} shz_ldr_retire_buffer;
#endif
