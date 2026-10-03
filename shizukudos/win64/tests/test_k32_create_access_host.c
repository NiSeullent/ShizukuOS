/* SPDX-License-Identifier: GPL-2.0-only
 * Host regression: kernel32 CreateFileW native desired-access translation versus
 * the unchanged Kernel64 sysfile.c delete-on-close admission guard (extracted
 * verbatim by test_k32_create_access_host.py). Not a guest file-system test:
 * final-close deletion and console-handle rejection still need the T_K32_SYS run.
 */
#include <stdint.h>
#include <stdio.h>
#include "k32_create_access.h"
#include "nt_file_rights.h"

#define STATUS_SUCCESS 0
#define STATUS_ACCESS_DENIED ((int32_t)0xC0000022)
#define FILE_SUPERSEDE 0
#define FILE_OPEN 1
#define FILE_CREATE 2
#define FILE_OVERWRITE 4
#define FILE_OVERWRITE_IF 5
#define FILE_DELETE_ON_CLOSE 0x1000
#define GENERIC_WRITE 0x40000000u
#define GENERIC_READ 0x80000000u
#define GENERIC_ALL 0x10000000u
#define DELETE_ACCESS 0x10000u
#define FILE_WRITE_DATA 0x0002u

static int32_t sysfile_admission(uint32_t a2, uint32_t disposition, uint32_t options)
{
    a2 = shz_file_access(a2);
/* @SYSFILE_GUARD@ */
    return STATUS_SUCCESS;
}

static unsigned checks, failures;
#define EXPECT(c) do { ++checks; if (!(c)) { ++failures; fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

int main(void)
{
    const uint32_t rw = GENERIC_READ | GENERIC_WRITE;
    /* T_K32_SYS: CreateFileA(k32con.txt, GENERIC_READ|GENERIC_WRITE, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE). */
    uint32_t native = k32_create_native_access(rw, K32_FILE_FLAG_DELETE_ON_CLOSE);
    EXPECT(native == (rw | K32_NT_DELETE | K32_NT_SYNCHRONIZE | K32_NT_FILE_READ_ATTRIBUTES));
    EXPECT(sysfile_admission(native, FILE_OVERWRITE_IF, FILE_DELETE_ON_CLOSE) == STATUS_SUCCESS);
    EXPECT(sysfile_admission(native, FILE_CREATE, FILE_DELETE_ON_CLOSE) == STATUS_SUCCESS);
    /* Without the flag no DELETE right is added (no silent elevation). */
    native = k32_create_native_access(rw, 0);
    EXPECT(!(native & K32_NT_DELETE));
    EXPECT(native == (rw | K32_NT_SYNCHRONIZE | K32_NT_FILE_READ_ATTRIBUTES));
    EXPECT(k32_create_native_access(GENERIC_READ, 0x40000000u /* OVERLAPPED */) == (GENERIC_READ | 0x00100080u));
    /* Raw native delete-on-close without DELETE remains rejected before mutation. */
    EXPECT(sysfile_admission(rw | 0x00100080u, FILE_OVERWRITE_IF, FILE_DELETE_ON_CLOSE) == STATUS_ACCESS_DENIED);
    EXPECT(sysfile_admission(rw | 0x00100080u, FILE_OPEN, FILE_DELETE_ON_CLOSE) == STATUS_ACCESS_DENIED);
    EXPECT(sysfile_admission(rw | 0x00100080u, FILE_SUPERSEDE, 0) == STATUS_ACCESS_DENIED);
    /* Read-only delete-on-close open still needs no write right; overwrite still needs write. */
    native = k32_create_native_access(GENERIC_READ, K32_FILE_FLAG_DELETE_ON_CLOSE);
    EXPECT(sysfile_admission(native, FILE_OPEN, FILE_DELETE_ON_CLOSE) == STATUS_SUCCESS);
    EXPECT(sysfile_admission(native, FILE_OVERWRITE_IF, FILE_DELETE_ON_CLOSE) == STATUS_ACCESS_DENIED);
    printf("k32 create access: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
