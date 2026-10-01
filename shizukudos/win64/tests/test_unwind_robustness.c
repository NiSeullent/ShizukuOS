/* SPDX-License-Identifier: GPL-2.0-only
 * Host regressions for malformed records; reuse the existing OS stubs and fixtures.
 * Compile with the real ntdll/unwind.c, never a second unwind implementation.
 */
#define main unwind_existing_main
#include "test_unwind.c"
#undef main

static void test_truncated_operand(void)
{
    uint8_t *m = calloc(1, 0x108);
    RUNTIME_FUNCTION fe = { 0, 0x100, 0x100 };
    CONTEXT c = {0};
    DWORD64 est = 123;
    PVOID hd = (PVOID)1;
    m[0x100] = 1; m[0x101] = 0xff; m[0x102] = 1;
    m[0x104] = 1; m[0x105] = 0x11; /* ALLOC_LARGE(info=1) claims only one of three slots */
    c.Rsp = (DWORD64)(uintptr_t)(stackbuf + 0x1000);
    c.Rip = 0x1234;
    RtlVirtualUnwind(0, (DWORD64)(uintptr_t)m, (DWORD64)(uintptr_t)m + 1, &fe, &c, &hd, &est, 0);
    CHECK("truncated operand stops the walk", c.Rip == 0 && est == 0 && hd == 0);
    free(m);
}

int main(void)
{
    stackbuf = mmap(0, STACK_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stackbuf == MAP_FAILED) return 2;
    test_truncated_operand();
    printf("unwind robustness: %d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
