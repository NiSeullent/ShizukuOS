/* SPDX-License-Identifier: GPL-2.0-only
 * Exact production ABI adapter with controlled existing _find*64 boundary.
 * Native guest test separately exercises the real filesystem enumerator.
 */
#define SHZ_HOST_TEST
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../dlls/ucrtbase/crtint.h"
#include "../dlls/ucrtbase/ucrt_office_find.h"
static int error, invalid, first_calls, next_calls, fail_error;
static unsigned long doserror;
static const char *wanted_spec;
static intptr_t wanted_handle;
static struct crt_finddata64 supplied;
int *crt_errno_ptr(void) { return &error; }
unsigned long *crt_doserrno_ptr(void) { return &doserror; }
void crt_invalid_parameter(void) { ++invalid; }
void *crt_memcpy(void *out, const void *in, size_t n) { return memcpy(out, in, n); }
intptr_t _findfirst64(const char *spec, struct crt_finddata64 *out)
{
    ++first_calls; if (spec != wanted_spec) abort();
    if (fail_error) { error = fail_error; doserror = 18; return -1; }
    memcpy(out, &supplied, sizeof *out); return wanted_handle;
}
int _findnext64(intptr_t handle, struct crt_finddata64 *out)
{
    ++next_calls; if (handle != wanted_handle) abort();
    if (fail_error) { error = fail_error; doserror = 18; return -1; }
    memcpy(out, &supplied, sizeof *out); return 0;
}
#include "../dlls/ucrtbase/ucrt_office_find.c"
static unsigned checks;
#define VERIFY(c) do { ++checks; if (!(c)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); abort(); } } while (0)
struct guarded { uint64_t before; struct crt_finddata64i32 data; uint64_t after; };
static void verify_record(const struct guarded *g)
{
    VERIFY(g->before == 0x12345678abcdef01ull && g->after == 0xfedcba9876543210ull);
    VERIFY(g->data.attrib == supplied.attrib && g->data.time_create == supplied.time_create &&
           g->data.time_access == supplied.time_access && g->data.time_write == supplied.time_write);
    VERIFY(g->data.size == (uint32_t)supplied.size && !memcmp(g->data.name, supplied.name, 260));
}
int main(void)
{
    struct guarded g = {0x12345678abcdef01ull, {0}, 0xfedcba9876543210ull}, unchanged;
    unsigned n; uint64_t state = 0xabcdef1234567890ull;
    wanted_spec = "C:\\real-backend\\*.bin"; wanted_handle = (intptr_t)0x123456789abcdef0ull;
    supplied.attrib = 0x21; supplied.time_create = -1; supplied.time_access = 0x80000000ll;
    supplied.time_write = 0x123456789ll; supplied.size = 0x100000009ll;
    memset(supplied.name, 'x', 259); supplied.name[259] = 0;
    error = 123; VERIFY(_findfirst64i32(wanted_spec, &g.data) == wanted_handle && first_calls == 1 && error == 123);
    verify_record(&g); VERIFY(g.data.size == 9);
    for (n = 0; n < 1000; ++n) {
        state = state * 6364136223846793005ull + 1; supplied.size = (long long)state;
        supplied.time_create = (long long)(state ^ 0x5555555555555555ull);
        supplied.time_access = (long long)(state ^ 0xaaaaaaaaaaaaaaaaull); supplied.time_write = (long long)state;
        VERIFY(!_findnext64i32(wanted_handle, &g.data)); verify_record(&g);
    }
    unchanged = g; fail_error = CRT_ENOENT;
    VERIFY(_findfirst64i32(wanted_spec, &g.data) == -1 && error == CRT_ENOENT && doserror == 18 && !memcmp(&g, &unchanged, sizeof g));
    VERIFY(_findnext64i32(wanted_handle, &g.data) == -1 && error == CRT_ENOENT && !memcmp(&g, &unchanged, sizeof g));
    fail_error = CRT_EBADF;
    VERIFY(_findnext64i32(wanted_handle, &g.data) == -1 && error == CRT_EBADF && !memcmp(&g, &unchanged, sizeof g));
    first_calls = next_calls = invalid = 0; fail_error = 0;
    VERIFY(_findfirst64i32(NULL, &g.data) == -1 && error == CRT_EINVAL && invalid == 1 && !first_calls);
    VERIFY(_findfirst64i32(wanted_spec, NULL) == -1 && error == CRT_EINVAL && invalid == 2 && !first_calls);
    VERIFY(_findnext64i32(wanted_handle, NULL) == -1 && error == CRT_EINVAL && invalid == 3 && !next_calls);
    VERIFY(!memcmp(&g, &unchanged, sizeof g));
    printf("OFFICE-FIND-HOST: %u checks passed; exact ABI, 64-bit times, low32 sizes, unchanged failed output, full handle and error propagation\n", checks);
    return 0;
}
