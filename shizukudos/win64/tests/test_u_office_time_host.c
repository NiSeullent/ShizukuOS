/* SPDX-License-Identifier: GPL-2.0-only */
#define SHZ_HOST_TEST
#define OFFICE_CALL
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
static unsigned checks;
#define OFFICE_CHECK(c, label) do { ++checks; if (!(c)) { \
    fprintf(stderr, "FAIL: line %d: %s\n", __LINE__, label); abort(); } } while (0)
#include "office_time_contract.h"

static int error_value, invalid_calls, allocation_failure, live_allocations;
int *crt_errno_ptr(void) { return &error_value; }
int *u_crt_errno_ptr(void) { return &error_value; }
void crt_invalid_parameter(void) { ++invalid_calls; }
void u_crt_invalid_parameter(void) { ++invalid_calls; }
void *crt_malloc(size_t size)
{
    void *p;
    if (allocation_failure) { error_value = CRT_ENOMEM; return NULL; }
    p = malloc(size);
    if (p) ++live_allocations;
    return p;
}
void crt_free(void *p) { if (p) { --live_allocations; free(p); } }
size_t crt_strlen(const char *s) { return strlen(s); }
void *crt_memcpy(void *out, const void *in, size_t n) { return memcpy(out, in, n); }
size_t u_crt_strftime_core(void *, size_t, int, const void *, int, const struct crt_tm *, long, const char *);
size_t office_c_strftime(char *out, size_t n, const char *format, const struct crt_tm *tm)
{ return u_crt_strftime_core(out, n, 0, format, 0, tm, 0, "UTC"); }
size_t office_c_wcsftime(wchar16 *out, size_t n, const wchar16 *format, const struct crt_tm *tm)
{ return u_crt_strftime_core(out, n, 1, format, 1, tm, 0, "UTC"); }
#define strftime office_c_strftime
#define wcsftime office_c_wcsftime
#include "../dlls/ucrtbase/ucrt_office_time.c"
#undef strftime
#undef wcsftime

int main(void)
{
    const struct office_time_api api = {
        _Getdays, _Getmonths, _W_Getdays, _W_Getmonths, _Gettnames, _W_Gettnames,
        _Strftime, _Wcsftime, crt_free, crt_errno_ptr
    };
    office_time_contract(&api);
    OFFICE_CHECK(live_allocations == 0, "all caller-owned allocations are releasable");
    OFFICE_CHECK(invalid_calls == 2, "each invalid weekday/directive invokes the invalid-parameter path exactly once");
    allocation_failure = 1; error_value = 0;
    OFFICE_CHECK(_Getdays() == NULL && error_value == CRT_ENOMEM, "weekday allocation failure remains a failure");
    OFFICE_CHECK(_Getmonths() == NULL, "month allocation failure remains a failure");
    OFFICE_CHECK(_W_Getdays() == NULL && _W_Getmonths() == NULL, "wide list allocation failures remain failures");
    OFFICE_CHECK(_Gettnames() == NULL && _W_Gettnames() == NULL && live_allocations == 0, "snapshot allocation failure leaks no block");
    printf("OFFICE-TIME-HOST: %u checks passed; owned snapshot ABI, caller-selected names/pictures, C locale, boundaries and failure\n", checks);
    return 0;
}
