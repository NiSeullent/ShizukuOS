/* SPDX-License-Identifier: GPL-2.0-only */
#define SHZ_HOST_TEST
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../dlls/ucrtbase/crtint.h"
static int error, invalid, fail, calls;
static unsigned supplied;
int *crt_errno_ptr(void) { return &error; }
void crt_invalid_parameter(void) { ++invalid; }
int shz_random_bytes(void *out, size_t size)
{
    ++calls;
    if (size != sizeof supplied) abort();
    memcpy(out, &supplied, size);
    return !fail;
}
#include "../dlls/ucrtbase/ucrt_office_random.c"
#define VERIFY(c) do { ++checks; if (!(c)) { fprintf(stderr,"FAIL: line %d: %s\n",__LINE__,#c); abort(); } } while(0)
int main(void)
{
    unsigned value, checks = 0;
    error = 123; supplied = 0; value = 99;
    VERIFY(rand_s(&value) == 0 && value == 0 && error == 123);
    supplied = (unsigned)-1;
    VERIFY(rand_s(&value) == 0 && value == (unsigned)-1);
    supplied = 0xaabbccdd; fail = 1;
    VERIFY(rand_s(&value) == CRT_EINVAL && value == 0 && error == CRT_EINVAL);
    VERIFY(calls == 3 && invalid == 0);
    VERIFY(rand_s(NULL) == CRT_EINVAL && error == CRT_EINVAL && invalid == 1 && calls == 3);
    printf("OFFICE-RANDOM-HOST: %u checks passed; exact entropy buffer, full range, partial backend failure, null validation\n",checks);
    return 0;
}
