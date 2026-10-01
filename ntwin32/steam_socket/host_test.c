/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "accept_buffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__unix__)
#include <sys/mman.h>
#include <unistd.h>
#endif

static unsigned checks;
#define CHECK(c) do { ++checks; if (!(c)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); exit(1); } } while (0)

static void put32(uint8_t *p, uint32_t n)
{
    p[0] = (uint8_t)n; p[1] = (uint8_t)(n >> 8);
    p[2] = (uint8_t)(n >> 16); p[3] = (uint8_t)(n >> 24);
}

static void block(uint8_t *p, uint16_t family, uint32_t n)
{
    uint32_t i;
    put32(p, n);
    for (i = 0; i < n; ++i) p[4 + i] = (uint8_t)(i + 1);
    p[4] = (uint8_t)family; p[5] = (uint8_t)(family >> 8);
}

static void failure(enum ntw_accept_layout layout, const void *buffer, size_t cap,
                    uint32_t data, uint32_t local, uint32_t remote,
                    enum ntw_accept_status expected)
{
    struct ntw_accept_addresses out, before;
    memset(&out, 0xa5, sizeof(out));
    memcpy(&before, &out, sizeof(out));
    CHECK(ntw_accept_decode(layout, buffer, cap, data, local, remote, &out) == expected);
    CHECK(!memcmp(&out, &before, sizeof(out)));
}

static void valid_and_malformed(void)
{
    uint8_t allocation[192], before[192];
    uint8_t *b = allocation + 1; /* deliberately unaligned */
    struct ntw_accept_addresses out;
    unsigned i;
    memset(allocation, 0xc7, sizeof(allocation));
    block(b + 7, NTW_ACCEPT_AF_INET, 16);
    block(b + 7 + 48, NTW_ACCEPT_AF_INET, 16);
    memcpy(before, allocation, sizeof(before));
    CHECK(ntw_accept_decode(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 87, 7, 48, 32, &out) == NTW_ACCEPT_OK);
    CHECK(out.local.bytes == b + 11 && out.remote.bytes == b + 59);
    CHECK(out.local.length == 16 && out.remote.length == 16);
    CHECK(out.local.family == 2 && out.remote.family == 2);
    CHECK(out.local.bytes[2] == 3 && out.remote.bytes[7] == 8);
    CHECK(!memcmp(allocation, before, sizeof(before)));
    /* Every byte truncation of the complete declared operation is rejected. */
    for (i = 0; i < 87; ++i)
        failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, i, 7, 48, 32, NTW_ACCEPT_TRUNCATED);
    failure(NTW_ACCEPT_LAYOUT_UNKNOWN, b, 87, 7, 48, 32, NTW_ACCEPT_PROVIDER_LAYOUT);
    failure((enum ntw_accept_layout)99, b, 87, 7, 48, 32, NTW_ACCEPT_PROVIDER_LAYOUT);
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, NULL, 87, 7, 48, 32, NTW_ACCEPT_ARGUMENT);
    CHECK(ntw_accept_decode(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 87, 7, 48, 32, NULL) == NTW_ACCEPT_ARGUMENT);
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 87, UINT32_MAX, 1, 32, NTW_ACCEPT_LENGTH_OVERFLOW);
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 87, UINT32_MAX - 32, 32, 1, NTW_ACCEPT_LENGTH_OVERFLOW);
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 87, 7, 0, 32, NTW_ACCEPT_ADDRESS_LENGTH);
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 87, 7, 4, 32, NTW_ACCEPT_ADDRESS_LENGTH);
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 87, 7, 5, 32, NTW_ACCEPT_ADDRESS_LENGTH);
    put32(b + 7, UINT32_MAX);
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 87, 7, 48, 32, NTW_ACCEPT_ADDRESS_LENGTH);
    put32(b + 7, 49);
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 87, 7, 48, 32, NTW_ACCEPT_ADDRESS_LENGTH);
    put32(b + 7, 15);
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 87, 7, 48, 32, NTW_ACCEPT_ADDRESS_LENGTH);
    put32(b + 7, 16); b[11] = 10; /* Linux AF_INET6 is NOT Windows AF_INET6 */
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 87, 7, 48, 32, NTW_ACCEPT_ADDRESS_FAMILY);
    block(b + 7, 2, 16);
    put32(b + 55, 0); /* malformed remote must not publish valid local */
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 87, 7, 48, 32, NTW_ACCEPT_ADDRESS_LENGTH);
    /* A +16 pointer would read padding, not these actual provider addresses. */
    block(b, 2, 16); block(b + 20, 2, 16);
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 40, 0, 20, 20, NTW_ACCEPT_RESERVATION);
    block(b, 23, 28); block(b + 44, 23, 28);
    CHECK(ntw_accept_decode(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 88, 0, 44, 44, &out) == NTW_ACCEPT_OK);
    CHECK(out.local.bytes == b + 4 && out.remote.bytes == b + 48);
    CHECK(out.local.family == 23 && out.remote.length == 28);
    CHECK(out.remote.bytes[27] == 28); /* preserve IPv6 scope-id bytes */
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 88, 0, 43, 44, NTW_ACCEPT_RESERVATION);
    put32(b, 16);
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 88, 0, 44, 44, NTW_ACCEPT_ADDRESS_LENGTH);
    /* Result may not alias the input allocation. No bytes change on rejection. */
    memcpy(before, allocation, sizeof(before));
    CHECK(ntw_accept_decode(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, allocation, sizeof(allocation), 0, 44, 44,
                            (struct ntw_accept_addresses *)(void *)allocation) == NTW_ACCEPT_ARGUMENT);
    CHECK(!memcmp(allocation, before, sizeof(before)));
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, SIZE_MAX, 0, 44, 44, NTW_ACCEPT_LENGTH_OVERFLOW);
}

static void guarded_reads(void)
{
#if defined(__unix__)
    long n = sysconf(_SC_PAGESIZE);
    uint8_t *area, *b;
    struct ntw_accept_addresses out;
    unsigned i;
    CHECK(n > 0);
    area = mmap(NULL, (size_t)n * 2, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(area != MAP_FAILED);
    CHECK(mprotect(area + n, (size_t)n, PROT_NONE) == 0);
    b = area + n - 64;
    memset(b, 0xff, 64);
    block(b, 2, 16); block(b + 32, 2, 16);
    CHECK(ntw_accept_decode(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, b, 64, 0, 32, 32, &out) == NTW_ACCEPT_OK);
    CHECK(out.remote.bytes + out.remote.length <= area + n);
    /* A zero-sized remote region starts AT the inaccessible page. */
    block(area + n - 32, 2, 16);
    failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, area + n - 32, 32, 0, 32, 0,
            NTW_ACCEPT_ADDRESS_LENGTH);
    for (i = 0; i < 64; ++i)
        failure(NTW_ACCEPT_LAYOUT_WINE_LENGTH32, area + n - i, i, 0, 32, 32, NTW_ACCEPT_TRUNCATED);
    CHECK(munmap(area, (size_t)n * 2) == 0);
#endif
}

int main(void)
{
    valid_and_malformed();
    guarded_reads();
    printf("AcceptEx Wine-layout decoder: %u checks PASS (host only)\n", checks);
    return 0;
}
