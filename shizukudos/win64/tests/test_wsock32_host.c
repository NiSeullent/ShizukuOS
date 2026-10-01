/* SPDX-License-Identifier: GPL-2.0-only
 * Production decoder on fixed provider-format fixtures, all buffer alignments,
 * malformed length/output contracts and bounded randomized provider data. */
#define SHZ_WSOCK32_HOST_TEST
#include "../dlls/wsock32/wsock32.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
static int last_error;
void WINAPI WSASetLastError(int error) { last_error = error; }
#define CHECK(c) do { ++checks; if (!(c)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); exit(1); } } while (0)

/* IPv4 port 8080 and 127.0.0.1; IPv6 port 443 and ::1. Literal independently
 * specified bytes include the length prefix and a different address family. */
static const unsigned char ipv4[] = {16,0,0,0, 2,0,0x1f,0x90, 127,0,0,1, 0,0,0,0,0,0,0,0};
static const unsigned char ipv6[] = {28,0,0,0, 23,0,1,0xbb, 0,0,0,0,
                                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1, 0,0,0,0};

static void rejected(void *buffer, DWORD receive, DWORD local_size, DWORD remote_size)
{
    struct sockaddr *local = (void *)1, *remote = (void *)1;
    int local_n = 123, remote_n = 456;
    last_error = 0;
    GetAcceptExSockaddrs(buffer, receive, local_size, remote_size, &local, &local_n, &remote, &remote_n);
    CHECK(!local && !remote && !local_n && !remote_n && last_error == WSAEINVAL);
}

int main(void)
{
    unsigned char storage[320], *buffer;
    struct sockaddr *local, *remote;
    int local_n, remote_n;
    unsigned alignment, omitted, i;
    uint32_t rng = 0x762efd91;
    for (alignment = 0; alignment < 16; ++alignment) {
        memset(storage, 0xa5, sizeof storage);
        buffer = storage + alignment;
        memcpy(buffer + 7, ipv4, sizeof ipv4);
        memcpy(buffer + 7 + 32, ipv6, sizeof ipv6);
        local = remote = NULL; local_n = remote_n = -1; last_error = 0x3456;
        GetAcceptExSockaddrs(buffer, 7, 32, 44, &local, &local_n, &remote, &remote_n);
        CHECK((void *)local == buffer + 11 && local_n == 16);
        CHECK((void *)remote == buffer + 43 && remote_n == 28);
        CHECK(!memcmp(local, ipv4 + 4, 16) && !memcmp(remote, ipv6 + 4, 28));
        CHECK(last_error == 0x3456);              /* successful void API does not clear caller error */
        for (omitted = 1; omitted < 16; ++omitted) {
            local = remote = (void *)1; local_n = remote_n = 99; last_error = 0;
            GetAcceptExSockaddrs(buffer, 7, 32, 44, omitted & 1 ? NULL : &local,
                                omitted & 2 ? NULL : &local_n, omitted & 4 ? NULL : &remote,
                                omitted & 8 ? NULL : &remote_n);
            CHECK(last_error == WSAEINVAL);
            CHECK((omitted & 1 || !local) && (omitted & 2 || !local_n) &&
                  (omitted & 4 || !remote) && (omitted & 8 || !remote_n));
        }
        for (i = 0; i < 6; ++i) {
            rejected(buffer, 7, i, 44);
            rejected(buffer, 7, 32, i);
        }
        buffer[7] = 0; rejected(buffer, 7, 32, 44);
        buffer[7] = 1; rejected(buffer, 7, 32, 44);
        buffer[7] = 29; rejected(buffer, 7, 32, 44);
        memset(buffer + 7, 0xff, 4); rejected(buffer, 7, 32, 44);
        memcpy(buffer + 7, ipv4, sizeof ipv4);
        buffer[39] = 41; rejected(buffer, 7, 32, 44);
        memset(buffer + 39, 0xff, 4); rejected(buffer, 7, 32, 44);
    }
    rejected(NULL, 0, 32, 32);
    rejected((void *)(UINTPTR_MAX - 3), 7, 32, 44);
    rejected((void *)(UINTPTR_MAX - 10), 0, 32, 44);
    rejected((void *)(UINTPTR_MAX - 40), 0, 32, 44);
    /* Undersized segments reject before reading even an inaccessible address. */
    rejected((void *)1, 0, 3, 32);
    rejected((void *)1, 0, 32, 3);
    for (i = 0; i < 100000; ++i) {
        DWORD receive, local_size, remote_size;
        unsigned k;
        for (k = 0; k < sizeof storage; ++k) {
            rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
            storage[k] = (unsigned char)rng;
        }
        receive = rng & 31; local_size = rng >> 5 & 63; remote_size = rng >> 11 & 63;
        local = remote = NULL; local_n = remote_n = 0; last_error = 0;
        GetAcceptExSockaddrs(storage, receive, local_size, remote_size, &local, &local_n, &remote, &remote_n);
        if (last_error) {
            CHECK(last_error == WSAEINVAL && !local && !remote && !local_n && !remote_n);
        } else {
            CHECK(local_n >= 2 && remote_n >= 2 && (unsigned)local_n <= local_size - 4 &&
                  (unsigned)remote_n <= remote_size - 4);
            CHECK((void *)local == storage + receive + 4 && (void *)remote == storage + receive + local_size + 4);
        }
    }
    printf("WSOCK32-HOST: %u checks passed\n", checks);
    return 0;
}
