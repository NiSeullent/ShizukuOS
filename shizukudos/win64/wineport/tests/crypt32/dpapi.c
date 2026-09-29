/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku checks of CryptProtectData / CryptUnprotectData and CryptProtectMemory / CryptUnprotectMemory as ported:
 * round trips, the effect of entropy and tampering, block-size rules, and that CROSS_PROCESS memory protection uses
 * one key for every process of the boot while SAME_PROCESS keys differ between processes (checked in a child process).
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "wincrypt.h"
#include "wine/test.h"

static const char secret[] = "the Shizuku wineport DPAPI secret";

static void test_protect_data(void)
{
    DATA_BLOB in = { sizeof(secret), (BYTE *)secret }, out = { 0 }, back = { 0 }, ent = { 5, (BYTE *)"salty" };
    DATA_BLOB wrong = { 5, (BYTE *)"SALTY" };
    WCHAR *desc = NULL;
    BOOL ret;

    ret = CryptProtectData(&in, L"wineport", &ent, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out);
    ok(ret && out.cbData > sizeof(secret), "CryptProtectData failed %08lx\n", GetLastError());
    if (!ret) return;
    {
        DWORD i;
        BOOL found = FALSE;
        for (i = 0; i + sizeof(secret) - 1 <= out.cbData; i++)
            if (!memcmp(out.pbData + i, secret, sizeof(secret) - 1)) found = TRUE;
        ok(!found, "the plaintext must not appear in the blob\n");
    }
    ret = CryptUnprotectData(&out, &desc, &ent, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &back);
    ok(ret && back.cbData == sizeof(secret) && !memcmp(back.pbData, secret, sizeof(secret)), "round trip failed %08lx\n",
       GetLastError());
    ok(desc && !wcscmp(desc, L"wineport"), "description %s\n", wine_dbgstr_w(desc));
    LocalFree(desc);
    LocalFree(back.pbData);
    SetLastError(0xdeadbeef);
    ok(!CryptUnprotectData(&out, NULL, &wrong, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &back), "wrong entropy must fail\n");
    SetLastError(0xdeadbeef);
    ok(!CryptUnprotectData(&out, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &back), "missing entropy must fail\n");
    out.pbData[out.cbData - 30] ^= 0x40;
    SetLastError(0xdeadbeef);
    ok(!CryptUnprotectData(&out, NULL, &ent, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &back), "a tampered blob must fail\n");
    LocalFree(out.pbData);
}

static void hex(const BYTE *b, DWORD n, char *out)
{
    DWORD i;
    for (i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
}

static void unhex(const char *s, BYTE *b, DWORD n)
{
    DWORD i;
    unsigned v;
    for (i = 0; i < n; i++) { sscanf(s + 2 * i, "%2x", &v); b[i] = (BYTE)v; }
}

static void test_protect_memory(void)
{
    BYTE buf[16], orig[16], same[16];
    char cmd[MAX_PATH + 100], **argv, a[40], b[40];
    PROCESS_INFORMATION pi;
    STARTUPINFOA si = { sizeof(si) };
    DWORD i;

    for (i = 0; i < sizeof(buf); i++) orig[i] = (BYTE)(i * 7 + 1);
    memcpy(buf, orig, sizeof(buf));
    ok(CryptProtectMemory(buf, sizeof(buf), CRYPTPROTECTMEMORY_SAME_PROCESS), "protect failed %08lx\n", GetLastError());
    ok(memcmp(buf, orig, sizeof(buf)), "protected memory must differ from the plaintext\n");
    memcpy(same, buf, sizeof(buf));
    ok(CryptUnprotectMemory(buf, sizeof(buf), CRYPTPROTECTMEMORY_SAME_PROCESS) && !memcmp(buf, orig, sizeof(buf)),
       "same-process round trip failed\n");

    SetLastError(0xdeadbeef);
    ok(!CryptProtectMemory(buf, 20, CRYPTPROTECTMEMORY_SAME_PROCESS) && GetLastError() == ERROR_INVALID_PARAMETER,
       "a size that is not a multiple of CRYPTPROTECTMEMORY_BLOCK_SIZE must fail (%lu)\n", GetLastError());

    memcpy(buf, orig, sizeof(buf));
    ok(CryptProtectMemory(buf, sizeof(buf), CRYPTPROTECTMEMORY_CROSS_PROCESS), "cross-process protect %08lx\n",
       GetLastError());
    ok(memcmp(buf, same, sizeof(buf)), "cross-process and same-process keys differ\n");

    /* the child must decrypt (16-byte samples: the Shizuku kernel limits command lines to 259 characters) */
    /* the child must decrypt the CROSS_PROCESS data and must not decrypt this process's SAME_PROCESS data */
    hex(buf, sizeof(buf), a);
    hex(same, sizeof(same), b);
    winetest_get_mainargs(&argv);
    sprintf(cmd, "\"%s\" dpapi child %s %s", argv[0], a, b);
    ok(CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi), "CreateProcess %lu\n", GetLastError());
    winetest_wait_child_process(&pi);
}

static void child(const char *cross, const char *same)
{
    BYTE buf[16], orig[16];
    DWORD i;
    for (i = 0; i < sizeof(buf); i++) orig[i] = (BYTE)(i * 7 + 1);
    unhex(cross, buf, sizeof(buf));
    ok(CryptUnprotectMemory(buf, sizeof(buf), CRYPTPROTECTMEMORY_CROSS_PROCESS) && !memcmp(buf, orig, sizeof(buf)),
       "the child decrypts CROSS_PROCESS data of its parent\n");
    unhex(same, buf, sizeof(buf));
    CryptUnprotectMemory(buf, sizeof(buf), CRYPTPROTECTMEMORY_SAME_PROCESS);
    ok(memcmp(buf, orig, sizeof(buf)), "SAME_PROCESS data of another process must not decrypt\n");
}

START_TEST(dpapi)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);
    if (argc >= 5 && !strcmp(argv[2], "child"))
    {
        child(argv[3], argv[4]);
        return;
    }
    test_protect_data();
    test_protect_memory();
}
