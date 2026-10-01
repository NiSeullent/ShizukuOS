#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the exact production environment functions against a bounded host heap.

Tests observable block layout, old-block lifetime, case replacement, all drive
letters, ANSI dispatch, invalid names and allocation failure. This does not
prove guest filesystem/current-directory behavior: t_drive_environment.c does.
Use --source with a saved pre-change k32_mem.c for a counterfactual regression.
"""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

ADAPTER = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint16_t WCHAR;
typedef const WCHAR *LPCWSTR;
typedef WCHAR *LPWSTR;
typedef WCHAR *LPWCH;
typedef const char *LPCSTR;
typedef char *LPSTR;
typedef uint32_t DWORD;
typedef int BOOL;
#define K32API
#define WINAPI
#define TRUE 1
#define FALSE 0
#define ERROR_INVALID_PARAMETER 87
#define ERROR_ENVVAR_NOT_FOUND 203
#define ERROR_NOT_ENOUGH_MEMORY 8
static DWORD last_error;
static unsigned fail_allocation, checks, failures;
static void *allocations[256];
static unsigned allocation_count;
static WCHAR initial[] = L"ROOT=unchanged\0OTHER=retained\0";
static WCHAR *g_env;
static size_t k32_wlen(const WCHAR *p) { size_t n = 0; if (p) while (p[n]) ++n; return n; }
static void shz_set_last_error(DWORD e) { last_error = e; }
static void *ShzProcessHeap(void) { return NULL; }
static void *RtlAllocateHeap(void *heap, unsigned flags, size_t n) {
    void *p; (void)heap; (void)flags;
    if (fail_allocation) return NULL;
    if (allocation_count == 256) abort();
    p = malloc(n); if (!p) abort();
    memset(p, 0xcc, n); allocations[allocation_count++] = p; return p;
}
static WCHAR *env_block(void) { return g_env ? g_env : initial; }
/* ASCII-only adapters isolate the environment contract from codec internals. */
static int k32_utf8_to_wide(const char *p, int n, WCHAR *out, int cap) {
    int i; if (!p) return 0; if (n < 0) n = (int)strlen(p) + 1;
    if (n > cap) return 0; for (i = 0; i < n; ++i) out[i] = (unsigned char)p[i]; return n;
}
static int k32_wide_to_utf8(const WCHAR *p, int n, char *out, int cap) {
    int i; if (n > cap) return 0; for (i = 0; i < n; ++i) out[i] = (char)p[i]; return n;
}
static int weq(const WCHAR *a, const WCHAR *b) {
    while (*a && *a == *b) { ++a; ++b; } return *a == *b;
}
static unsigned count_drive(const WCHAR *env, WCHAR drive) {
    unsigned count = 0;
    for (; *env; env += k32_wlen(env) + 1)
        if (env[0] == '=' && (env[1] | 32) == (drive | 32) && env[2] == ':' && env[3] == '=') ++count;
    return count;
}
#define CHECK(cond) do { ++checks; if (!(cond)) { ++failures; fprintf(stderr, "FAIL line %d\n", __LINE__); } } while (0)
'''

HARNESS = r'''
int main(void) {
    WCHAR value[64], name[] = L"=A:", lower[] = L"=a:";
    WCHAR *old, *unchanged;
    const WCHAR *invalid[] = {L"bad=name", L"==D:", L"=D:=x", L"=D:=", L""};
    DWORD n;
    unsigned i;
    CHECK(SetEnvironmentVariableW(L"REGULAR", L"ordinary=value"));
    CHECK(GetEnvironmentVariableW(L"regular", value, 64) == 14 && weq(value, L"ordinary=value"));
    for (i = 0; i < 26; ++i) {
        name[1] = (WCHAR)('A' + i); lower[1] = (WCHAR)('a' + i);
        last_error = 0xdead;
        CHECK(SetEnvironmentVariableW(name, L"drive-one") && last_error == 0xdead);
        CHECK(GetEnvironmentVariableW(lower, value, 64) == 9 && weq(value, L"drive-one"));
        old = GetEnvironmentStringsW();
        CHECK(count_drive(old, name[1]) == 1);
        CHECK(SetEnvironmentVariableW(lower, L"drive-two=tail"));
        CHECK(count_drive(GetEnvironmentStringsW(), name[1]) == 1 && count_drive(old, name[1]) == 1);
        CHECK(GetEnvironmentVariableW(name, value, 64) == 14 && weq(value, L"drive-two=tail"));
        CHECK(FreeEnvironmentStringsW(old));
        last_error = 0x123;
        CHECK(GetEnvironmentVariableW(name, NULL, 0) == 15 && last_error == 0x123);
        value[0] = 0xabcd;
        CHECK(GetEnvironmentVariableW(name, value, 1) == 15 && value[0] == 0xabcd);
        unchanged = env_block();
        fail_allocation = 1; last_error = 0;
        CHECK(!SetEnvironmentVariableW(name, L"lost") && last_error == ERROR_NOT_ENOUGH_MEMORY && env_block() == unchanged);
        fail_allocation = 0;
        CHECK(GetEnvironmentVariableW(name, value, 64) == 14 && weq(value, L"drive-two=tail"));
        CHECK(SetEnvironmentVariableW(name, L""));
        value[0] = 0xface; last_error = 0x123;
        CHECK(GetEnvironmentVariableW(name, value, 64) == 0 && value[0] == 0 && last_error == 0x123);
        CHECK(SetEnvironmentVariableW(name, NULL));
        last_error = 0;
        CHECK(GetEnvironmentVariableW(name, value, 64) == 0 && last_error == ERROR_ENVVAR_NOT_FOUND && count_drive(env_block(), name[1]) == 0);
    }
    for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
        old = env_block(); last_error = 0;
        CHECK(!SetEnvironmentVariableW(invalid[i], L"bad") && last_error == ERROR_INVALID_PARAMETER && env_block() == old);
    }
    /* Preserve the implementation's deliberately bounded hidden-name support;
     * Wine/Windows allow additional leading-'=' names, not covered here. */
    CHECK(!SetEnvironmentVariableW(L"=other", L"unsupported"));
    CHECK(!SetEnvironmentVariableW(L"=1:", L"unsupported"));
    CHECK(SetEnvironmentVariableA("=D:", "D:\\steam"));
    CHECK(GetEnvironmentVariableW(L"=d:", value, 64) == 8 && weq(value, L"D:\\steam"));
    { char a[64]; n = GetEnvironmentVariableA("=d:", a, 64); CHECK(n == 8 && !strcmp(a, "D:\\steam")); }
    CHECK(SetEnvironmentVariableA("=D:", NULL));
    CHECK(GetEnvironmentVariableW(L"ROOT", value, 64) == 9 && weq(value, L"unchanged"));
    CHECK(GetEnvironmentVariableW(L"OTHER", value, 64) == 8 && weq(value, L"retained"));
    CHECK(GetEnvironmentVariableW(L"REGULAR", value, 64) == 14 && weq(value, L"ordinary=value"));
    for (i = 0; i < allocation_count; ++i) free(allocations[i]);
    printf("DRIVE_ENV_HOST: %u checks, %u failed\n", checks, failures);
    return failures != 0;
}
'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1] / "kernel32/k32_mem.c")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    raw = args.source.read_bytes()
    source = raw.decode()
    start = source.index("K32API LPWCH WINAPI GetEnvironmentStringsW")
    end = source.index("K32API VOID WINAPI GetStartupInfoW", start)
    with tempfile.TemporaryDirectory(prefix="win98-drive-env-") as temporary:
        folder = Path(temporary)
        c = folder / "production-env.c"
        c.write_text(ADAPTER + "\n" + source[start:end] + "\n" + HARNESS)
        exe = folder / "test"
        flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation", "-fshort-wchar"]
        if args.sanitize:
            flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        subprocess.run([args.cc, *flags, str(c), "-o", str(exe)], check=True)
        result = subprocess.run([str(exe)], text=True, capture_output=True)
        print(result.stdout, end="")
        print(result.stderr, end="")
        print(json.dumps({"source": str(args.source.resolve()), "sha256": hashlib.sha256(raw).hexdigest(),
                          "compiler": args.cc, "sanitize": args.sanitize, "exit_code": result.returncode}))
        return result.returncode

if __name__ == "__main__":
    raise SystemExit(main())
