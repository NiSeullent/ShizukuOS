#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the production token-query branch and handle lookup with host memory fixtures.

This checks granted handle rights and reference/output handling; it does not
replace the real Win64 token/userenv guest tests.
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

KERNEL = Path(__file__).resolve().parents[1] / "kernel64"


def function_body(text, name):
    match = re.search(r"\b" + name + r"\([^;{}]*\)\s*\{", text)
    if not match:
        raise ValueError(f"missing production function: {name}")
    start = match.end() - 1
    depth = 1
    for end in range(start + 1, len(text)):
        depth += (text[end] == "{") - (text[end] == "}")
        if not depth:
            return text[start:end + 1]
    raise ValueError(f"unterminated production function: {name}")


def fixture_source():
    security = (KERNEL / "sysk32_sec.c").read_text()
    token = re.search(r"typedef struct shz_token_info \{.*?\} shz_token_info;", security, re.S).group(0)
    query = security.split("case SHZ_TOK_QUERY: {", 1)[1].split("case SHZ_TOK_SET:", 1)[0]
    lookup = function_body((KERNEL / "objects.c").read_text(), "handle_ref")
    return r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define STATUS_INVALID_HANDLE ((int32_t)0xc0000008)
#define STATUS_OBJECT_TYPE_MISMATCH ((int32_t)0xc0000024)
#define STATUS_SUCCESS 0
#define STATUS_ACCESS_DENIED ((int32_t)0xc0000022)
#define STATUS_INFO_LENGTH_MISMATCH ((int32_t)0xc0000004)
#define STATUS_ACCESS_VIOLATION ((int32_t)0xc0000005)
#define OB_TOKEN 12
typedef struct kobject { unsigned type, refs; struct { struct { void *t; } token; } u; } kobject_t;
typedef struct { kobject_t *obj; uint32_t access; } handle_entry_t;
typedef struct { unsigned handle_cap; handle_entry_t *handles; } process_t;
static uint64_t irq_save(void) { return 0; }
static void irq_restore(uint64_t ignored) { (void)ignored; }
static void ob_deref(kobject_t *object) { --object->refs; }
static unsigned copies;
static int copy_to_user(process_t *p, uint64_t dst, const void *src, uint64_t size)
{ (void)p; ++copies; if (!dst) return -1; memcpy((void *)(uintptr_t)dst, src, (size_t)size); return 0; }
''' + token + '\nint32_t handle_ref(process_t *p, uint64_t handle, uint32_t type, kobject_t **out, uint32_t *access)\n' + lookup + r'''
static int32_t query(process_t *p, uint64_t a2, uint64_t a3, uint64_t a4)
{
''' + query + r'''
#define VERIFY(condition) do { if (!(condition)) { fprintf(stderr,"failed line %d: %s\n",__LINE__,#condition); return 1; } } while (0)
int main(void)
{
    shz_token_info original = { .type=1, .integrity_rid=0x2000, .session=1, .id=47, .owner_pid=92 }, output;
    kobject_t object = { .type=OB_TOKEN, .refs=1 };
    handle_entry_t handles[1] = {{ &object, 8 }};
    process_t process = {1, handles};
    object.u.token.t=&original;
    memset(&output,0xa5,sizeof output);
    VERIFY(query(&process,4,(uint64_t)(uintptr_t)&output,sizeof output)==STATUS_SUCCESS);
    VERIFY(!memcmp(&output,&original,sizeof output) && object.refs==1 && copies==1);
    handles[0].access=0xf01ff;
    VERIFY(query(&process,4,(uint64_t)(uintptr_t)&output,sizeof output)==STATUS_SUCCESS);
    VERIFY(object.refs==1 && copies==2);
    const uint32_t denied[] = {0,2,4,0x10,0x10000000};
    for (unsigned i=0;i<sizeof denied/sizeof denied[0];++i) {
        handles[0].access=denied[i]; memset(&output,0xa5,sizeof output);
        shz_token_info before=output; unsigned before_copies=copies;
        VERIFY(query(&process,4,(uint64_t)(uintptr_t)&output,sizeof output)==STATUS_ACCESS_DENIED);
        VERIFY(!memcmp(&output,&before,sizeof output) && copies==before_copies && object.refs==1);
        VERIFY(query(&process,4,0,0)==STATUS_ACCESS_DENIED);
        VERIFY(copies==before_copies && object.refs==1);
    }
    handles[0].access=8;
    unsigned before_copies=copies;
    VERIFY(query(&process,4,0,sizeof output-1)==STATUS_INFO_LENGTH_MISMATCH);
    VERIFY(copies==before_copies && object.refs==1);
    VERIFY(query(&process,4,0,sizeof output)==STATUS_ACCESS_VIOLATION);
    VERIFY(copies==before_copies+1 && object.refs==1);
    const uint64_t invalid[] = {0,1,3,8,UINT64_MAX};
    for (unsigned i=0;i<sizeof invalid/sizeof invalid[0];++i) {
        VERIFY(query(&process,invalid[i],0,sizeof output)==STATUS_INVALID_HANDLE);
        VERIFY(object.refs==1 && copies==before_copies+1);
    }
    object.type=OB_TOKEN+1;
    VERIFY(query(&process,4,0,sizeof output)==STATUS_OBJECT_TYPE_MISMATCH);
    VERIFY(object.refs==1 && copies==before_copies+1);
    puts("production token query: granted-rights, denial, output and reference controls PASS");
    return 0;
}
'''


class TokenQueryHostTests(unittest.TestCase):
    def test_production_query(self):
        compilers = [("gcc", [])]
        if shutil.which("clang"):
            compilers.append(("clang", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]))
        with tempfile.TemporaryDirectory(prefix="shz-token-query-") as directory:
            source = Path(directory) / "query.c"
            source.write_text(fixture_source())
            for compiler, extra in compilers:
                with self.subTest(compiler=compiler):
                    output = Path(directory) / compiler
                    subprocess.run([compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", *extra,
                                    str(source), "-o", str(output)], check=True, capture_output=True, timeout=30)
                    result = subprocess.run([str(output)], capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
