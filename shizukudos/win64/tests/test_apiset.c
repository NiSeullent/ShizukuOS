/* SPDX-License-Identifier: GPL-2.0-only
 * Host tests of the Kernel64 API-set resolver (kernel64/apiset.c + the generated kernel64/apiset_table.h):
 * name classification, the versioned-suffix rule (highest compatible version of the same contract level), table
 * invariants, and a mutation fuzz that must never crash (run under ASan/UBSan by test_pe_parse.py).
 *
 * With "--cli" it reads one name per line from stdin and prints "<result> <windows host> <host>" for each, so the
 * Python reading of the table (gen_apiset_table.lookup, used by import_coverage.py) can be checked against this code.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../kernel64/apiset.h"

static int failures, checks;
#define CHECK(cond, ...) do { ++checks; if (!(cond)) { ++failures; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static void expect(const char *name, int want, const char *host)
{
    const apiset_entry_t *e = 0;
    const int r = apiset_lookup(name, &e);
    CHECK(r == want, "%s: result %d, expected %d", name, r, want);
    if (host) CHECK(e && !strcmp(e->host, host), "%s: host %s, expected %s", name, e ? e->host : "(none)", host);
}

static void test_rules(void)
{
    /* not API-set names */
    expect("kernel32.dll", APISET_NOT_APISET, 0);
    expect("apix-ms-win-core-synch-l1-1-0.dll", APISET_NOT_APISET, 0);
    expect("", APISET_NOT_APISET, 0);
    expect("ap", APISET_NOT_APISET, 0);
    expect("api", APISET_NOT_APISET, 0);
    expect("apiset.dll", APISET_NOT_APISET, 0);
    CHECK(apiset_lookup(0, 0) == APISET_NOT_APISET, "NULL name");
    /* case and the optional .dll suffix */
    expect("api-ms-win-core-synch-l1-2-0.dll", APISET_OK, "kernel32.dll");
    expect("API-MS-WIN-CORE-SYNCH-L1-2-0.DLL", APISET_OK, "kernel32.dll");
    expect("Api-Ms-Win-Core-Synch-L1-2-0", APISET_OK, "kernel32.dll");
    /* highest compatible version of the same contract level: the table has synch-l1-2-1 */
    expect("api-ms-win-core-synch-l1-1-0.dll", APISET_OK, "kernel32.dll");
    expect("api-ms-win-core-synch-l1-2-1.dll", APISET_OK, "kernel32.dll");
    expect("api-ms-win-core-synch-l1-2-2.dll", APISET_VERSION, "kernel32.dll");
    expect("api-ms-win-core-synch-l1-3-0.dll", APISET_VERSION, "kernel32.dll");
    expect("api-ms-win-core-synch-l2-1-0.dll", APISET_UNKNOWN, 0);
    expect("api-ms-win-core-synch-l0-1-0.dll", APISET_UNKNOWN, 0);
    /* libraryloader: the trees import l1-2-0 and l1-2-1; the table provides l1-2-2 */
    expect("api-ms-win-core-libraryloader-l1-2-0.dll", APISET_OK, "kernel32.dll");
    expect("api-ms-win-core-libraryloader-l1-2-1.dll", APISET_OK, "kernel32.dll");
    expect("api-ms-win-core-libraryloader-l1-1-1.dll", APISET_OK, "kernel32.dll");
    /* hosts other than kernel32 */
    expect("api-ms-win-core-registry-l1-1-0.dll", APISET_OK, "advapi32.dll");
    expect("api-ms-win-core-registry-l2-1-0.dll", APISET_OK, "advapi32.dll");
    expect("api-ms-win-core-registry-l9-1-0.dll", APISET_UNKNOWN, 0);
    expect("api-ms-win-core-com-l1-1-0.dll", APISET_OK, "ole32.dll");
    expect("api-ms-win-core-com-l1-1-1.dll", APISET_OK, "ole32.dll");
    expect("api-ms-win-core-com-l1-1-2.dll", APISET_VERSION, "ole32.dll");
    expect("api-ms-win-core-rtlsupport-l1-1-0.dll", APISET_OK, "ntdll.dll");
    expect("api-ms-win-core-winrt-string-l1-1-0.dll", APISET_OK, "combase.dll");
    expect("api-ms-win-crt-runtime-l1-1-0.dll", APISET_OK, "ucrtbase.dll");
    expect("ext-ms-win-uiacore-l1-1-1.dll", APISET_OK, "uiautomationcore.dll");
    expect("api-ms-win-security-sddl-l1-1-0.dll", APISET_OK, "advapi32.dll");
    expect("api-ms-win-core-delayload-l1-1-1.dll", APISET_OK, "kernel32.dll");
    expect("api-ms-win-core-nonexistent-l1-1-0.dll", APISET_UNKNOWN, 0);
    /* the Windows host is recorded separately from the Shizuku host */
    {
        const apiset_entry_t *e = 0;
        CHECK(apiset_lookup("api-ms-win-core-file-l1-2-2.dll", &e) == APISET_OK && e && !strcmp(e->windows_host, "kernelbase.dll") &&
              !strcmp(e->host, "kernel32.dll"), "file-l1: windows host kernelbase.dll, Shizuku host kernel32.dll");
        CHECK(apiset_lookup("api-ms-win-core-com-l1-1-0.dll", &e) == APISET_OK && e && !strcmp(e->windows_host, "combase.dll"),
              "com-l1: windows host combase.dll");
    }
    /* malformed suffixes */
    expect("api-ms-win-core-synch", APISET_BAD_NAME, 0);
    expect("api-ms-win-core-synch-l1-2", APISET_BAD_NAME, 0);
    expect("api-ms-win-core-synch-lx-2-0", APISET_BAD_NAME, 0);
    expect("api-ms-win-core-synch-l1--0", APISET_BAD_NAME, 0);
    expect("api-ms-win-core-synch-l1-2-", APISET_BAD_NAME, 0);
    expect("api-ms-win-core-synch-1-2-0", APISET_BAD_NAME, 0);
    expect("api-l1-1-0", APISET_BAD_NAME, 0);
    expect("api-ms-win-core-synch-l1-2-123456", APISET_BAD_NAME, 0);
    expect("api-ms-win-core-synch-l1-2-0.dl", APISET_BAD_NAME, 0);
    {
        char longname[400];
        memset(longname, 'a', sizeof longname);
        memcpy(longname, "api-", 4);
        memcpy(longname + sizeof longname - 12, "-l1-1-0.dll", 12);
        expect(longname, APISET_BAD_NAME, 0);
    }
    /* parse helper */
    {
        char c[64];
        unsigned M = 9, m = 9;
        CHECK(!apiset_parse_name("API-MS-WIN-CORE-FILE-L2-1-2.DLL", c, sizeof c, &M, &m) && !strcmp(c, "api-ms-win-core-file-l2") && M == 1 && m == 2,
              "parse: %s %u %u", c, M, m);
        CHECK(apiset_parse_name("api-ms-win-core-file-l2-1-2", c, 10, &M, &m) == -1, "parse: contract longer than the buffer");
    }
}

static void test_table(void)
{
    unsigned i;
    CHECK(apiset_count() >= 100, "table has %u rows", apiset_count());
    CHECK(apiset_entry(apiset_count()) == 0, "out-of-range index");
    for (i = 0; i < apiset_count(); ++i) {
        const apiset_entry_t *e = apiset_entry(i), *got = 0;
        char name[160];
        int r;
        if (i) {
            const apiset_entry_t *p = apiset_entry(i - 1);
            const int c = strcmp(p->contract, e->contract);
            CHECK(c < 0 || (c == 0 && (p->major < e->major || (p->major == e->major && p->minor < e->minor))),
                  "table not sorted/unique at %s", e->contract);
        }
        CHECK(strlen(e->host) > 4 && !strcmp(e->host + strlen(e->host) - 4, ".dll"), "%s: host %s", e->contract, e->host);
        snprintf(name, sizeof name, "%s-%u-%u.dll", e->contract, e->major, e->minor);
        r = apiset_lookup(name, &got);
        CHECK(r == APISET_OK && got, "%s resolves", name);
        snprintf(name, sizeof name, "%s-%u-%u.dll", e->contract, e->major, e->minor + 1);
        r = apiset_lookup(name, &got);
        CHECK(r == APISET_VERSION || (r == APISET_OK && got != e), "%s (one minor above the row) is refused", name);
        snprintf(name, sizeof name, "%s-%u-%u", e->contract, e->major + 1, 0);
        r = apiset_lookup(name, &got);
        CHECK(r == APISET_VERSION || (r == APISET_OK && got != e), "%s (next major) is refused", name);
    }
}

static unsigned rnd(void) { static unsigned s = 12345u; s = s * 1103515245u + 12345u; return s >> 8; }

static void test_fuzz(void)
{
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._";
    unsigned iter, ok = 0;
    for (iter = 0; iter < 200000; ++iter) {
        char name[200];
        const apiset_entry_t *e = apiset_entry(rnd() % apiset_count()), *got = 0;
        size_t n;
        int r, k, muts = (int)(rnd() % 4);
        snprintf(name, sizeof name, "%s-%u-%u.dll", e->contract, e->major, e->minor);
        n = strlen(name);
        for (k = 0; k < muts && n; ++k) {
            switch (rnd() % 4) {
            case 0: name[rnd() % n] = alphabet[rnd() % (sizeof alphabet - 1)]; break;           /* replace */
            case 1: if (n > 1) { size_t at = rnd() % n; memmove(name + at, name + at + 1, n - at); --n; } break;  /* delete */
            case 2: if (n + 2 < sizeof name) { size_t at = rnd() % (n + 1); memmove(name + at + 1, name + at, n - at + 1); name[at] = alphabet[rnd() % (sizeof alphabet - 1)]; ++n; } break;
            default: name[rnd() % (n + 1)] = 0; n = strlen(name); break;                          /* truncate */
            }
        }
        r = apiset_lookup(name, &got);
        CHECK(r >= APISET_BAD_NAME && r <= APISET_OK, "fuzz result %d for %s", r, name);
        if (r == APISET_OK || r == APISET_VERSION) CHECK(got != 0, "fuzz: %s has no entry", name);
        if (r == APISET_OK) ++ok;
        if (failures > 20) break;
    }
    printf("fuzz: 200000 mutated names, %u still valid contracts, no crash\n", ok);
}

static int cli(void)
{
    char line[512];
    while (fgets(line, sizeof line, stdin)) {
        const apiset_entry_t *e = 0;
        int r;
        line[strcspn(line, "\r\n")] = 0;
        r = apiset_lookup(line, &e);
        printf("%d %s %s\n", r, e ? e->windows_host : "-", e ? e->host : "-");
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--cli")) return cli();
    test_rules();
    test_table();
    test_fuzz();
    printf("apiset: %d checks, %d failures, %u contracts in the table\n", checks, failures, apiset_count());
    return failures ? 1 : 0;
}
