/* SPDX-License-Identifier: GPL-2.0-only
 * Native unit test of kernel32/ini_core.c (GetPrivateProfileStringW). Expected results follow the documented behaviour of
 * GetPrivateProfileString (MSDN): value lookup with default, section/key name lists terminated by two NULs, truncation to
 * nSize - 1 (value) or nSize - 2 (lists), quotes around a value removed, names compared without regard to case.
 * Build and run: python3 shizukudos/win64/tests/host/run_host_tests.py */
#include <stdio.h>
#include <string.h>
#include "../../kernel32/ini_core.c"

static int failures, checks;
#define CHECK(cond, ...) do { ++checks; if (!(cond)) { ++failures; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static ini_w text[1024];
static unsigned text_n;

static void set_text(const char *s) { text_n = 0; while (*s) text[text_n++] = (unsigned char)*s++; }
static ini_w *W(const char *s) { static ini_w b[8][128]; static int k; ini_w *w = b[k++ & 7]; int i = 0; while ((w[i] = (unsigned char)s[i])) ++i; return w; }

/* renders out[0..n] with NULs shown as '|' */
static const char *show(const ini_w *o, unsigned n)
{
    static char b[512];
    unsigned i;
    for (i = 0; i < n && i < 500; ++i) b[i] = o[i] ? (char)o[i] : '|';
    b[i] = 0;
    return b;
}

static void value(const char *sec, const char *key, const char *def, unsigned size, const char *want, unsigned want_ret, int want_found)
{
    ini_w out[128];
    int found = -1;
    unsigned r;
    memset(out, 0xff, sizeof out);
    r = ini_get_string(text, text_n, W(sec), W(key), def ? W(def) : 0, out, size, &found);
    CHECK(r == want_ret && !strcmp(show(out, r), want) && out[r] == 0 && found == want_found,
          "[%s] %s (size %u): got \"%s\" ret %u found %d, want \"%s\" ret %u found %d", sec, key, size, show(out, r), r, found, want,
          want_ret, want_found);
}

static void list(const char *sec, unsigned size, const char *want, unsigned want_ret)
{
    ini_w out[128];
    int found;
    unsigned r;
    memset(out, 0xff, sizeof out);
    r = ini_get_string(text, text_n, sec ? W(sec) : 0, 0, 0, out, size, &found);
    CHECK(r == want_ret && !strcmp(show(out, (unsigned)strlen(want)), want), "list [%s] size %u: got \"%s\" ret %u, want \"%s\" ret %u",
          sec ? sec : "(sections)", size, show(out, (unsigned)strlen(want)), r, want, want_ret);
}

int main(void)
{
    set_text("; leading comment\r\n"
             "orphan=outside any section\r\n"
             "[Settings]\r\n"
             "  Name =  Shizuku  \r\n"
             "Quoted=\"  spaced  \"\r\n"
             "Single='x'\r\n"
             "Mismatch=\"abc'\r\n"
             "Empty=\r\n"
             "; comment inside\r\n"
             "\r\n"
             "[ Other ]  trailing text\n"
             "key=1\n"
             "KEY2=two\n"
             "[settings]\n"
             "Name=second section of the same name\n");

    value("Settings", "Name", 0, 64, "Shizuku", 7, 1);
    value("SETTINGS", "name", 0, 64, "Shizuku", 7, 1);
    value("Settings", "Quoted", 0, 64, "  spaced  ", 10, 1);
    value("Settings", "Single", 0, 64, "x", 1, 1);
    value("Settings", "Mismatch", 0, 64, "\"abc'", 5, 1);
    value("Settings", "Empty", "dflt", 64, "", 0, 1);
    value("Settings", "Missing", "fallback  ", 64, "fallback", 8, 0);
    value("Settings", "Missing", 0, 64, "", 0, 0);
    value("Nowhere", "Name", "d", 64, "d", 1, 0);
    value("Other", "key", 0, 64, "1", 1, 1);
    value("Other", "key2", 0, 64, "two", 3, 1);
    value("settings", "Name", 0, 64, "Shizuku", 7, 1);           /* a repeated section name: the first section counts */
    value("Settings", "Name", 0, 4, "Shi", 3, 1);                 /* truncated to size - 1 */
    value("Settings", "Name", 0, 1, "", 0, 1);
    value("Settings", "orphan", "none", 64, "none", 4, 0);        /* a line before the first section belongs to none */

    list(0, 64, "Settings|Other|settings||", 24);            /* the count excludes only the list's final NUL */
    list("Settings", 64, "Name|Quoted|Single|Mismatch|Empty||", 34);
    list("Other", 64, "key|KEY2||", 9);
    list("Other", 7, "key|K||", 5);                               /* truncated list: size - 2, two NULs */
    list("Nowhere", 64, "|", 0);
    {
        ini_w out[4];
        int found;
        CHECK(ini_get_string(text, text_n, W("Settings"), W("Name"), 0, out, 0, &found) == 0, "size 0 returns 0");
    }
    printf("ini_host_test: %d checks, %d failed\n", checks, failures);
    return failures != 0;
}
