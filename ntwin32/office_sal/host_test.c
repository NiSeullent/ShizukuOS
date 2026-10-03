/* SPDX-License-Identifier: GPL-2.0-only
 * Host logic controls for office_sal.c with an in-memory file system and a Latin-1-only ANSI page. */
#include "office_sal.h"
#include <stdio.h>
#include <string.h>

static int checks, failures;
#define CHECK(c) do { ++checks; if (!(c)) { ++failures; printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

#define NF 8
static char names[NF][64]; static char data[NF][16]; static int fail_move_n = -1, moves;
static int find(const char *p) { int i; for (i = 0; i < NF; ++i) if (names[i][0] && !strcmp(names[i], p)) return i; return -1; }
static void put(const char *p, const char *d) { int i = find(p); if (i < 0) for (i = 0; names[i][0]; ++i) { } strcpy(names[i], p); strcpy(data[i], d); }

static int to_ansi(void *c, const uint16_t *w, int n, char *o, int cap, int *lossy)
{ int i; (void)c; *lossy = 0; if (n > cap) return 0; for (i = 0; i < n; ++i) { if (w[i] > 0xFF) { *lossy = 1; o[i] = '?'; } else o[i] = (char)w[i]; } return n; }
static int to_wide(void *c, const char *a, int n, uint16_t *o, int cap)
{ int i; (void)c; if (n > cap) return 0; for (i = 0; i < n; ++i) o[i] = (uint8_t)a[i]; return n; }
static int exists(void *c, const char *p) { (void)c; return find(p) >= 0; }
static int samevol(void *c, const char *a, const char *b) { (void)c; return a[0] == b[0]; }
static uint32_t mv(void *c, const char *s, const char *d)
{
    int i = find(s), j;
    (void)c;
    if (moves++ == fail_move_n) return 5;
    if (i < 0) return 2;
    j = find(d);
    if (j >= 0) names[j][0] = 0;
    strcpy(names[i], d);
    return 0;
}
static uint32_t rm(void *c, const char *p) { int i = find(p); (void)c; if (i < 0) return 2; names[i][0] = 0; return 0; }
static uint32_t fl(void *c, const char *p) { (void)c; return find(p) < 0 ? 2 : 0; }
static int64_t pos, fsize = 0x180000010LL;
static uint32_t setfp(void *c, void *h, int32_t lo, int32_t *hi, uint32_t m, uint32_t *err)
{
    int64_t d = (int64_t)(((uint64_t)(uint32_t)*hi << 32) | (uint32_t)lo), np;
    (void)c; (void)h; *err = 0;
    np = m == 0 ? d : m == 1 ? pos + d : fsize + d;
    if (np < 0) { *err = 131; return 0xFFFFFFFFu; }
    pos = np; *hi = (int32_t)(np >> 32);
    if ((uint32_t)np == 0xFFFFFFFFu) *err = 0;
    return (uint32_t)np;
}
static uint32_t getsz(void *c, void *h, uint32_t *hi, uint32_t *err)
{ (void)c; *err = 0; if (!h) { *err = 6; return 0xFFFFFFFFu; } *hi = (uint32_t)(fsize >> 32); return (uint32_t)fsize; }
static int image;
static void *byname(void *c, const char *n) { (void)c; return !n ? (void *)&image : !strcmp(n, "sal3.dll") ? (void *)&image + 8 : NULL; }
static void *byaddr(void *c, const void *a) { (void)c; return (const char *)a >= (const char *)&image && (const char *)a < (const char *)&image + 8 ? (void *)&image : NULL; }
static int addrefs; static uint32_t addref(void *c, void *m) { (void)c; (void)m; ++addrefs; return 0; }

static const struct ofs_backend B = { 0, to_ansi, to_wide, exists, samevol, mv, rm, fl, setfp, getsz, byname, byaddr, addref };
static const uint16_t W_A[] = {'C',':','a','.','d','o','c',0}, W_B[] = {'C',':','b','.','t','m','p',0},
    W_BK[] = {'C',':','b','k',0}, W_D[] = {'D',':','b','.','t','m','p',0}, W_UNI[] = {'C',':',0x4E2D,0},
    W_LIT[] = {'C',':',0xE9,0}, W_LONGP[] = {'\\','\\','?','\\','C',0}, W_SAL[] = {'s','a','l','3','.','d','l','l',0};

static void reset(void) { memset(names, 0, sizeof names); moves = 0; fail_move_n = -1; put("C:a.doc", "old"); put("C:b.tmp", "new"); }

int main(void)
{
    int64_t v; void *m; struct ofs_proc_table t; uint32_t pid;
    reset();
    CHECK(ofs_replace_file(&B, W_A, W_B, 0, 0, 0, 0) == 0);
    CHECK(find("C:a.doc") >= 0 && !strcmp(data[find("C:a.doc")], "new") && find("C:b.tmp") < 0 && find("C:a.doc.~ofs") < 0);
    reset(); CHECK(ofs_replace_file(&B, W_A, W_B, W_BK, 1, 0, 0) == 0 && find("C:bk") >= 0 && !strcmp(data[find("C:bk")], "old"));
    reset(); fail_move_n = 1;   /* replacement move fails: original must be back */
    CHECK(ofs_replace_file(&B, W_A, W_B, 0, 0, 0, 0) == OFS_ERROR_UNABLE_TO_MOVE_REPLACEMENT);
    CHECK(find("C:a.doc") >= 0 && !strcmp(data[find("C:a.doc")], "old") && find("C:b.tmp") >= 0);
    reset(); fail_move_n = 0; CHECK(ofs_replace_file(&B, W_A, W_B, 0, 0, 0, 0) == OFS_ERROR_UNABLE_TO_REMOVE_REPLACED);
    reset(); CHECK(ofs_replace_file(&B, W_A, W_D, 0, 0, 0, 0) == OFS_ERROR_FILE_NOT_FOUND);   /* D: src missing: not-found first */
    put("D:b.tmp", "x"); CHECK(ofs_replace_file(&B, W_A, W_D, 0, 0, 0, 0) == OFS_ERROR_UNABLE_TO_MOVE_REPLACEMENT);
    reset(); put("C:a.doc.~ofs", "stale"); CHECK(ofs_replace_file(&B, W_A, W_B, 0, 0, 0, 0) == OFS_ERROR_UNABLE_TO_REMOVE_REPLACED && find("C:a.doc.~ofs") >= 0);
    reset(); CHECK(ofs_replace_file(&B, W_A, W_B, 0, 8, 0, 0) == OFS_ERROR_INVALID_PARAMETER);
    CHECK(ofs_replace_file(&B, W_A, W_A, 0, 0, 0, 0) == OFS_ERROR_INVALID_PARAMETER);
    CHECK(ofs_replace_file(&B, W_A, W_B, 0, 0, &image, 0) == OFS_ERROR_INVALID_PARAMETER);
    CHECK(ofs_replace_file(&B, W_UNI, W_B, 0, 0, 0, 0) == OFS_ERROR_NO_UNICODE_TRANSLATION);
    put("C:\xe9", "e"); CHECK(ofs_replace_file(&B, W_LIT, W_B, 0, 0, 0, 0) == 0);
    CHECK(ofs_replace_file(&B, W_LONGP, W_B, 0, 0, 0, 0) == OFS_ERROR_INVALID_NAME);
    { uint16_t big[300]; int i; for (i = 0; i < 299; ++i) big[i] = 'a'; big[299] = 0; char o[260];
      CHECK(ofs_w2a(&B, big, o, sizeof o) == OFS_ERROR_FILENAME_EXCED_RANGE); CHECK(ofs_w2a(&B, W_A, o, 4) == OFS_ERROR_INSUFFICIENT_BUFFER); }
    /* file pointer / size */
    CHECK(ofs_set_file_pointer_ex(&B, &image, 0x100000005LL, &v, 0) == 0 && v == 0x100000005LL);
    CHECK(ofs_set_file_pointer_ex(&B, &image, -3, &v, 1) == 0 && v == 0x100000002LL);
    CHECK(ofs_set_file_pointer_ex(&B, &image, 0, &v, 2) == 0 && v == fsize);
    CHECK(ofs_set_file_pointer_ex(&B, &image, -1, &v, 0) == OFS_ERROR_NEGATIVE_SEEK);
    CHECK(ofs_set_file_pointer_ex(&B, &image, 0, &v, 3) == OFS_ERROR_INVALID_PARAMETER);
    CHECK(ofs_set_file_pointer_ex(&B, &image, 0xFFFFFFFFLL, &v, 0) == 0 && v == 0xFFFFFFFFLL);   /* low word 0xFFFFFFFF is not an error */
    CHECK(ofs_get_file_size_ex(&B, &image, &v) == 0 && v == 0x180000010LL);
    CHECK(ofs_get_file_size_ex(&B, 0, &v) == 6 && ofs_get_file_size_ex(&B, &image, 0) == OFS_ERROR_INVALID_PARAMETER);
    /* module handles */
    CHECK(ofs_get_module_handle_ex(&B, OFS_GMHE_FROM_ADDRESS | OFS_GMHE_UNCHANGED_REFCOUNT, (const uint16_t *)&image, &m) == 0 && m == &image && addrefs == 0);
    CHECK(ofs_get_module_handle_ex(&B, OFS_GMHE_FROM_ADDRESS, (const uint16_t *)&image, &m) == 0 && addrefs == 1);
    CHECK(ofs_get_module_handle_ex(&B, OFS_GMHE_FROM_ADDRESS, (const uint16_t *)&B, &m) == OFS_ERROR_MOD_NOT_FOUND && m == 0);
    CHECK(ofs_get_module_handle_ex(&B, 0, W_SAL, &m) == 0 && m != 0 && addrefs == 2);
    CHECK(ofs_get_module_handle_ex(&B, 0, 0, &m) == 0 && m == &image);
    CHECK(ofs_get_module_handle_ex(&B, OFS_GMHE_PIN, W_SAL, &m) == OFS_ERROR_NOT_SUPPORTED);
    CHECK(ofs_get_module_handle_ex(&B, 3, W_SAL, &m) == OFS_ERROR_INVALID_PARAMETER);
    CHECK(ofs_get_module_handle_ex(&B, 8, W_SAL, &m) == OFS_ERROR_INVALID_PARAMETER);
    CHECK(ofs_get_module_handle_ex(&B, OFS_GMHE_FROM_ADDRESS, 0, &m) == OFS_ERROR_INVALID_PARAMETER);
    CHECK(ofs_get_module_handle_ex(&B, 0, W_SAL, 0) == OFS_ERROR_INVALID_PARAMETER);
    /* search path mode / process table */
    CHECK(ofs_search_path_mode_check(OFS_SEARCH_ENABLE_SAFE | OFS_SEARCH_PERMANENT) == OFS_ERROR_CALL_NOT_IMPLEMENTED);
    CHECK(ofs_search_path_mode_check(3) == OFS_ERROR_INVALID_PARAMETER && ofs_search_path_mode_check(0) == OFS_ERROR_INVALID_PARAMETER);
    memset(&t, 0, sizeof t);
    CHECK(ofs_proc_lookup(&t, &image, &pid) == OFS_ERROR_NOT_SUPPORTED);
    CHECK(ofs_proc_register(&t, &image, 77) == 0 && ofs_proc_lookup(&t, &image, &pid) == 0 && pid == 77);
    CHECK(ofs_proc_register(&t, &image, 0) == OFS_ERROR_INVALID_PARAMETER && ofs_proc_register(&t, (void *)(uintptr_t)-1, 5) == OFS_ERROR_INVALID_PARAMETER);
    CHECK(ofs_proc_forget(&t, &image) == 0 && ofs_proc_forget(&t, &image) == 6 && ofs_proc_lookup(&t, &image, &pid) == OFS_ERROR_NOT_SUPPORTED);
    { unsigned i; char dummy[OFS_PROC_TABLE + 1]; for (i = 0; i < OFS_PROC_TABLE; ++i) CHECK(ofs_proc_register(&t, dummy + i, 1 + i) == 0);
      CHECK(ofs_proc_register(&t, dummy + OFS_PROC_TABLE, 9) == 8); }
    printf("office_sal host: %d checks, %d failures\n", checks, failures);
    return failures != 0;
}
