/* Host regression for the ntdll providers (fake Win98 backend). Not guest evidence.
 * SPDX-License-Identifier: GPL-2.0-only */
#include "lc_ntdll.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

typedef struct fake { lc_nt_file_info f; uint64_t pos; uint32_t err; int fail_seek_after, seeks, eof_set, times_set; uint64_t eof_pos; } fake;
static fake fk;
static int f_info(void *o, uintptr_t h, lc_nt_file_info *f)
{ (void)o; if (h == 0x77) { fk.err = 1; return 0; } *f = fk.f; return 1; }
static int f_seek(void *o, uintptr_t h, int64_t off, int wh, uint64_t *p)
{
    (void)o; (void)h;
    if (fk.fail_seek_after && ++fk.seeks > fk.fail_seek_after) { fk.err = 25; return 0; }
    if (wh == LC_SEEK_SET) fk.pos = (uint64_t)off; else if (wh == LC_SEEK_CUR) fk.pos += (uint64_t)off; else fk.pos = fk.f.size + (uint64_t)off;
    *p = fk.pos; return 1;
}
static int f_eof(void *o, uintptr_t h) { (void)o; (void)h; fk.eof_set++; fk.eof_pos = fk.pos; fk.f.size = fk.pos; return 1; }
static int f_times(void *o, uintptr_t h, const uint64_t *c, const uint64_t *a, const uint64_t *w)
{ (void)o; (void)h; fk.times_set++; if (c) fk.f.creation = *c; if (a) fk.f.access = *a; if (w) fk.f.write = *w; return 1; }
static int f_proc(void *o, uintptr_t h, uint32_t *pid, uint32_t *par)
{ (void)o; if (h != (uintptr_t)-1) { fk.err = 50; return 0; } *pid = 1234; *par = 99; return 1; }
static uint32_t f_err(void *o) { (void)o; return fk.err; }
static const lc_nt_ops ops = { 0, f_info, f_seek, f_eof, f_times, f_proc, f_err };

static uint32_t rd32(const unsigned char *b, size_t o) { return b[o] | b[o+1] << 8 | b[o+2] << 16 | (uint32_t)b[o+3] << 24; }
static uint64_t rd64(const unsigned char *b, size_t o) { return rd32(b, o) | (uint64_t)rd32(b, o + 4) << 32; }
static void wr64(unsigned char *b, size_t o, uint64_t v) { size_t i; for (i = 0; i < 8; i++) b[o + i] = (unsigned char)(v >> (8 * i)); }

int main(void)
{
    unsigned char b[128];
    uint32_t info, st, i, e;
    /* status mapping, including the FACILITY_NTWIN32 encoding lc_sock stores */
    CHECK(lc_nt_status_to_dos(0) == 0);
    CHECK(lc_nt_status_to_dos(0xC0000034u) == 2 && lc_nt_status_to_dos(0xC0000022u) == 5);
    CHECK(lc_nt_status_to_dos(0xC0072746u) == 0x2746 && lc_nt_status_to_dos(0x80070005u) == 5);
    CHECK(lc_nt_status_to_dos(0xC0000010u) == 1 && lc_nt_status_to_dos(0x80000005u) == 234);
    CHECK(lc_nt_status_to_dos(0xC01234F0u) == LC_ERROR_MR_MID_NOT_FOUND);
    CHECK(lc_nt_status_from_win32(0) == 0 && lc_nt_status_from_win32(1) == LC_STATUS_INVALID_DEVICE_REQUEST);
    CHECK(lc_nt_status_from_win32(5) == 0xC0000022u && lc_nt_status_from_win32(0x2746) != 0);
    for (i = 1; i < 6000; i++) { /* every Win32 error round-trips through NTSTATUS */
        e = lc_nt_status_to_dos(lc_nt_status_from_win32(i));
        CHECK(e == i);
    }

    fk.f = (lc_nt_file_info){ 0x20, 0xABCD, 1, 111, 222, 333, 1000, 0x100000002ull };
    fk.pos = 17;
    memset(b, 0xee, sizeof(b));
    CHECK(lc_nt_query_information_file(&ops, 5, b, 40, LC_FileBasicInformation, &info) == 0 && info == 40);
    CHECK(rd64(b, 0) == 111 && rd64(b, 8) == 222 && rd64(b, 16) == 333 && rd64(b, 24) == 333 && rd32(b, 32) == 0x20);
    CHECK(lc_nt_query_information_file(&ops, 5, b, 39, LC_FileBasicInformation, &info) == LC_STATUS_INFO_LENGTH_MISMATCH && info == 0);
    memset(b, 0xee, sizeof(b));
    CHECK(lc_nt_query_information_file(&ops, 5, b, 24, LC_FileStandardInformation, &info) == 0 && info == 24);
    CHECK(rd64(b, 0) == 1024 && rd64(b, 8) == 1000 && rd32(b, 16) == 1 && b[20] == 0 && b[21] == 0);
    CHECK(lc_nt_query_information_file(&ops, 5, b, 8, LC_FilePositionInformation, &info) == 0 && rd64(b, 0) == 17);
    memset(b, 0xee, sizeof(b));
    CHECK(lc_nt_query_information_file(&ops, 5, b, 104, LC_FileAllInformation, &info) == 0 && info == 100);
    CHECK(rd64(b, 0) == 111 && rd64(b, 40 + 8) == 1000 && rd64(b, 64) == 0x100000002ull && rd64(b, 80) == 17 && rd32(b, 96) == 0);
    CHECK(rd32(b, 72) == 0 && rd32(b, 76) == 0 && rd32(b, 88) == 0 && rd32(b, 92) == 0);
    CHECK(lc_nt_query_information_file(&ops, 5, b, 128, 8 /*Access*/, &info) == LC_STATUS_NOT_IMPLEMENTED && info == 0);
    CHECK(lc_nt_query_information_file(&ops, 5, b, 128, 16 /*Mode*/, &info) == LC_STATUS_NOT_IMPLEMENTED);
    CHECK(lc_nt_query_information_file(&ops, 0, b, 40, 4, &info) == LC_STATUS_INVALID_HANDLE);
    CHECK(lc_nt_query_information_file(&ops, 5, NULL, 40, 4, &info) == LC_STATUS_INVALID_PARAMETER);
    st = lc_nt_query_information_file(&ops, 0x77, b, 40, 4, &info); /* backend ERROR_INVALID_FUNCTION */
    CHECK(st == LC_STATUS_INVALID_DEVICE_REQUEST && info == 0);

    /* volume */
    CHECK(lc_nt_query_volume_information_file(&ops, 5, b, 24, LC_FileFsVolumeInformation, &info) == 0 && info == 18);
    CHECK(rd64(b, 0) == 0 && rd32(b, 8) == 0xABCD && rd32(b, 12) == 0 && b[16] == 0);
    CHECK(lc_nt_query_volume_information_file(&ops, 5, b, 24, 5 /*Attribute*/, &info) == LC_STATUS_NOT_IMPLEMENTED);
    CHECK(lc_nt_query_volume_information_file(&ops, 5, b, 10, 1, &info) == LC_STATUS_INFO_LENGTH_MISMATCH);

    /* set basic: times applied, attribute change refused BEFORE touching times */
    memset(b, 0, 40); wr64(b, 8, 5555);
    CHECK(lc_nt_set_information_file(&ops, 5, b, 40, LC_FileBasicInformation, &info) == 0 && fk.f.access == 5555 && fk.f.creation == 111 && fk.times_set == 1);
    memset(b, 0, 40); wr64(b, 16, 9999); b[32] = 0x01; /* READONLY while current is ARCHIVE */
    CHECK(lc_nt_set_information_file(&ops, 5, b, 40, LC_FileBasicInformation, &info) == LC_STATUS_NOT_IMPLEMENTED);
    CHECK(fk.times_set == 1 && fk.f.write == 333);
    b[32] = 0x20; /* same attributes: no-op for them, times apply */
    CHECK(lc_nt_set_information_file(&ops, 5, b, 40, LC_FileBasicInformation, &info) == 0 && fk.f.write == 9999);
    /* end of file keeps the file pointer */
    fk.pos = 42; wr64(b, 0, 700);
    CHECK(lc_nt_set_information_file(&ops, 5, b, 8, LC_FileEndOfFileInformation, &info) == 0);
    CHECK(fk.eof_set == 1 && fk.eof_pos == 700 && fk.pos == 42 && fk.f.size == 700);
    wr64(b, 0, 0x8000000000000000ull);
    CHECK(lc_nt_set_information_file(&ops, 5, b, 8, LC_FileEndOfFileInformation, &info) == LC_STATUS_INVALID_PARAMETER && fk.eof_set == 1);
    /* a failing seek during EOF set: failure status, no truncation */
    fk.seeks = 0; fk.fail_seek_after = 1; fk.pos = 42; wr64(b, 0, 10); fk.eof_set = 0;
    st = lc_nt_set_information_file(&ops, 5, b, 8, LC_FileEndOfFileInformation, &info);
    CHECK(st == lc_nt_status_from_win32(25) && fk.eof_set == 0);
    fk.fail_seek_after = 0;
    wr64(b, 0, 321);
    CHECK(lc_nt_set_information_file(&ops, 5, b, 8, LC_FilePositionInformation, &info) == 0 && fk.pos == 321);
    CHECK(lc_nt_set_information_file(&ops, 5, b, 64, 10 /*Rename*/, &info) == LC_STATUS_NOT_IMPLEMENTED);
    CHECK(lc_nt_set_information_file(&ops, 5, b, 64, 13 /*Disposition*/, &info) == LC_STATUS_NOT_IMPLEMENTED);

    /* process */
    memset(b, 0xee, sizeof(b));
    CHECK(lc_nt_query_information_process(&ops, (uintptr_t)-1, b, 24, LC_ProcessBasicInformation, &info) == 0 && info == 24);
    CHECK(rd32(b, 16) == 1234 && rd32(b, 20) == 99 && rd32(b, 0) == 259 && rd32(b, 4) == 0);
    CHECK(lc_nt_query_information_process(&ops, (uintptr_t)-1, b, 23, 0, &info) == LC_STATUS_INFO_LENGTH_MISMATCH && info == 0);
    CHECK(lc_nt_query_information_process(&ops, (uintptr_t)-1, b, 24, 7, &info) == LC_STATUS_NOT_IMPLEMENTED);
    st = lc_nt_query_information_process(&ops, 0x1000, b, 24, 0, &info);
    CHECK(st == lc_nt_status_from_win32(50) && lc_nt_status_to_dos(st) == 50 && info == 0);
    puts("lc_ntdll host: PASS (fake Win98 backend, not guest evidence)");
    return 0;
}
