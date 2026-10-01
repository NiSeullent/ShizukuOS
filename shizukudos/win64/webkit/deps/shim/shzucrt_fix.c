/* SPDX-License-Identifier: GPL-2.0-only
 * C runtime names that the WebKit toolchain's images import but that the Shizuku runtime DLLs do not export yet
 * (found by wkguest.import_check against build/shizukudos/win64; listed in docs/shizukudos10/reports/W3.md under
 * "Needed from K5"). toolchain.py compiles this file and adds it to the sysroot's libmingwex.a, which the mingw driver
 * links before the UCRT import library, so these definitions (and their __imp_ pointers, for dllimport references)
 * win over the import-library thunks.
 *
 * Semantics follow the Shizuku ucrtbase, which implements only the C locale (docs CRT.md): the _l variants ignore the
 * locale argument and call the C-locale function. When K5 adds a name to ucrtbase.dll, delete it here.
 *
 * Every function is its own object (compiled once per SHZ_PART value, see SHZ_PARTS in toolchain.py) so that the
 * linker pulls only the names an image really needs.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>
#include <errno.h>

#define IMP(name) void *__imp_##name = (void *)(name)

#if SHZ_PART == 0  /* _assert */
void __cdecl _assert(const char *msg, const char *file, unsigned line)
{
    fprintf(stderr, "Assertion failed: %s, file %s, line %u\n", msg, file, line);
    fflush(stderr);
    abort();
}
IMP(_assert);
#endif

#if SHZ_PART == 1  /* _wassert */
void __cdecl _wassert(const wchar_t *msg, const wchar_t *file, unsigned line)
{
    fprintf(stderr, "Assertion failed: %ls, file %ls, line %u\n", msg, file, line);
    fflush(stderr);
    abort();
}
IMP(_wassert);
#endif

#if SHZ_PART == 2  /* _mbtowc_l */
int __cdecl _mbtowc_l(wchar_t *dst, const char *src, size_t n, _locale_t loc)
{
    (void)loc;
    return mbtowc(dst, src, n);
}
IMP(_mbtowc_l);
#endif

#if SHZ_PART == 3  /* _strcoll_l */
int __cdecl _strcoll_l(const char *a, const char *b, _locale_t loc)
{
    (void)loc;
    return strcoll(a, b);
}
IMP(_strcoll_l);
#endif

#if SHZ_PART == 4  /* _strxfrm_l */
size_t __cdecl _strxfrm_l(char *dst, const char *src, size_t n, _locale_t loc)
{
    (void)loc;
    return strxfrm(dst, src, n);
}
IMP(_strxfrm_l);
#endif

#if SHZ_PART == 5  /* _wcscoll_l */
int __cdecl _wcscoll_l(const wchar_t *a, const wchar_t *b, _locale_t loc)
{
    (void)loc;
    return wcscoll(a, b);
}
IMP(_wcscoll_l);
#endif

#if SHZ_PART == 6  /* _wcsxfrm_l */
size_t __cdecl _wcsxfrm_l(wchar_t *dst, const wchar_t *src, size_t n, _locale_t loc)
{
    (void)loc;
    return wcsxfrm(dst, src, n);
}
IMP(_wcsxfrm_l);
#endif

#if SHZ_PART == 7  /* rand_s */
/* bcryptprimitives!ProcessPrng is the system RNG that the Shizuku runtime exports (the Windows 10 rand_s source). */
__declspec(dllimport) BOOL WINAPI ProcessPrng(PBYTE data, SIZE_T len);

errno_t __cdecl rand_s(unsigned int *out)
{
    if (!out) return EINVAL;
    if (!ProcessPrng((PBYTE)out, sizeof *out)) { *out = 0; return ENOMEM; }
    return 0;
}
IMP(rand_s);
#endif

#if SHZ_PART >= 8 && SHZ_PART <= 11
/* The C locale object. The Shizuku ucrtbase returns a locale whose locinfo is NULL; the UCRT's public inline helpers
 * (mingw ctype.h _ischartype_l, used by libc++) read locinfo->_locale_pctype and ->_locale_mb_cur_max, so the object
 * handed out here carries the C locale's public data. The Shizuku _l functions ignore their locale argument (C locale
 * only), so passing this object to them is equivalent to passing theirs. */
struct shz_c_locinfo { const unsigned short *pctype; int mb_cur_max; unsigned int lc_codepage; };
struct shz_c_locale { struct shz_c_locinfo *locinfo; void *mbcinfo; };
extern struct shz_c_locale shz_c_locale_object;
extern int shz_is_c_locale_name(const char *name);
#endif

#if SHZ_PART == 8  /* _create_locale (+ the shared object) */
static struct shz_c_locinfo shz_c_locinfo_data;
struct shz_c_locale shz_c_locale_object;

int shz_is_c_locale_name(const char *name)
{
    return !strcmp(name, "C") || !strcmp(name, "POSIX") || !strcmp(name, "");
}

_locale_t __cdecl _create_locale(int cat, const char *name)
{
    if (cat < 0 || cat > 5 || !name) { errno = EINVAL; return 0; }
    if (!shz_is_c_locale_name(name)) return 0;
    if (!shz_c_locale_object.locinfo) {
        shz_c_locinfo_data.pctype = __pctype_func();
        shz_c_locinfo_data.mb_cur_max = 1;
        shz_c_locinfo_data.lc_codepage = 0;
        shz_c_locale_object.locinfo = &shz_c_locinfo_data;
    }
    return (_locale_t)&shz_c_locale_object;
}
IMP(_create_locale);
#endif

#if SHZ_PART == 9  /* _wcreate_locale */
_locale_t __cdecl _wcreate_locale(int cat, const wchar_t *name)
{
    char narrow[8];
    size_t i;
    if (cat < 0 || cat > 5 || !name) { errno = EINVAL; return 0; }
    for (i = 0; i < sizeof narrow - 1 && name[i] && name[i] < 0x80; ++i) narrow[i] = (char)name[i];
    if (name[i]) return 0;
    narrow[i] = 0;
    return _create_locale(cat, narrow);
}
IMP(_wcreate_locale);
#endif

#if SHZ_PART == 10  /* _get_current_locale */
_locale_t __cdecl _get_current_locale(void)
{
    return _create_locale(LC_ALL, "C");
}
IMP(_get_current_locale);
#endif

#if SHZ_PART == 11  /* _free_locale */
void __cdecl _free_locale(_locale_t loc)
{
    (void)loc;                    /* the C locale object is static */
}
IMP(_free_locale);
#endif

#if SHZ_PART == 12 || SHZ_PART == 13
#include <sys/stat.h>
static int shz_chmod_w(const wchar_t *path, int mode)
{
    DWORD a = GetFileAttributesW(path);
    if (a == INVALID_FILE_ATTRIBUTES) { errno = ENOENT; return -1; }
    a = (mode & _S_IWRITE) ? (a & ~FILE_ATTRIBUTE_READONLY) : (a | FILE_ATTRIBUTE_READONLY);
    if (!SetFileAttributesW(path, a ? a : FILE_ATTRIBUTE_NORMAL)) { errno = EACCES; return -1; }
    return 0;
}
#endif

#if SHZ_PART == 12  /* _wchmod: only the read-only attribute is meaningful on Windows */
int __cdecl _wchmod(const wchar_t *path, int mode)
{
    return shz_chmod_w(path, mode);
}
IMP(_wchmod);
#endif

#if SHZ_PART == 13  /* _chmod */
int __cdecl _chmod(const char *path, int mode)
{
    wchar_t w[MAX_PATH];
    if (!MultiByteToWideChar(CP_ACP, 0, path, -1, w, MAX_PATH)) { errno = ENOENT; return -1; }
    return shz_chmod_w(w, mode);
}
IMP(_chmod);
#endif
