/* SPDX-License-Identifier: GPL-2.0-only
 * tridentrt: module-local versions of system functions that Wine's code compiled into tridentrt calls but the
 * Shizuku ntdll/kernel32 and the wineport C runtime do not provide. They are not exported (other modules are not
 * meant to bind to them here); the __imp_ pointers satisfy Wine's dllimport declarations, as in wineport/glue.
 *   ntdll   RtlCreateUnicodeStringFromAsciiz, RtlUnicodeToMultiByteSize, RtlUnicodeToMultiByteN,
 *           RtlDowncaseUnicodeChar  (kernelbase/path.c, the ANSI URL functions and UrlCombineW)
 *   kernel32 IsDBCSLeadByte        (kernelbase/path.c, ANSI path functions)
 *   musl    math_error, the error hook of the musl libm (static library "musl") that fmod/pow of oleaut32's
 *           variant arithmetic report through; as msvcrt does without a _matherr handler: errno EDOM for a domain
 *           error, ERANGE for a singularity or overflow, nothing for underflow, and the result unchanged
 *   CRT     _create_locale/_free_locale (oleaut32/vartype.c formats doubles in the "C" locale). The wineport C
 *           runtime has no locales at all (every conversion is the C locale), so a locale object carries nothing; the
 *           module is compiled with -D_create_locale=trt_create_locale -D_free_locale=trt_free_locale so that a
 *           later wineport/crt implementation cannot collide with this one.
 * The ntdll/kernel32 ones are listed under "Needed from K4" in the tridentrt report.
 */
#define WINBASEAPI                                          /* defined here, not imported */
#include <errno.h>
#include <math.h>
#include <wctype.h>
#include <locale.h>
#include "comrt.h"
#include "winternl.h"
#include "winnls.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

BOOLEAN WINAPI RtlCreateUnicodeStringFromAsciiz(UNICODE_STRING *target, const char *src)
{
    int n = MultiByteToWideChar(CP_ACP, 0, src, -1, NULL, 0);
    if (n <= 0 || n > 0x7fff) return FALSE;
    if (!(target->Buffer = HeapAlloc(GetProcessHeap(), 0, n * sizeof(WCHAR)))) return FALSE;  /* RtlFreeUnicodeString */
    MultiByteToWideChar(CP_ACP, 0, src, -1, target->Buffer, n);
    target->Length = (USHORT)((n - 1) * sizeof(WCHAR));
    target->MaximumLength = (USHORT)(n * sizeof(WCHAR));
    return TRUE;
}

NTSTATUS WINAPI RtlUnicodeToMultiByteSize(DWORD *size, const WCHAR *src, DWORD len)
{
    *size = len ? WideCharToMultiByte(CP_ACP, 0, src, len / sizeof(WCHAR), NULL, 0, NULL, NULL) : 0;
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI RtlUnicodeToMultiByteN(char *dst, DWORD dstlen, DWORD *reslen, const WCHAR *src, DWORD srclen)
{
    int n = srclen && dstlen ? WideCharToMultiByte(CP_ACP, 0, src, srclen / sizeof(WCHAR), dst, dstlen, NULL, NULL) : 0;
    if (!n && srclen && dstlen)                             /* the destination is too small: fill what fits */
    {
        DWORD i, out = 0;
        char tmp[8];
        int c;
        for (i = 0; i < srclen / sizeof(WCHAR); i++)
        {
            if ((c = WideCharToMultiByte(CP_ACP, 0, src + i, 1, tmp, sizeof(tmp), NULL, NULL)) <= 0) break;
            if (out + c > dstlen) break;
            memcpy(dst + out, tmp, c);
            out += c;
        }
        n = out;
    }
    if (reslen) *reslen = n;
    return STATUS_SUCCESS;
}

WCHAR WINAPI RtlDowncaseUnicodeChar(WCHAR ch)
{
    return towlower(ch);
}

BOOL WINAPI IsDBCSLeadByte(BYTE c)
{
    CPINFO info;
    int i;
    if (!GetCPInfo(CP_ACP, &info)) return FALSE;
    for (i = 0; i < MAX_LEADBYTES && info.LeadByte[i]; i += 2)
        if (c >= info.LeadByte[i] && c <= info.LeadByte[i + 1]) return TRUE;
    return FALSE;
}

void *__imp_RtlCreateUnicodeStringFromAsciiz = (void *)RtlCreateUnicodeStringFromAsciiz;
void *__imp_RtlUnicodeToMultiByteSize = (void *)RtlUnicodeToMultiByteSize;
void *__imp_RtlUnicodeToMultiByteN = (void *)RtlUnicodeToMultiByteN;
void *__imp_RtlDowncaseUnicodeChar = (void *)RtlDowncaseUnicodeChar;
void *__imp_IsDBCSLeadByte = (void *)IsDBCSLeadByte;

/* the C runtime's locale objects: see the header comment */
static void *c_locale[2];                                   /* stands for the C locale; never looked into */

_locale_t __cdecl _create_locale(int category, const char *name)
{
    if (category < LC_ALL || category > LC_MAX || !name) return NULL;
    if (strcmp(name, "C") && strcmp(name, "")) return NULL;         /* only the C locale exists */
    return (_locale_t)c_locale;
}

void __cdecl _free_locale(_locale_t locale)
{
}

double math_error(int type, const char *name, double arg1, double arg2, double retval)
{
    if (type == _DOMAIN) errno = EDOM;
    else if (type == _SING || type == _OVERFLOW) errno = ERANGE;
    return retval;
}
