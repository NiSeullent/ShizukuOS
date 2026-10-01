/*
 * Low level variant functions
 *
 * Copyright 2003 Jon Griffiths
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Selected Wine 11.0 Automation DECIMAL bodies; upstream db11d0fe6a169c457e23d007e20404643d067aa8.
 * This header does not expose general VARIANT coercion or a synthetic locale provider. */
#ifndef SHZ_DECIMAL_WINE_INT_H
#define SHZ_DECIMAL_WINE_INT_H
#ifdef SHZ_DECIMAL_HOST
#include "../../tests/decimal_host_contract.h"
#else
#include "nt.h"
#define _OLEAUT32_
#include <oleauto.h>
#include <math.h>
#include <wchar.h>
#include <string.h>
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#endif
#define TRACE(...) ((void)0)
#define WARN(...) ((void)0)
#define FIXME(...) ((void)0)
#define CY_MULTIPLIER 10000
#define CY_MULTIPLIER_F 10000.0
#define CY_HALF (CY_MULTIPLIER/2)
#define CY_HALF_F (CY_MULTIPLIER_F/2.0)
/* Size constraints */
#define I1_MAX   0x7f
#define I1_MIN   ((-I1_MAX)-1)
#define UI1_MAX  0xff
#define UI1_MIN  0
#define I2_MAX   0x7fff
#define I2_MIN   ((-I2_MAX)-1)
#define UI2_MAX  0xffff
#define UI2_MIN  0
#define I4_MAX   0x7fffffff
#define I4_MIN   ((-I4_MAX)-1)
#define UI4_MAX  0xffffffff
#define UI4_MIN  0
#define I8_MAX   (((LONGLONG)I4_MAX << 32) | UI4_MAX)
#define I8_MIN   ((-I8_MAX)-1)
#define UI8_MAX  (((ULONGLONG)UI4_MAX << 32) | UI4_MAX)
#define UI8_MIN  0
#define DATE_MAX 2958465
#define DATE_MIN -657434
#define R4_MAX 3.402823567797336e38
#define R4_MIN 1.40129846432481707e-45
#define R8_MAX 1.79769313486231470e+308
#define R8_MIN 4.94065645841246544e-324

/* Value of sign for a positive decimal number */
#define DECIMAL_POS 0

#define DEC_MAX_SCALE    28 /* Maximum scale for a decimal */

/* Internal flags for low level conversion functions */
#define  VAR_BOOLONOFF 0x0400 /* Convert bool to "On"/"Off" */
#define  VAR_BOOLYESNO 0x0800 /* Convert bool to "Yes"/"No" */


static inline HRESULT shz_decimal_provider_error(void)
{
    DWORD error = GetLastError();
    return HRESULT_FROM_WIN32(error ? error : ERROR_INVALID_PARAMETER);
}
static inline int shz_decimal_valid(const DECIMAL *d)
{
    return d && d->scale <= DEC_MAX_SCALE && !(d->sign & ~DECIMAL_NEG);
}
/* Exact 96-bit scale reduction, retaining the discarded digits for round-to-even. */
static inline HRESULT shz_decimal_integer_magnitude(const DECIMAL *d, ULONG64 *out)
{
    DWORD words[3] = {d->Lo32, d->Mid32, d->Hi32};
    unsigned first = 0, sticky = 0, i, step;
    ULONG64 carry, mag;
    for (step = 0; step < d->scale; ++step) {
        sticky |= first;
        carry = 0;
        for (i = 3; i-- > 0;) {
            ULONG64 n = (carry << 32) | words[i];
            words[i] = (DWORD)(n / 10);
            carry = n % 10;
        }
        first = (unsigned)carry;
    }
    if (words[2]) return DISP_E_OVERFLOW;
    mag = ((ULONG64)words[1] << 32) | words[0];
    if (first > 5 || (first == 5 && (sticky || (mag & 1)))) {
        if (mag == ~(ULONG64)0) return DISP_E_OVERFLOW;
        ++mag;
    }
    *out = mag;
    return S_OK;
}
HRESULT WINAPI shz_wine_VarBstrFromDec(const DECIMAL* pDecIn, LCID lcid, ULONG dwFlags, BSTR* pbstrOut);
HRESULT WINAPI shz_wine_VarCyFromR8(DOUBLE dblIn, CY* pCyOut);
HRESULT WINAPI shz_wine_VarDecAdd(const DECIMAL* pDecLeft, const DECIMAL* pDecRight, DECIMAL* pDecOut);
HRESULT WINAPI shz_wine_VarDecCmp(const DECIMAL* pDecLeft, const DECIMAL* pDecRight);
HRESULT WINAPI shz_wine_VarDecDiv(const DECIMAL* pDecLeft, const DECIMAL* pDecRight, DECIMAL* pDecOut);
HRESULT WINAPI shz_wine_VarDecFromI2(SHORT sIn, DECIMAL* pDecOut);
HRESULT WINAPI shz_wine_VarDecFromI4(LONG lIn, DECIMAL* pDecOut);
HRESULT WINAPI shz_wine_VarDecFromI8(LONG64 llIn, DECIMAL* pDecOut);
HRESULT WINAPI shz_wine_VarDecFromR4(FLOAT fltIn, DECIMAL* pDecOut);
HRESULT WINAPI shz_wine_VarDecFromR8(DOUBLE dblIn, DECIMAL* pDecOut);
HRESULT WINAPI shz_wine_VarDecFromStr(const OLECHAR* strIn, LCID lcid, ULONG dwFlags, DECIMAL* pDecOut);
HRESULT WINAPI shz_wine_VarDecFromUI1(BYTE bIn, DECIMAL* pDecOut);
HRESULT WINAPI shz_wine_VarDecFromUI2(USHORT usIn, DECIMAL* pDecOut);
HRESULT WINAPI shz_wine_VarDecFromUI4(ULONG ulIn, DECIMAL* pDecOut);
HRESULT WINAPI shz_wine_VarDecFromUI8(ULONG64 ullIn, DECIMAL* pDecOut);
HRESULT WINAPI shz_wine_VarDecMul(const DECIMAL* pDecLeft, const DECIMAL* pDecRight, DECIMAL* pDecOut);
HRESULT WINAPI shz_wine_VarDecNeg(const DECIMAL* pDecIn, DECIMAL* pDecOut);
HRESULT WINAPI shz_wine_VarDecSub(const DECIMAL* pDecLeft, const DECIMAL* pDecRight, DECIMAL* pDecOut);
HRESULT WINAPI shz_wine_VarI2FromDec(const DECIMAL *pdecIn, SHORT* psOut);
HRESULT WINAPI shz_wine_VarI4FromDec(const DECIMAL *pdecIn, LONG *piOut);
HRESULT WINAPI shz_wine_VarI8FromDec(const DECIMAL *pdecIn, LONG64* pi64Out);
HRESULT WINAPI shz_wine_VarI8FromR8(double dblIn, LONG64* pi64Out);
HRESULT WINAPI shz_wine_VarNumFromParseNum(NUMPARSE *pNumprs, BYTE *rgbDig,
                                  ULONG dwVtBits, VARIANT *pVarDst);
HRESULT WINAPI shz_wine_VarParseNumFromStr(const OLECHAR *lpszStr, LCID lcid, ULONG dwFlags,
                                  NUMPARSE *pNumprs, BYTE *rgbDig);
HRESULT WINAPI shz_wine_VarR4FromDec(const DECIMAL* pDecIn, float *pFltOut);
HRESULT WINAPI shz_wine_VarR8FromDec(const DECIMAL* pDecIn, DOUBLE *pDblOut);
HRESULT WINAPI shz_wine_VarUI1FromDec(const DECIMAL *pdecIn, BYTE* pbOut);
HRESULT WINAPI shz_wine_VarUI2FromDec(const DECIMAL *pdecIn, USHORT* pusOut);
HRESULT WINAPI shz_wine_VarUI4FromDec(const DECIMAL *pdecIn, ULONG *pulOut);
HRESULT WINAPI shz_wine_VarUI4FromStr(const OLECHAR* strIn, LCID lcid, ULONG dwFlags, ULONG *pulOut);
HRESULT WINAPI shz_wine_VarUI8FromDec(const DECIMAL *pdecIn, ULONG64* pui64Out);
HRESULT WINAPI shz_wine_VarUI8FromR8(double dblIn, ULONG64* pui64Out);

#endif
