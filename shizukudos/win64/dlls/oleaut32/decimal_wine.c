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

/* Internal transitive helpers are not DLL exports. Public entry points below validate
 * parameters, snapshot aliased input and publish a result only after successful work. */
#include "decimal_wine_int.h"
#define VARIANT_DutchRound(typ, value, res) do { \
  double whole = value < 0 ? ceil(value) : floor(value); \
  double fract = value - whole; \
  if (fract > 0.5) res = (typ)whole + (typ)1; \
  else if (fract == 0.5) { typ is_odd = (typ)whole & 1; res = whole + is_odd; } \
  else if (fract >= 0.0) res = (typ)whole; \
  else if (fract == -0.5) { typ is_odd = (typ)whole & 1; res = whole - is_odd; } \
  else if (fract > -0.5) res = (typ)whole; \
  else res = (typ)whole - (typ)1; \
} while(0)

#define RETTYP static inline HRESULT


/* Simple compiler cast from one type to another */
#define SIMPLE(dest, src, func) RETTYP _##func(src in, dest* out) { \
  *out = in; return S_OK; }

/* Compiler cast where input cannot be negative */
#define NEGTST(dest, src, func) RETTYP _##func(src in, dest* out) { \
  if (in < 0) { return DISP_E_OVERFLOW; } *out = in; return S_OK; }

/* Compiler cast where input cannot be > some number */
#define POSTST(dest, src, func, tst) RETTYP _##func(src in, dest* out) { \
  if (in > (dest)tst) { return DISP_E_OVERFLOW; } *out = in; return S_OK; }

/* Compiler cast where input cannot be < some number or >= some other number */
#define BOTHTST(dest, src, func, lo, hi) RETTYP _##func(src in, dest* out) { \
  if (in < (dest)lo || in > hi) { return DISP_E_OVERFLOW; } *out = in; return S_OK; }

/* I1 */
POSTST(signed char, BYTE, VarI1FromUI1, I1_MAX)
BOTHTST(signed char, SHORT, VarI1FromI2, I1_MIN, I1_MAX)
BOTHTST(signed char, LONG, VarI1FromI4, I1_MIN, I1_MAX)
SIMPLE(signed char, VARIANT_BOOL, VarI1FromBool)
POSTST(signed char, USHORT, VarI1FromUI2, I1_MAX)
POSTST(signed char, ULONG, VarI1FromUI4, I1_MAX)
BOTHTST(signed char, LONG64, VarI1FromI8, I1_MIN, I1_MAX)
POSTST(signed char, ULONG64, VarI1FromUI8, I1_MAX)

/* UI1 */
BOTHTST(BYTE, SHORT, VarUI1FromI2, UI1_MIN, UI1_MAX)
SIMPLE(BYTE, VARIANT_BOOL, VarUI1FromBool)
NEGTST(BYTE, signed char, VarUI1FromI1)
POSTST(BYTE, USHORT, VarUI1FromUI2, UI1_MAX)
BOTHTST(BYTE, LONG, VarUI1FromI4, UI1_MIN, UI1_MAX)
POSTST(BYTE, ULONG, VarUI1FromUI4, UI1_MAX)
BOTHTST(BYTE, LONG64, VarUI1FromI8, UI1_MIN, UI1_MAX)
POSTST(BYTE, ULONG64, VarUI1FromUI8, UI1_MAX)

/* I2 */
SIMPLE(SHORT, BYTE, VarI2FromUI1)
BOTHTST(SHORT, LONG, VarI2FromI4, I2_MIN, I2_MAX)
SIMPLE(SHORT, VARIANT_BOOL, VarI2FromBool)
SIMPLE(SHORT, signed char, VarI2FromI1)
POSTST(SHORT, USHORT, VarI2FromUI2, I2_MAX)
POSTST(SHORT, ULONG, VarI2FromUI4, I2_MAX)
BOTHTST(SHORT, LONG64, VarI2FromI8, I2_MIN, I2_MAX)
POSTST(SHORT, ULONG64, VarI2FromUI8, I2_MAX)

/* UI2 */
SIMPLE(USHORT, BYTE, VarUI2FromUI1)
NEGTST(USHORT, SHORT, VarUI2FromI2)
BOTHTST(USHORT, LONG, VarUI2FromI4, UI2_MIN, UI2_MAX)
SIMPLE(USHORT, VARIANT_BOOL, VarUI2FromBool)
NEGTST(USHORT, signed char, VarUI2FromI1)
POSTST(USHORT, ULONG, VarUI2FromUI4, UI2_MAX)
BOTHTST(USHORT, LONG64, VarUI2FromI8, UI2_MIN, UI2_MAX)
POSTST(USHORT, ULONG64, VarUI2FromUI8, UI2_MAX)

/* I4 */
SIMPLE(LONG, BYTE, VarI4FromUI1)
SIMPLE(LONG, SHORT, VarI4FromI2)
SIMPLE(LONG, VARIANT_BOOL, VarI4FromBool)
SIMPLE(LONG, signed char, VarI4FromI1)
SIMPLE(LONG, USHORT, VarI4FromUI2)
POSTST(LONG, ULONG, VarI4FromUI4, I4_MAX)
BOTHTST(LONG, LONG64, VarI4FromI8, I4_MIN, I4_MAX)
POSTST(LONG, ULONG64, VarI4FromUI8, I4_MAX)

/* UI4 */
SIMPLE(ULONG, BYTE, VarUI4FromUI1)
NEGTST(ULONG, SHORT, VarUI4FromI2)
NEGTST(ULONG, LONG, VarUI4FromI4)
SIMPLE(ULONG, VARIANT_BOOL, VarUI4FromBool)
NEGTST(ULONG, signed char, VarUI4FromI1)
SIMPLE(ULONG, USHORT, VarUI4FromUI2)
BOTHTST(ULONG, LONG64, VarUI4FromI8, UI4_MIN, UI4_MAX)
POSTST(ULONG, ULONG64, VarUI4FromUI8, UI4_MAX)

/* I8 */
SIMPLE(LONG64, BYTE, VarI8FromUI1)
SIMPLE(LONG64, SHORT, VarI8FromI2)
SIMPLE(LONG64, signed char, VarI8FromI1)
SIMPLE(LONG64, USHORT, VarI8FromUI2)
SIMPLE(LONG64, ULONG, VarI8FromUI4)
POSTST(LONG64, ULONG64, VarI8FromUI8, I8_MAX)

/* UI8 */
SIMPLE(ULONG64, BYTE, VarUI8FromUI1)
NEGTST(ULONG64, SHORT, VarUI8FromI2)
NEGTST(ULONG64, signed char, VarUI8FromI1)
SIMPLE(ULONG64, USHORT, VarUI8FromUI2)
SIMPLE(ULONG64, ULONG, VarUI8FromUI4)
NEGTST(ULONG64, LONG64, VarUI8FromI8)

/* R4 (float) */
SIMPLE(float, BYTE, VarR4FromUI1)
SIMPLE(float, SHORT, VarR4FromI2)
SIMPLE(float, signed char, VarR4FromI1)
SIMPLE(float, USHORT, VarR4FromUI2)
SIMPLE(float, LONG, VarR4FromI4)
SIMPLE(float, ULONG, VarR4FromUI4)
SIMPLE(float, LONG64, VarR4FromI8)
SIMPLE(float, ULONG64, VarR4FromUI8)

/* R8 (double) */
SIMPLE(double, BYTE, VarR8FromUI1)
SIMPLE(double, SHORT, VarR8FromI2)
SIMPLE(double, float, VarR8FromR4)
RETTYP _VarR8FromCy(CY i, double* o) { *o = (double)i.int64 / CY_MULTIPLIER_F; return S_OK; }
SIMPLE(double, DATE, VarR8FromDate)
SIMPLE(double, signed char, VarR8FromI1)
SIMPLE(double, USHORT, VarR8FromUI2)
SIMPLE(double, LONG, VarR8FromI4)
SIMPLE(double, ULONG, VarR8FromUI4)
SIMPLE(double, LONG64, VarR8FromI8)
SIMPLE(double, ULONG64, VarR8FromUI8)

typedef struct DECIMAL_internal
{
    DWORD bitsnum[3];  /* 96 significant bits, unsigned */
    unsigned char scale;      /* number scaled * 10 ^ -(scale) */
    unsigned int  sign : 1;   /* 0 - positive, 1 - negative */
} VARIANT_DI;


typedef union
{
    struct
    {
        unsigned int m : 23;
        unsigned int exp_bias : 8;
        unsigned int sign : 1;
    } i;
    float f;
} R4_FIELDS;


typedef union
{
    struct
    {
        unsigned int m_lo : 32;     /* 52 bits of precision */
        unsigned int m_hi : 20;
        unsigned int exp_bias : 11; /* bias == 1023 */
        unsigned int sign : 1;
    } i;
    double d;
} R8_FIELDS;


static ULONG VARIANT_Add(ULONG ulLeft, ULONG ulRight, ULONG* pulHigh);
static HRESULT VARIANT_BstrReplaceDecimal(WCHAR * buff, LCID lcid, ULONG dwFlags, BSTR *out);
static inline void VARIANT_CopyData(const VARIANT *srcVar, VARTYPE vt, void *pOut);
static void VARIANT_DIFromDec(const DECIMAL * from, VARIANT_DI * to);
static HRESULT VARIANT_DI_FromR4(float source, VARIANT_DI * dest);
static HRESULT VARIANT_DI_FromR8(double source, VARIANT_DI * dest);
static void VARIANT_DI_clear(VARIANT_DI * i);
static HRESULT VARIANT_DI_div(const VARIANT_DI * dividend, const VARIANT_DI * divisor,
                              VARIANT_DI * quotient, BOOL round_remainder);
static int VARIANT_DI_mul(const VARIANT_DI * a, const VARIANT_DI * b, VARIANT_DI * result);
static HRESULT VARIANT_DI_normalize(VARIANT_DI * val, int exponent2, BOOL isDouble);
static BOOL VARIANT_DI_tostringW(const VARIANT_DI * a, WCHAR * s, unsigned int n);
static inline int VARIANT_DecCmp(const DECIMAL *pDecLeft, const DECIMAL *pDecRight);
static void VARIANT_DecFromDI(const VARIANT_DI * from, DECIMAL * to);
static HRESULT VARIANT_DecScale(const DECIMAL** ppDecLeft,
                                const DECIMAL** ppDecRight,
                                DECIMAL pDecOut[2]);
static ULONG VARIANT_Mul(ULONG ulLeft, ULONG ulRight, ULONG* pulHigh);
static HRESULT VARIANT_NumberFromBstr(const OLECHAR* pStrIn, LCID lcid, ULONG ulFlags,
                                      void* pOut, VARTYPE vt);
static ULONG VARIANT_Sub(ULONG ulLeft, ULONG ulRight, ULONG* pulHigh);
static HRESULT VARIANT_do_division(const DECIMAL *pDecLeft, const DECIMAL *pDecRight, DECIMAL *pDecOut,
        BOOL round);
static unsigned char VARIANT_int_add(DWORD * v, unsigned int nv, const DWORD * p,
    unsigned int np);
static int VARIANT_int_addlossy(
    DWORD * a, int * ascale, unsigned int an,
    DWORD * b, int * bscale, unsigned int bn);
static void VARIANT_int_div(DWORD * p, unsigned int n, const DWORD * divisor,
    unsigned int dn);
static unsigned char VARIANT_int_divbychar(DWORD * p, unsigned int n, unsigned char divisor);
static BOOL VARIANT_int_iszero(const DWORD * p, unsigned int n);
static unsigned char VARIANT_int_mulbychar(DWORD * p, unsigned int n, unsigned char m);
static void VARIANT_int_shiftleft(DWORD * p, unsigned int n, unsigned int shift);
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
HRESULT WINAPI shz_wine_VarR4FromDec(const DECIMAL* pDecIn, float *pFltOut);
HRESULT WINAPI shz_wine_VarR8FromDec(const DECIMAL* pDecIn, DOUBLE *pDblOut);
HRESULT WINAPI shz_wine_VarUI1FromDec(const DECIMAL *pdecIn, BYTE* pbOut);
HRESULT WINAPI shz_wine_VarUI2FromDec(const DECIMAL *pdecIn, USHORT* pusOut);
HRESULT WINAPI shz_wine_VarUI4FromDec(const DECIMAL *pdecIn, ULONG *pulOut);
HRESULT WINAPI shz_wine_VarUI4FromStr(const OLECHAR* strIn, LCID lcid, ULONG dwFlags, ULONG *pulOut);
HRESULT WINAPI shz_wine_VarUI8FromDec(const DECIMAL *pdecIn, ULONG64* pui64Out);
HRESULT WINAPI shz_wine_VarUI8FromR8(double dblIn, ULONG64* pui64Out);

/* Wine vartype.c:41 VARIANT_CopyData */
static inline void VARIANT_CopyData(const VARIANT *srcVar, VARTYPE vt, void *pOut)
{
  switch (vt)
  {
  case VT_I1:
  case VT_UI1: memcpy(pOut, &V_UI1(srcVar), sizeof(BYTE)); break;
  case VT_BOOL:
  case VT_I2:
  case VT_UI2: memcpy(pOut, &V_UI2(srcVar), sizeof(SHORT)); break;
  case VT_R4:
  case VT_INT:
  case VT_I4:
  case VT_UINT:
  case VT_UI4: memcpy(pOut, &V_UI4(srcVar), sizeof (LONG)); break;
  case VT_R8:
  case VT_DATE:
  case VT_CY:
  case VT_I8:
  case VT_UI8: memcpy(pOut, &V_UI8(srcVar), sizeof (LONG64)); break;
  case VT_INT_PTR: memcpy(pOut, &V_INT_PTR(srcVar), sizeof (INT_PTR)); break;
  case VT_DECIMAL: memcpy(pOut, &V_DECIMAL(srcVar), sizeof (DECIMAL)); break;
  case VT_BSTR: memcpy(pOut, &V_BSTR(srcVar), sizeof(BSTR)); break;
  default:
    FIXME("VT_ type %d unhandled, please report!\n", vt);
  }
}

/* Wine vartype.c:84 VARIANT_NumberFromBstr */
static HRESULT VARIANT_NumberFromBstr(const OLECHAR* pStrIn, LCID lcid, ULONG ulFlags,
                                      void* pOut, VARTYPE vt)
{
  VARIANTARG dstVar;
  HRESULT hRet;
  NUMPARSE np;
  BYTE rgb[1024];

  /* Use shz_wine_VarParseNumFromStr/shz_wine_VarNumFromParseNum as MSDN indicates */
  np.cDig = ARRAY_SIZE(rgb);
  np.dwInFlags = NUMPRS_STD;

  hRet = shz_wine_VarParseNumFromStr(pStrIn, lcid, ulFlags, &np, rgb);

  if (SUCCEEDED(hRet))
  {
    /* 1 << vt gives us the VTBIT constant for the destination number type */
    hRet = shz_wine_VarNumFromParseNum(&np, rgb, 1 << vt, &dstVar);
    if (SUCCEEDED(hRet))
      VARIANT_CopyData(&dstVar, vt, pOut);
  }
  return hRet;
}

/* Wine vartype.c:828 VarUI1FromDec */
HRESULT WINAPI shz_wine_VarUI1FromDec(const DECIMAL *pdecIn, BYTE* pbOut)
{
  LONG64 i64;
  HRESULT hRet;

  hRet = shz_wine_VarI8FromDec(pdecIn, &i64);

  if (SUCCEEDED(hRet))
    hRet = _VarUI1FromI8(i64, pbOut);
  return hRet;
}

/* Wine vartype.c:1125 VarI2FromDec */
HRESULT WINAPI shz_wine_VarI2FromDec(const DECIMAL *pdecIn, SHORT* psOut)
{
  LONG64 i64;
  HRESULT hRet;

  hRet = shz_wine_VarI8FromDec(pdecIn, &i64);

  if (SUCCEEDED(hRet))
    hRet = _VarI2FromI8(i64, psOut);
  return hRet;
}

/* Wine vartype.c:1422 VarUI2FromDec */
HRESULT WINAPI shz_wine_VarUI2FromDec(const DECIMAL *pdecIn, USHORT* pusOut)
{
  LONG64 i64;
  HRESULT hRet;

  hRet = shz_wine_VarI8FromDec(pdecIn, &i64);

  if (SUCCEEDED(hRet))
    hRet = _VarUI2FromI8(i64, pusOut);
  return hRet;
}

/* Wine vartype.c:1714 VarI4FromDec */
HRESULT WINAPI shz_wine_VarI4FromDec(const DECIMAL *pdecIn, LONG *piOut)
{
  LONG64 i64;
  HRESULT hRet;

  hRet = shz_wine_VarI8FromDec(pdecIn, &i64);

  if (SUCCEEDED(hRet))
    hRet = _VarI4FromI8(i64, piOut);
  return hRet;
}

/* Wine vartype.c:1914 VarUI4FromStr */
HRESULT WINAPI shz_wine_VarUI4FromStr(const OLECHAR* strIn, LCID lcid, ULONG dwFlags, ULONG *pulOut)
{
  return VARIANT_NumberFromBstr(strIn, lcid, dwFlags, pulOut, VT_UI4);
}

/* Wine vartype.c:2006 VarUI4FromDec */
HRESULT WINAPI shz_wine_VarUI4FromDec(const DECIMAL *pdecIn, ULONG *pulOut)
{
  LONG64 i64;
  HRESULT hRet;

  hRet = shz_wine_VarI8FromDec(pdecIn, &i64);

  if (SUCCEEDED(hRet))
    hRet = _VarUI4FromI8(i64, pulOut);
  return hRet;
}

/* Wine vartype.c:2142 VarI8FromR8 */
HRESULT WINAPI shz_wine_VarI8FromR8(double dblIn, LONG64* pi64Out)
{
  if ( dblIn < -4611686018427387904.0 || dblIn >= 4611686018427387904.0)
    return DISP_E_OVERFLOW;
  VARIANT_DutchRound(LONG64, dblIn, *pi64Out);
  return S_OK;
}

/* Wine vartype.c:2329 VarI8FromDec */
HRESULT WINAPI shz_wine_VarI8FromDec(const DECIMAL *pdecIn, LONG64* pi64Out)
{
  ULONG64 mag;
  HRESULT hr = shz_decimal_integer_magnitude(pdecIn, &mag);
  if (FAILED(hr)) return hr;
  if (mag > (pdecIn->sign ? 0x8000000000000000ULL : 0x7fffffffffffffffULL))
    return DISP_E_OVERFLOW;
  *pi64Out = pdecIn->sign ? (LONG64)(0ULL - mag) : (LONG64)mag;
  return S_OK;
}

/* Wine vartype.c:2467 VarUI8FromR8 */
HRESULT WINAPI shz_wine_VarUI8FromR8(double dblIn, ULONG64* pui64Out)
{
  if (dblIn < -0.5 || dblIn > 1.844674407370955e19)
    return DISP_E_OVERFLOW;
  VARIANT_DutchRound(ULONG64, dblIn, *pui64Out);
  return S_OK;
}

/* Wine vartype.c:2664 VarUI8FromDec */
HRESULT WINAPI shz_wine_VarUI8FromDec(const DECIMAL *pdecIn, ULONG64* pui64Out)
{
  ULONG64 mag;
  HRESULT hr = shz_decimal_integer_magnitude(pdecIn, &mag);
  if (FAILED(hr)) return hr;
  if (pdecIn->sign && mag) return DISP_E_OVERFLOW;
  *pui64Out = mag;
  return S_OK;
}

/* Wine vartype.c:2940 VarR4FromDec */
HRESULT WINAPI shz_wine_VarR4FromDec(const DECIMAL* pDecIn, float *pFltOut)
{
  BYTE scale = pDecIn->scale;
  double divisor = 1.0;
  double highPart;

  if (scale > DEC_MAX_SCALE || pDecIn->sign & ~DECIMAL_NEG)
    return E_INVALIDARG;

  while (scale--)
    divisor *= 10.0;

  if (pDecIn->sign)
    divisor = -divisor;

  if (pDecIn->Hi32)
  {
    highPart = (double)pDecIn->Hi32 / divisor;
    highPart *= 4294967296.0F;
    highPart *= 4294967296.0F;
  }
  else
    highPart = 0.0;

  *pFltOut = (double)pDecIn->Lo64 / divisor + highPart;
  return S_OK;
}

/* Wine vartype.c:3261 VarR8FromDec */
HRESULT WINAPI shz_wine_VarR8FromDec(const DECIMAL* pDecIn, DOUBLE *pDblOut)
{
  BYTE scale = pDecIn->scale;
  double divisor = 1.0, highPart;

  if (scale > DEC_MAX_SCALE || pDecIn->sign & ~DECIMAL_NEG)
    return E_INVALIDARG;

  while (scale--)
    divisor *= 10;

  if (pDecIn->sign)
    divisor = -divisor;

  if (pDecIn->Hi32)
  {
    highPart = (double)pDecIn->Hi32 / divisor;
    highPart *= 4294967296.0F;
    highPart *= 4294967296.0F;
  }
  else
    highPart = 0.0;

  *pDblOut = (double)pDecIn->Lo64 / divisor + highPart;
  return S_OK;
}

/* Wine vartype.c:3497 VarCyFromR8 */
HRESULT WINAPI shz_wine_VarCyFromR8(DOUBLE dblIn, CY* pCyOut)
{
#if defined(__i386__) || (defined(__x86_64__) && !defined(__arm64ec__))
  /* This code gives identical results to Win32 on Intel.
   * Here we use fp exceptions to catch overflows when storing the value.
   */
  static const unsigned short r8_fpcontrol = 0x137f;
  static const double r8_multiplier = CY_MULTIPLIER_F;
  unsigned short old_fpcontrol, result_fpstatus;

  /* Clear exceptions, save the old fp state and load the new state */
  __asm__ __volatile__( "fnclex" );
  __asm__ __volatile__( "fstcw %0"   :   "=m" (old_fpcontrol) : );
  __asm__ __volatile__( "fldcw %0"   : : "m"  (r8_fpcontrol) );
  /* Perform the conversion. */
  __asm__ __volatile__( "fldl  %0"   : : "m"  (dblIn) );
  __asm__ __volatile__( "fmull %0"   : : "m"  (r8_multiplier) );
  __asm__ __volatile__( "fistpll %0" : : "m"  (*pCyOut) );
  /* Save the resulting fp state, load the old state and clear exceptions */
  __asm__ __volatile__( "fstsw %0"   :   "=m" (result_fpstatus) : );
  __asm__ __volatile__( "fnclex" );
  __asm__ __volatile__( "fldcw %0"   : : "m"  (old_fpcontrol) );

  if (result_fpstatus & 0x9) /* Overflow | Invalid */
    return DISP_E_OVERFLOW;
#else
  /* This version produces slightly different results for boundary cases */
  if (dblIn < -922337203685477.5807 || dblIn >= 922337203685477.5807)
    return DISP_E_OVERFLOW;
  dblIn *= CY_MULTIPLIER_F;
  VARIANT_DutchRound(LONG64, dblIn, pCyOut->int64);
#endif
  return S_OK;
}

/* Wine vartype.c:4091 VarDecFromUI1 */
HRESULT WINAPI shz_wine_VarDecFromUI1(BYTE bIn, DECIMAL* pDecOut)
{
  return shz_wine_VarDecFromUI4(bIn, pDecOut);
}

/* Wine vartype.c:4108 VarDecFromI2 */
HRESULT WINAPI shz_wine_VarDecFromI2(SHORT sIn, DECIMAL* pDecOut)
{
  return shz_wine_VarDecFromI4(sIn, pDecOut);
}

/* Wine vartype.c:4125 VarDecFromI4 */
HRESULT WINAPI shz_wine_VarDecFromI4(LONG lIn, DECIMAL* pDecOut)
{
  pDecOut->Hi32 = 0;
  pDecOut->Mid32 = 0;
  pDecOut->scale = 0;

  if (lIn < 0)
  {
      pDecOut->sign = DECIMAL_NEG;
      pDecOut->Lo32 = 0u - (ULONG)lIn; /* LONG_MIN is representable as an unsigned magnitude. */
  }
  else
  {
      pDecOut->sign = DECIMAL_POS;
      pDecOut->Lo32 = lIn;
  }
  return S_OK;
}

/* Wine vartype.c:4173 VarDecFromR4 */
HRESULT WINAPI shz_wine_VarDecFromR4(FLOAT fltIn, DECIMAL* pDecOut)
{
  VARIANT_DI di;
  HRESULT hres;

  hres = VARIANT_DI_FromR4(fltIn, &di);
  if (hres == S_OK) VARIANT_DecFromDI(&di, pDecOut);
  return hres;
}

/* Wine vartype.c:4195 VarDecFromR8 */
HRESULT WINAPI shz_wine_VarDecFromR8(DOUBLE dblIn, DECIMAL* pDecOut)
{
  VARIANT_DI di;
  HRESULT hres;

  hres = VARIANT_DI_FromR8(dblIn, &di);
  if (hres == S_OK) VARIANT_DecFromDI(&di, pDecOut);
  return hres;
}

/* Wine vartype.c:4267 VarDecFromStr */
HRESULT WINAPI shz_wine_VarDecFromStr(const OLECHAR* strIn, LCID lcid, ULONG dwFlags, DECIMAL* pDecOut)
{
  return VARIANT_NumberFromBstr(strIn, lcid, dwFlags, pDecOut, VT_DECIMAL);
}

/* Wine vartype.c:4352 VarDecFromUI2 */
HRESULT WINAPI shz_wine_VarDecFromUI2(USHORT usIn, DECIMAL* pDecOut)
{
  return shz_wine_VarDecFromUI4(usIn, pDecOut);
}

/* Wine vartype.c:4369 VarDecFromUI4 */
HRESULT WINAPI shz_wine_VarDecFromUI4(ULONG ulIn, DECIMAL* pDecOut)
{
    pDecOut->sign = DECIMAL_POS;
    pDecOut->scale = 0;
    pDecOut->Hi32 = 0;
    pDecOut->Lo64 = ulIn;
    return S_OK;
}

/* Wine vartype.c:4390 VarDecFromI8 */
HRESULT WINAPI shz_wine_VarDecFromI8(LONG64 llIn, DECIMAL* pDecOut)
{
    pDecOut->Hi32 = 0;
    pDecOut->scale = 0;

    if (llIn < 0)
    {
        pDecOut->sign = DECIMAL_NEG;
        pDecOut->Lo64 = 0ULL - (ULONG64)llIn; /* Avoid signed negation at INT64_MIN. */
    }
    else
    {
        pDecOut->sign = DECIMAL_POS;
        pDecOut->Lo64 = llIn;
    }
    return S_OK;
}

/* Wine vartype.c:4420 VarDecFromUI8 */
HRESULT WINAPI shz_wine_VarDecFromUI8(ULONG64 ullIn, DECIMAL* pDecOut)
{
    pDecOut->sign = DECIMAL_POS;
    pDecOut->scale = 0;
    pDecOut->Hi32 = 0;
    pDecOut->Lo64 = ullIn;
    return S_OK;
}

/* Wine vartype.c:4430 VARIANT_DecScale */
static HRESULT VARIANT_DecScale(const DECIMAL** ppDecLeft,
                                const DECIMAL** ppDecRight,
                                DECIMAL pDecOut[2])
{
  const DECIMAL scaleFactor = {.Lo32 = 10};
  unsigned char remainder;
  DECIMAL decTemp;
  VARIANT_DI di;
  int scaleAmount, i;

  if ((*ppDecLeft)->sign & ~DECIMAL_NEG || (*ppDecRight)->sign & ~DECIMAL_NEG)
    return E_INVALIDARG;

  i = scaleAmount = (*ppDecLeft)->scale - (*ppDecRight)->scale;

  if (!scaleAmount)
    return S_OK; /* Same scale */

  if (scaleAmount > 0)
  {
    decTemp = *(*ppDecRight); /* Left is bigger - scale the right hand side */
    *ppDecRight = &pDecOut[0];
  }
  else
  {
    decTemp = *(*ppDecLeft); /* Right is bigger - scale the left hand side */
    *ppDecLeft  = &pDecOut[0];
    i = -scaleAmount;
  }

  /* Multiply up the value to be scaled by the correct amount (if possible) */
  while (i > 0 && SUCCEEDED(shz_wine_VarDecMul(&decTemp, &scaleFactor, &pDecOut[0])))
  {
    decTemp = pDecOut[0];
    i--;
  }

  if (!i)
  {
    pDecOut[0].scale += (scaleAmount > 0) ? scaleAmount : (-scaleAmount);
    return S_OK; /* Same scale */
  }

  /* Scaling further not possible, reduce accuracy of other argument */
  pDecOut[0] = decTemp;
  if (scaleAmount > 0)
  {
    pDecOut[0].scale += scaleAmount - i;
    VARIANT_DIFromDec(*ppDecLeft, &di);
    *ppDecLeft = &pDecOut[1];
  }
  else
  {
    pDecOut[0].scale += (-scaleAmount) - i;
    VARIANT_DIFromDec(*ppDecRight, &di);
    *ppDecRight = &pDecOut[1];
  }

  di.scale -= i;
  remainder = 0;
  while (i-- > 0 && !VARIANT_int_iszero(di.bitsnum, ARRAY_SIZE(di.bitsnum)))
  {
    remainder = VARIANT_int_divbychar(di.bitsnum, ARRAY_SIZE(di.bitsnum), 10);
    if (remainder > 0) WARN("losing significant digits (remainder %u)...\n", remainder);
  }

  /* round up the result - native oleaut32 does this */
  if (remainder >= 5) {
      for (remainder = 1, i = 0; i < (int)ARRAY_SIZE(di.bitsnum) && remainder; i++) {
          ULONGLONG digit = (ULONGLONG)di.bitsnum[i] + 1;
          remainder = (digit > 0xFFFFFFFF) ? 1 : 0;
          di.bitsnum[i] = digit & 0xFFFFFFFF;
      }
  }

  VARIANT_DecFromDI(&di, &pDecOut[1]);
  return S_OK;
}

/* Wine vartype.c:4512 VARIANT_Add */
static ULONG VARIANT_Add(ULONG ulLeft, ULONG ulRight, ULONG* pulHigh)
{
  ULARGE_INTEGER ul64;

  ul64.QuadPart = (ULONG64)ulLeft + (ULONG64)ulRight + (ULONG64)*pulHigh;
  *pulHigh = ul64.HighPart;
  return ul64.LowPart;
}

/* Wine vartype.c:4522 VARIANT_Sub */
static ULONG VARIANT_Sub(ULONG ulLeft, ULONG ulRight, ULONG* pulHigh)
{
  BOOL invert = FALSE;
  ULARGE_INTEGER ul64;

  ul64.QuadPart = (LONG64)ulLeft - (ULONG64)ulRight;
  if (ulLeft < ulRight)
    invert = TRUE;

  if (ul64.QuadPart > (ULONG64)*pulHigh)
    ul64.QuadPart -= (ULONG64)*pulHigh;
  else
  {
    ul64.QuadPart -= (ULONG64)*pulHigh;
    invert = TRUE;
  }
  if (invert)
    ul64.HighPart = -ul64.HighPart ;

  *pulHigh = ul64.HighPart;
  return ul64.LowPart;
}

/* Wine vartype.c:4546 VARIANT_Mul */
static ULONG VARIANT_Mul(ULONG ulLeft, ULONG ulRight, ULONG* pulHigh)
{
  ULARGE_INTEGER ul64;

  ul64.QuadPart = (ULONG64)ulLeft * (ULONG64)ulRight + (ULONG64)*pulHigh;
  *pulHigh = ul64.HighPart;
  return ul64.LowPart;
}

/* Wine vartype.c:4556 VARIANT_DecCmp */
static inline int VARIANT_DecCmp(const DECIMAL *pDecLeft, const DECIMAL *pDecRight)
{
  if ( pDecLeft->Hi32 < pDecRight->Hi32 ||
      (pDecLeft->Hi32 <= pDecRight->Hi32 && pDecLeft->Lo64 < pDecRight->Lo64))
    return -1;
  else if (pDecLeft->Hi32 == pDecRight->Hi32 && pDecLeft->Lo64 == pDecRight->Lo64)
    return 0;
  return 1;
}

/* Wine vartype.c:4580 VarDecAdd */
HRESULT WINAPI shz_wine_VarDecAdd(const DECIMAL* pDecLeft, const DECIMAL* pDecRight, DECIMAL* pDecOut)
{
  HRESULT hRet;
  DECIMAL scaled[2];

  hRet = VARIANT_DecScale(&pDecLeft, &pDecRight, scaled);

  if (SUCCEEDED(hRet))
  {
    /* Our decimals now have the same scale, we can add them as 96 bit integers */
    ULONG overflow = 0;
    BYTE sign = DECIMAL_POS;
    int cmp;

    /* Correct for the sign of the result */
    if (pDecLeft->sign && pDecRight->sign)
    {
      /* -x + -y : Negative */
      sign = DECIMAL_NEG;
      goto VarDecAdd_AsPositive;
    }
    else if (pDecLeft->sign && !pDecRight->sign)
    {
      cmp = VARIANT_DecCmp(pDecLeft, pDecRight);

      /* -x + y : Negative if x > y */
      if (cmp > 0)
      {
        sign = DECIMAL_NEG;
VarDecAdd_AsNegative:
        pDecOut->Lo32  = VARIANT_Sub(pDecLeft->Lo32,  pDecRight->Lo32,  &overflow);
        pDecOut->Mid32 = VARIANT_Sub(pDecLeft->Mid32, pDecRight->Mid32, &overflow);
        pDecOut->Hi32  = VARIANT_Sub(pDecLeft->Hi32,  pDecRight->Hi32,  &overflow);
      }
      else
      {
VarDecAdd_AsInvertedNegative:
        pDecOut->Lo32  = VARIANT_Sub(pDecRight->Lo32,  pDecLeft->Lo32,  &overflow);
        pDecOut->Mid32 = VARIANT_Sub(pDecRight->Mid32, pDecLeft->Mid32, &overflow);
        pDecOut->Hi32  = VARIANT_Sub(pDecRight->Hi32,  pDecLeft->Hi32,  &overflow);
      }
    }
    else if (!pDecLeft->sign && pDecRight->sign)
    {
      cmp = VARIANT_DecCmp(pDecLeft, pDecRight);

      /* x + -y : Negative if x <= y */
      if (cmp <= 0)
      {
        sign = DECIMAL_NEG;
        goto VarDecAdd_AsInvertedNegative;
      }
      goto VarDecAdd_AsNegative;
    }
    else
    {
      /* x + y : Positive */
VarDecAdd_AsPositive:
      pDecOut->Lo32  = VARIANT_Add(pDecLeft->Lo32,  pDecRight->Lo32,  &overflow);
      pDecOut->Mid32 = VARIANT_Add(pDecLeft->Mid32, pDecRight->Mid32, &overflow);
      pDecOut->Hi32  = VARIANT_Add(pDecLeft->Hi32,  pDecRight->Hi32,  &overflow);

      if (overflow)
      {
        int i;
        DWORD n[4];
        unsigned char remainder;

        if (!pDecLeft->scale)
          return DISP_E_OVERFLOW;

        pDecOut->scale = pDecLeft->scale - 1;
        pDecOut->sign = sign;

        n[0] = pDecOut->Lo32;
        n[1] = pDecOut->Mid32;
        n[2] = pDecOut->Hi32;
        n[3] = overflow;

        remainder = VARIANT_int_divbychar(n,4,10);

        /* round up the result */
        if (remainder >= 5)
        {
          for (remainder = 1, i = 0; i < (int)ARRAY_SIZE(n) && remainder; i++)
          {
            ULONGLONG digit = (ULONGLONG)n[i] + 1;
            remainder = (digit > 0xFFFFFFFF) ? 1 : 0;
            n[i] = digit & 0xFFFFFFFF;
          }
        }

        pDecOut->Lo32 = n[0] ;
        pDecOut->Mid32 = n[1];
        pDecOut->Hi32 = n[2];

        return S_OK;
      }
    }

    if (overflow)
      return DISP_E_OVERFLOW; /* overflowed */

    pDecOut->scale = pDecLeft->scale;
    pDecOut->sign = sign;
  }
  return hRet;
}

/* Wine vartype.c:4690 VARIANT_DIFromDec */
static void VARIANT_DIFromDec(const DECIMAL * from, VARIANT_DI * to)
{
    to->scale = from->scale;
    to->sign = from->sign ? 1 : 0;

    to->bitsnum[0] = from->Lo32;
    to->bitsnum[1] = from->Mid32;
    to->bitsnum[2] = from->Hi32;
}

/* Wine vartype.c:4700 VARIANT_DecFromDI */
static void VARIANT_DecFromDI(const VARIANT_DI * from, DECIMAL * to)
{
    to->sign = from->sign ? DECIMAL_NEG : DECIMAL_POS;
    to->scale = from->scale;
    to->Lo32 = from->bitsnum[0];
    to->Mid32 = from->bitsnum[1];
    to->Hi32 = from->bitsnum[2];
}

/* Wine vartype.c:4710 VARIANT_DI_clear */
static void VARIANT_DI_clear(VARIANT_DI * i)
{
    memset(i, 0, sizeof(VARIANT_DI));
}

/* Wine vartype.c:4720 VARIANT_int_divbychar */
static unsigned char VARIANT_int_divbychar(DWORD * p, unsigned int n, unsigned char divisor)
{
    if (divisor == 0) {
        /* division by 0 */
        return 0xFF;
    } else if (divisor == 1) {
        /* dividend remains unchanged */
        return 0;
    } else {
        unsigned char remainder = 0;
        ULONGLONG iTempDividend;
        signed int i;
        
        for (i = n - 1; i >= 0 && !p[i]; i--);  /* skip leading zeros */
        for (; i >= 0; i--) {
            iTempDividend = ((ULONGLONG)remainder << 32) + p[i];
            remainder = iTempDividend % divisor;
            p[i] = iTempDividend / divisor;
        }
        
        return remainder;
    }
}

/* Wine vartype.c:4745 VARIANT_int_iszero */
static BOOL VARIANT_int_iszero(const DWORD * p, unsigned int n)
{
    for (; n > 0; n--) if (*p++ != 0) return FALSE;
    return TRUE;
}

/* Wine vartype.c:4756 VARIANT_DI_mul */
static int VARIANT_DI_mul(const VARIANT_DI * a, const VARIANT_DI * b, VARIANT_DI * result)
{
    BOOL r_overflow = FALSE;
    DWORD running[6];
    signed int mulstart;

    VARIANT_DI_clear(result);
    result->sign = (a->sign ^ b->sign) ? 1 : 0;

    /* Multiply 128-bit operands into a (max) 256-bit result. The scale
       of the result is formed by adding the scales of the operands.
     */
    result->scale = a->scale + b->scale;
    memset(running, 0, sizeof(running));

    /* count number of leading zero-bytes in operand A */
    for (mulstart = ARRAY_SIZE(a->bitsnum) - 1; mulstart >= 0 && !a->bitsnum[mulstart]; mulstart--);
    if (mulstart < 0) {
        /* result is 0, because operand A is 0 */
        result->scale = 0;
        result->sign = 0;
    } else {
        unsigned char remainder = 0;
        int iA;        

        /* perform actual multiplication */
        for (iA = 0; iA <= mulstart; iA++) {
            ULONG iOverflowMul;
            int iB;
            
            for (iOverflowMul = 0, iB = 0; iB < (int)ARRAY_SIZE(b->bitsnum); iB++) {
                ULONG iRV;
                int iR;
                
                iRV = VARIANT_Mul(b->bitsnum[iB], a->bitsnum[iA], &iOverflowMul);
                iR = iA + iB;
                do {
                    running[iR] = VARIANT_Add(running[iR], 0, &iRV);
                    iR++;
                } while (iRV);
            }
        }

/* Too bad - native oleaut does not do this, so we should not either */
#if 0
        /* While the result is divisible by 10, and the scale > 0, divide by 10.
           This operation should not lose significant digits, and gives an
           opportunity to reduce the possibility of overflows in future
           operations issued by the application.
         */
        while (result->scale > 0) {
            memcpy(quotient, running, sizeof(quotient));
            remainder = VARIANT_int_divbychar(quotient, sizeof(quotient) / sizeof(DWORD), 10);
            if (remainder > 0) break;
            memcpy(running, quotient, sizeof(quotient));
            result->scale--;
        }
#endif
        /* While the 256-bit result overflows, and the scale > 0, divide by 10.
           This operation *will* lose significant digits of the result because
           all the factors of 10 were consumed by the previous operation.
        */
        while (result->scale > 0 && !VARIANT_int_iszero(running + ARRAY_SIZE(result->bitsnum),
            ARRAY_SIZE(running) - ARRAY_SIZE(result->bitsnum))) {

            remainder = VARIANT_int_divbychar(running, ARRAY_SIZE(running), 10);
            if (remainder > 0) WARN("losing significant digits (remainder %u)...\n", remainder);
            result->scale--;
        }
        
        /* round up the result - native oleaut32 does this */
        if (remainder >= 5) {
            unsigned int i;
            for (remainder = 1, i = 0; i < ARRAY_SIZE(running) && remainder; i++) {
                ULONGLONG digit = running[i] + 1;
                remainder = (digit > 0xFFFFFFFF) ? 1 : 0;
                running[i] = digit & 0xFFFFFFFF;
            }
        }

        /* Signal overflow if scale == 0 and 256-bit result still overflows,
           and copy result bits into result structure
        */
        r_overflow = !VARIANT_int_iszero(running + ARRAY_SIZE(result->bitsnum),
            ARRAY_SIZE(running) - ARRAY_SIZE(result->bitsnum));
        memcpy(result->bitsnum, running, sizeof(result->bitsnum));
    }
    return r_overflow;
}

/* Wine vartype.c:4850 VARIANT_DI_tostringW */
static BOOL VARIANT_DI_tostringW(const VARIANT_DI * a, WCHAR * s, unsigned int n)
{
    BOOL overflow = FALSE;
    DWORD quotient[3];
    unsigned char remainder;
    unsigned int i;

    /* place negative sign */
    if (!VARIANT_int_iszero(a->bitsnum, ARRAY_SIZE(a->bitsnum)) && a->sign) {
        if (n > 0) {
            *s++ = '-';
            n--;
        }
        else overflow = TRUE;
    }

    /* prepare initial 0 */
    if (!overflow) {
        if (n >= 2) {
            s[0] = '0';
            s[1] = '\0';
        } else overflow = TRUE;
    }

    i = 0;
    memcpy(quotient, a->bitsnum, sizeof(a->bitsnum));
    while (!overflow && !VARIANT_int_iszero(quotient, ARRAY_SIZE(quotient))) {
        remainder = VARIANT_int_divbychar(quotient, ARRAY_SIZE(quotient), 10);
        if (i + 2 > n) {
            overflow = TRUE;
        } else {
            s[i++] = '0' + remainder;
            s[i] = '\0';
        }
    }

    if (!overflow && !VARIANT_int_iszero(a->bitsnum, ARRAY_SIZE(a->bitsnum))) {

        /* reverse order of digits */
        WCHAR * x = s; WCHAR * y = s + i - 1;
        while (x < y) {
            *x ^= *y;
            *y ^= *x;
            *x++ ^= *y--;
        }

        /* check for decimal point. "i" now has string length */
        if (i <= a->scale) {
            unsigned int numzeroes = a->scale + 1 - i;
            if (i + 1 + numzeroes >= n) {
                overflow = TRUE;
            } else {
                memmove(s + numzeroes, s, (i + 1) * sizeof(WCHAR));
                i += numzeroes;
                while (numzeroes > 0) {
                    s[--numzeroes] = '0';
                }
            }
        }

        /* place decimal point */
        if (a->scale > 0) {
            unsigned int periodpos = i - a->scale;
            if (i + 2 >= n) {
                overflow = TRUE;
            } else {
                memmove(s + periodpos + 1, s + periodpos, (i + 1 - periodpos) * sizeof(WCHAR));
                s[periodpos] = '.'; i++;
                
                /* remove extra zeros at the end, if any */
                while (s[i - 1] == '0') s[--i] = '\0';
                if (s[i - 1] == '.') s[--i] = '\0';
            }
        }
    }

    return !overflow;
}

/* Wine vartype.c:4930 VARIANT_int_shiftleft */
static void VARIANT_int_shiftleft(DWORD * p, unsigned int n, unsigned int shift)
{
    DWORD shifted;
    unsigned int i;
    
    /* shift whole DWORDs to the left */
    while (shift >= 32)
    {
        memmove(p + 1, p, (n - 1) * sizeof(DWORD));
        *p = 0; shift -= 32;
    }
    
    /* shift remainder (1..31 bits) */
    shifted = 0;
    if (shift > 0) for (i = 0; i < n; i++)
    {
        DWORD b;
        b = p[i] >> (32 - shift);
        p[i] = (p[i] << shift) | shifted;
        shifted = b;
    }
}

/* Wine vartype.c:4957 VARIANT_int_add */
static unsigned char VARIANT_int_add(DWORD * v, unsigned int nv, const DWORD * p,
    unsigned int np)
{
    unsigned char carry = 0;

    if (nv >= np) {
        ULONGLONG sum;
        unsigned int i;

        for (i = 0; i < np; i++) {
            sum = (ULONGLONG)v[i]
                + (ULONGLONG)p[i]
                + (ULONGLONG)carry;
            v[i] = sum & 0xffffffff;
            carry = sum >> 32;
        }
        for (; i < nv && carry; i++) {
            sum = (ULONGLONG)v[i]
                + (ULONGLONG)carry;
            v[i] = sum & 0xffffffff;
            carry = sum >> 32;
        }
    }
    return carry;
}

/* Wine vartype.c:4996 VARIANT_int_div */
static void VARIANT_int_div(DWORD * p, unsigned int n, const DWORD * divisor,
    unsigned int dn)
{
    unsigned int i;
    DWORD tempsub[8];
    DWORD * negdivisor = tempsub + n;

    /* build 2s-complement of divisor */
    for (i = 0; i < n; i++) negdivisor[i] = (i < dn) ? ~divisor[i] : 0xFFFFFFFF;
    p[n] = 1;
    VARIANT_int_add(negdivisor, n, p + n, 1);
    memset(p + n, 0, n * sizeof(DWORD));

    /* skip all leading zero DWORDs in quotient */
    for (i = 0; i < n && !p[n - 1]; i++) VARIANT_int_shiftleft(p, n, 32);
    /* i is now number of DWORDs left to process */
    for (i <<= 5; i < (n << 5); i++) {
        VARIANT_int_shiftleft(p, n << 1, 1);    /* shl quotient+remainder */

        /* trial subtraction */
        memcpy(tempsub, p + n, n * sizeof(DWORD));
        VARIANT_int_add(tempsub, n, negdivisor, n);

        /* check whether result of subtraction was negative */
        if ((tempsub[n - 1] & 0x80000000) == 0) {
            memcpy(p + n, tempsub, n * sizeof(DWORD));
            p[0] |= 1;
        }
    }
}

/* Wine vartype.c:5028 VARIANT_int_mulbychar */
static unsigned char VARIANT_int_mulbychar(DWORD * p, unsigned int n, unsigned char m)
{
    unsigned int i;
    ULONG iOverflowMul;
    
    for (iOverflowMul = 0, i = 0; i < n; i++)
        p[i] = VARIANT_Mul(p[i], m, &iOverflowMul);
    return (unsigned char)iOverflowMul;
}

/* Wine vartype.c:5043 VARIANT_int_addlossy */
static int VARIANT_int_addlossy(
    DWORD * a, int * ascale, unsigned int an,
    DWORD * b, int * bscale, unsigned int bn)
{
    int underflow = 0;

    if (VARIANT_int_iszero(a, an)) {
        /* if A is zero, copy B into A, after removing digits */
        while (bn > an && !VARIANT_int_iszero(b + an, bn - an)) {
            VARIANT_int_divbychar(b, bn, 10);
            (*bscale)--;
        }
        memcpy(a, b, an * sizeof(DWORD));
        *ascale = *bscale;
    } else if (!VARIANT_int_iszero(b, bn)) {
        unsigned int tn = an + 1;
        DWORD t[5];

        if (bn + 1 > tn) tn = bn + 1;
        if (*ascale != *bscale) {
            /* first (optimistic) try - try to scale down the one with the bigger
               scale, while this number is divisible by 10 */
            DWORD * digitchosen;
            unsigned int nchosen;
            int * scalechosen;
            int targetscale;

            if (*ascale < *bscale) {
                targetscale = *ascale;
                scalechosen = bscale;
                digitchosen = b;
                nchosen = bn;
            } else {
                targetscale = *bscale;
                scalechosen = ascale;
                digitchosen = a;
                nchosen = an;
            }
            memset(t, 0, tn * sizeof(DWORD));
            memcpy(t, digitchosen, nchosen * sizeof(DWORD));

            /* divide by 10 until target scale is reached */
            while (*scalechosen > targetscale) {
                unsigned char remainder = VARIANT_int_divbychar(t, tn, 10);
                if (!remainder) {
                    (*scalechosen)--;
                    memcpy(digitchosen, t, nchosen * sizeof(DWORD));
                } else break;
            }
        }

        if (*ascale != *bscale) {
            DWORD * digitchosen;
            unsigned int nchosen;
            int * scalechosen;
            int targetscale;

            /* try to scale up the one with the smaller scale */
            if (*ascale > *bscale) {
                targetscale = *ascale;
                scalechosen = bscale;
                digitchosen = b;
                nchosen = bn;
            } else {
                targetscale = *bscale;
                scalechosen = ascale;
                digitchosen = a;
                nchosen = an;
            }
            memset(t, 0, tn * sizeof(DWORD));
            memcpy(t, digitchosen, nchosen * sizeof(DWORD));

            /* multiply by 10 until target scale is reached, or
               significant bytes overflow the number
             */
            while (*scalechosen < targetscale && t[nchosen] == 0) {
                VARIANT_int_mulbychar(t, tn, 10);
                if (t[nchosen] == 0) {
                    /* still does not overflow */
                    (*scalechosen)++;
                    memcpy(digitchosen, t, nchosen * sizeof(DWORD));
                }
            }
        }

        if (*ascale != *bscale) {
            /* still different? try to scale down the one with the bigger scale
               (this *will* lose significant digits) */
            DWORD * digitchosen;
            unsigned int nchosen;
            int * scalechosen;
            int targetscale;

            if (*ascale < *bscale) {
                targetscale = *ascale;
                scalechosen = bscale;
                digitchosen = b;
                nchosen = bn;
            } else {
                targetscale = *bscale;
                scalechosen = ascale;
                digitchosen = a;
                nchosen = an;
            }
            memset(t, 0, tn * sizeof(DWORD));
            memcpy(t, digitchosen, nchosen * sizeof(DWORD));

            /* divide by 10 until target scale is reached */
            while (*scalechosen > targetscale) {
                VARIANT_int_divbychar(t, tn, 10);
                (*scalechosen)--;
                memcpy(digitchosen, t, nchosen * sizeof(DWORD));
            }
        }

        /* check whether any of the operands still has significant digits
           (underflow case 1)
         */
        if (VARIANT_int_iszero(a, an) || VARIANT_int_iszero(b, bn)) {
            underflow = 1;
        } else {
            /* at this step, both numbers have the same scale and can be added
               as integers. However, the result might not fit in A, so further
               scaling down might be necessary.
             */
            while (!underflow) {
                memset(t, 0, tn * sizeof(DWORD));
                memcpy(t, a, an * sizeof(DWORD));

                VARIANT_int_add(t, tn, b, bn);
                if (VARIANT_int_iszero(t + an, tn - an)) {
                    /* addition was successful */
                    memcpy(a, t, an * sizeof(DWORD));
                    break;
                } else {
                    /* addition overflowed - remove significant digits
                       from both operands and try again */
                    VARIANT_int_divbychar(a, an, 10); (*ascale)--;
                    VARIANT_int_divbychar(b, bn, 10); (*bscale)--;
                    /* check whether any operand keeps significant digits after
                       scaledown (underflow case 2)
                     */
                    underflow = (VARIANT_int_iszero(a, an) || VARIANT_int_iszero(b, bn));
                }
            }
        }
    }
    return underflow;
}

/* Wine vartype.c:5197 VARIANT_DI_div */
static HRESULT VARIANT_DI_div(const VARIANT_DI * dividend, const VARIANT_DI * divisor,
                              VARIANT_DI * quotient, BOOL round_remainder)
{
    HRESULT r_overflow = S_OK;

    if (VARIANT_int_iszero(divisor->bitsnum, ARRAY_SIZE(divisor->bitsnum))) {
        /* division by 0 */
        r_overflow = DISP_E_DIVBYZERO;
    } else if (VARIANT_int_iszero(dividend->bitsnum, ARRAY_SIZE(dividend->bitsnum))) {
        VARIANT_DI_clear(quotient);
    } else {
        int quotientscale, remainderscale, tempquotientscale;
        DWORD remainderplusquotient[8];
        int underflow;

        quotientscale = remainderscale = (int)dividend->scale - (int)divisor->scale;
        tempquotientscale = quotientscale;
        VARIANT_DI_clear(quotient);
        quotient->sign = (dividend->sign ^ divisor->sign) ? 1 : 0;

        /*  The following strategy is used for division
            1) if there was a nonzero remainder from previous iteration, use it as
               dividend for this iteration, else (for first iteration) use intended
               dividend
            2) perform integer division in temporary buffer, develop quotient in
               low-order part, remainder in high-order part
            3) add quotient from step 2 to final result, with possible loss of
               significant digits
            4) multiply integer part of remainder by 10, while incrementing the
               scale of the remainder. This operation preserves the intended value
               of the remainder.
            5) loop to step 1 until one of the following is true:
                a) remainder is zero (exact division achieved)
                b) addition in step 3 fails to modify bits in quotient (remainder underflow)
         */
        memset(remainderplusquotient, 0, sizeof(remainderplusquotient));
        memcpy(remainderplusquotient, dividend->bitsnum, sizeof(dividend->bitsnum));
        do {
            VARIANT_int_div(remainderplusquotient, 4, divisor->bitsnum, ARRAY_SIZE(divisor->bitsnum));
            underflow = VARIANT_int_addlossy( quotient->bitsnum, &quotientscale,
                ARRAY_SIZE(quotient->bitsnum), remainderplusquotient, &tempquotientscale, 4);
            if (round_remainder) {
                if(remainderplusquotient[4] >= 5){
                    unsigned int i;
                    unsigned char remainder = 1;
                    for (i = 0; i < ARRAY_SIZE(quotient->bitsnum) && remainder; i++) {
                        ULONGLONG digit = (ULONGLONG)quotient->bitsnum[i] + 1;
                        remainder = (digit > 0xFFFFFFFF) ? 1 : 0;
                        quotient->bitsnum[i] = digit & 0xFFFFFFFF;
                    }
                }
                memset(remainderplusquotient, 0, sizeof(remainderplusquotient));
            } else {
                VARIANT_int_mulbychar(remainderplusquotient + 4, 4, 10);
                memcpy(remainderplusquotient, remainderplusquotient + 4, 4 * sizeof(DWORD));
            }
            tempquotientscale = ++remainderscale;
        } while (!underflow && !VARIANT_int_iszero(remainderplusquotient + 4, 4));

        /* quotient scale might now be negative (extremely big number). If, so, try
           to multiply quotient by 10 (without overflowing), while adjusting the scale,
           until scale is 0. If this cannot be done, it is a real overflow.
         */
        while (r_overflow == S_OK && quotientscale < 0) {
            memset(remainderplusquotient, 0, sizeof(remainderplusquotient));
            memcpy(remainderplusquotient, quotient->bitsnum, sizeof(quotient->bitsnum));
            VARIANT_int_mulbychar(remainderplusquotient, ARRAY_SIZE(remainderplusquotient), 10);
            if (VARIANT_int_iszero(remainderplusquotient + ARRAY_SIZE(quotient->bitsnum),
                ARRAY_SIZE(remainderplusquotient) - ARRAY_SIZE(quotient->bitsnum))) {
                quotientscale++;
                memcpy(quotient->bitsnum, remainderplusquotient, sizeof(quotient->bitsnum));
            } else r_overflow = DISP_E_OVERFLOW;
        }
        if (r_overflow == S_OK) {
            if (quotientscale <= 255) quotient->scale = quotientscale;
            else VARIANT_DI_clear(quotient);
        }
    }
    return r_overflow;
}

/* Wine vartype.c:5285 VARIANT_DI_normalize */
static HRESULT VARIANT_DI_normalize(VARIANT_DI * val, int exponent2, BOOL isDouble)
{
    HRESULT hres = S_OK;
    int exponent5, exponent10;

    /* A factor of 2^exponent2 is equivalent to (10^exponent2)/(5^exponent2), and
       thus equal to (5^-exponent2)*(10^exponent2). After all manipulations,
       exponent10 might be used to set the VARIANT_DI scale directly. However,
       the value of 5^-exponent5 must be assimilated into the VARIANT_DI. */
    exponent5 = -exponent2;
    exponent10 = exponent2;

    /* Handle exponent5 > 0 */
    while (exponent5 > 0) {
        char bPrevCarryBit;
        char bCurrCarryBit;

        /* In order to multiply the value represented by the VARIANT_DI by 5, it
           is best to multiply by 10/2. Therefore, exponent10 is incremented, and
           somehow the mantissa should be divided by 2.  */
        if ((val->bitsnum[0] & 1) == 0) {
            /* The mantissa is divisible by 2. Therefore the division can be done
               without losing significant digits. */
            exponent10++; exponent5--;

            /* Shift right */
            bPrevCarryBit = val->bitsnum[2] & 1;
            val->bitsnum[2] >>= 1;
            bCurrCarryBit = val->bitsnum[1] & 1;
            val->bitsnum[1] = (val->bitsnum[1] >> 1) | (bPrevCarryBit ? 0x80000000 : 0);
            val->bitsnum[0] = (val->bitsnum[0] >> 1) | (bCurrCarryBit ? 0x80000000 : 0);
        } else {
            /* The mantissa is NOT divisible by 2. Therefore the mantissa should
               be multiplied by 5, unless the multiplication overflows. */
            DWORD temp_bitsnum[3];

            exponent5--;

            memcpy(temp_bitsnum, val->bitsnum, 3 * sizeof(DWORD));
            if (0 == VARIANT_int_mulbychar(temp_bitsnum, 3, 5)) {
                /* Multiplication succeeded without overflow, so copy result back
                   into VARIANT_DI */
                memcpy(val->bitsnum, temp_bitsnum, 3 * sizeof(DWORD));

                /* Mask out 3 extraneous bits introduced by the multiply */
            } else {
                /* Multiplication by 5 overflows. The mantissa should be divided
                   by 2, and therefore will lose significant digits. */
                exponent10++;

                /* Shift right */
                bPrevCarryBit = val->bitsnum[2] & 1;
                val->bitsnum[2] >>= 1;
                bCurrCarryBit = val->bitsnum[1] & 1;
                val->bitsnum[1] = (val->bitsnum[1] >> 1) | (bPrevCarryBit ? 0x80000000 : 0);
                val->bitsnum[0] = (val->bitsnum[0] >> 1) | (bCurrCarryBit ? 0x80000000 : 0);
            }
        }
    }

    /* Handle exponent5 < 0 */
    while (exponent5 < 0) {
        /* In order to divide the value represented by the VARIANT_DI by 5, it
           is best to multiply by 2/10. Therefore, exponent10 is decremented,
           and the mantissa should be multiplied by 2 */
        if ((val->bitsnum[2] & 0x80000000) == 0) {
            /* The mantissa can withstand a shift-left without overflowing */
            exponent10--; exponent5++;
            VARIANT_int_shiftleft(val->bitsnum, 3, 1);
        } else {
            /* The mantissa would overflow if shifted. Therefore it should be
               directly divided by 5. This will lose significant digits, unless
               by chance the mantissa happens to be divisible by 5 */
            exponent5++;
            VARIANT_int_divbychar(val->bitsnum, 3, 5);
        }
    }

    /* At this point, the mantissa has assimilated the exponent5, but the
       exponent10 might not be suitable for assignment. The exponent10 must be
       in the range [-DEC_MAX_SCALE..0], so the mantissa must be scaled up or
       down appropriately. */
    while (hres == S_OK && exponent10 > 0) {
        /* In order to bring exponent10 down to 0, the mantissa should be
           multiplied by 10 to compensate. If the exponent10 is too big, this
           will cause the mantissa to overflow. */
        if (0 == VARIANT_int_mulbychar(val->bitsnum, 3, 10)) {
            exponent10--;
        } else {
            hres = DISP_E_OVERFLOW;
        }
    }
    while (exponent10 < -DEC_MAX_SCALE) {
        int rem10;
        /* In order to bring exponent up to -DEC_MAX_SCALE, the mantissa should
           be divided by 10 to compensate. If the exponent10 is too small, this
           will cause the mantissa to underflow and become 0 */
        rem10 = VARIANT_int_divbychar(val->bitsnum, 3, 10);
        exponent10++;
        if (VARIANT_int_iszero(val->bitsnum, 3)) {
            /* Underflow, unable to keep dividing */
            exponent10 = 0;
        } else if (rem10 >= 5) {
            DWORD x = 1;
            VARIANT_int_add(val->bitsnum, 3, &x, 1);
        }
    }
    /* This step is required in order to remove excess bits of precision from the
       end of the bit representation, down to the precision guaranteed by the
       floating point number. */
    if (isDouble) {
        while (exponent10 < 0 && (val->bitsnum[2] != 0 || (val->bitsnum[1] & 0xFFE00000) != 0)) {
            int rem10;

            rem10 = VARIANT_int_divbychar(val->bitsnum, 3, 10);
            exponent10++;
            if (rem10 >= 5) {
                DWORD x = 1;
                VARIANT_int_add(val->bitsnum, 3, &x, 1);
            }
        }
    } else {
        while (exponent10 < 0 && (val->bitsnum[2] != 0 || val->bitsnum[1] != 0 ||
            (val->bitsnum[2] == 0 && val->bitsnum[1] == 0 && (val->bitsnum[0] & 0xFF000000) != 0))) {
            int rem10;

            rem10 = VARIANT_int_divbychar(val->bitsnum, 3, 10);
            exponent10++;
            if (rem10 >= 5) {
                DWORD x = 1;
                VARIANT_int_add(val->bitsnum, 3, &x, 1);
            }
        }
    }
    /* Remove multiples of 10 from the representation */
    while (exponent10 < 0) {
        DWORD temp_bitsnum[3];

        memcpy(temp_bitsnum, val->bitsnum, 3 * sizeof(DWORD));
        if (0 == VARIANT_int_divbychar(temp_bitsnum, 3, 10)) {
            exponent10++;
            memcpy(val->bitsnum, temp_bitsnum, 3 * sizeof(DWORD));
        } else break;
    }

    /* Scale assignment */
    if (hres == S_OK) val->scale = -exponent10;

    return hres;
}

/* Wine vartype.c:5449 VARIANT_DI_FromR4 */
static HRESULT VARIANT_DI_FromR4(float source, VARIANT_DI * dest)
{
    HRESULT hres = S_OK;
    R4_FIELDS fx;

    fx.f = source;

    /* Detect special cases */
    if (fx.i.m == 0 && fx.i.exp_bias == 0) {
        /* Floating-point zero */
        VARIANT_DI_clear(dest);
    } else if (fx.i.m == 0  && fx.i.exp_bias == 0xFF) {
        /* Floating-point infinity */
        hres = DISP_E_OVERFLOW;
    } else if (fx.i.exp_bias == 0xFF) {
        /* Floating-point NaN */
        hres = DISP_E_BADVARTYPE;
    } else {
        int exponent2;
        VARIANT_DI_clear(dest);

        exponent2 = fx.i.exp_bias - 127;   /* Get unbiased exponent */
        dest->sign = fx.i.sign;             /* Sign is simply copied */

        /* Copy significant bits to VARIANT_DI mantissa */
        dest->bitsnum[0] = fx.i.m;
        dest->bitsnum[0] &= 0x007FFFFF;
        if (fx.i.exp_bias == 0) {
            /* Denormalized number - correct exponent */
            exponent2++;
        } else {
            /* Add hidden bit to mantissa */
            dest->bitsnum[0] |= 0x00800000;
        }

        /* The act of copying a FP mantissa as integer bits is equivalent to
           shifting left the mantissa 23 bits. The exponent2 is reduced to
           compensate. */
        exponent2 -= 23;

        hres = VARIANT_DI_normalize(dest, exponent2, FALSE);
    }

    return hres;
}

/* Wine vartype.c:5509 VARIANT_DI_FromR8 */
static HRESULT VARIANT_DI_FromR8(double source, VARIANT_DI * dest)
{
    HRESULT hres = S_OK;
    R8_FIELDS fx;

    fx.d = source;

    /* Detect special cases */
    if (fx.i.m_lo == 0 && fx.i.m_hi == 0 && fx.i.exp_bias == 0) {
        /* Floating-point zero */
        VARIANT_DI_clear(dest);
    } else if (fx.i.m_lo == 0 && fx.i.m_hi == 0 && fx.i.exp_bias == 0x7FF) {
        /* Floating-point infinity */
        hres = DISP_E_OVERFLOW;
    } else if (fx.i.exp_bias == 0x7FF) {
        /* Floating-point NaN */
        hres = DISP_E_BADVARTYPE;
    } else {
        int exponent2;
        VARIANT_DI_clear(dest);

        exponent2 = fx.i.exp_bias - 1023;   /* Get unbiased exponent */
        dest->sign = fx.i.sign;             /* Sign is simply copied */

        /* Copy significant bits to VARIANT_DI mantissa */
        dest->bitsnum[0] = fx.i.m_lo;
        dest->bitsnum[1] = fx.i.m_hi;
        dest->bitsnum[1] &= 0x000FFFFF;
        if (fx.i.exp_bias == 0) {
            /* Denormalized number - correct exponent */
            exponent2++;
        } else {
            /* Add hidden bit to mantissa */
            dest->bitsnum[1] |= 0x00100000;
        }

        /* The act of copying a FP mantissa as integer bits is equivalent to
           shifting left the mantissa 52 bits. The exponent2 is reduced to
           compensate. */
        exponent2 -= 52;

        hres = VARIANT_DI_normalize(dest, exponent2, TRUE);
    }

    return hres;
}

/* Wine vartype.c:5556 VARIANT_do_division */
static HRESULT VARIANT_do_division(const DECIMAL *pDecLeft, const DECIMAL *pDecRight, DECIMAL *pDecOut,
        BOOL round)
{
  HRESULT hRet = S_OK;
  VARIANT_DI di_left, di_right, di_result;
  HRESULT divresult;

  VARIANT_DIFromDec(pDecLeft, &di_left);
  VARIANT_DIFromDec(pDecRight, &di_right);
  divresult = VARIANT_DI_div(&di_left, &di_right, &di_result, round);
  if (divresult != S_OK)
  {
      /* division actually overflowed */
      hRet = divresult;
  }
  else
  {
      hRet = S_OK;

      if (di_result.scale > DEC_MAX_SCALE)
      {
        unsigned char remainder = 0;
      
        /* division underflowed. In order to comply with the MSDN
           specifications for DECIMAL ranges, some significant digits
           must be removed
         */
        WARN("result scale is %u, scaling (with loss of significant digits)...\n",
            di_result.scale);
        while (di_result.scale > DEC_MAX_SCALE && 
               !VARIANT_int_iszero(di_result.bitsnum, ARRAY_SIZE(di_result.bitsnum)))
        {
            remainder = VARIANT_int_divbychar(di_result.bitsnum, ARRAY_SIZE(di_result.bitsnum), 10);
            di_result.scale--;
        }
        if (di_result.scale > DEC_MAX_SCALE)
        {
            WARN("result underflowed, setting to 0\n");
            di_result.scale = 0;
            di_result.sign = 0;
        }
        else if (remainder >= 5)    /* round up result - native oleaut32 does this */
        {
            unsigned int i;
            for (remainder = 1, i = 0; i < ARRAY_SIZE(di_result.bitsnum) && remainder; i++) {
                ULONGLONG digit = (ULONGLONG)di_result.bitsnum[i] + 1;
                remainder = (digit > 0xFFFFFFFF) ? 1 : 0;
                di_result.bitsnum[i] = digit & 0xFFFFFFFF;
            }
        }
      }
      VARIANT_DecFromDI(&di_result, pDecOut);
  }
  return hRet;
}

/* Wine vartype.c:5626 VarDecDiv */
HRESULT WINAPI shz_wine_VarDecDiv(const DECIMAL* pDecLeft, const DECIMAL* pDecRight, DECIMAL* pDecOut)
{
  if (!pDecLeft || !pDecRight || !pDecOut) return E_INVALIDARG;

  return VARIANT_do_division(pDecLeft, pDecRight, pDecOut, FALSE);
}

/* Wine vartype.c:5647 VarDecMul */
HRESULT WINAPI shz_wine_VarDecMul(const DECIMAL* pDecLeft, const DECIMAL* pDecRight, DECIMAL* pDecOut)
{
  HRESULT hRet = S_OK;
  VARIANT_DI di_left, di_right, di_result;
  int mulresult;

  VARIANT_DIFromDec(pDecLeft, &di_left);
  VARIANT_DIFromDec(pDecRight, &di_right);
  mulresult = VARIANT_DI_mul(&di_left, &di_right, &di_result);
  if (mulresult)
  {
    /* multiplication actually overflowed */
    hRet = DISP_E_OVERFLOW;
  }
  else
  {
    if (di_result.scale > DEC_MAX_SCALE)
    {
      /* multiplication underflowed. In order to comply with the MSDN
         specifications for DECIMAL ranges, some significant digits
         must be removed
       */
      WARN("result scale is %u, scaling (with loss of significant digits)...\n",
          di_result.scale);
      while (di_result.scale > DEC_MAX_SCALE && 
            !VARIANT_int_iszero(di_result.bitsnum, ARRAY_SIZE(di_result.bitsnum)))
      {
        VARIANT_int_divbychar(di_result.bitsnum, ARRAY_SIZE(di_result.bitsnum), 10);
        di_result.scale--;
      }
      if (di_result.scale > DEC_MAX_SCALE)
      {
        WARN("result underflowed, setting to 0\n");
        di_result.scale = 0;
        di_result.sign = 0;
      }
    }
    VARIANT_DecFromDI(&di_result, pDecOut);
  }
  return hRet;
}

/* Wine vartype.c:5702 VarDecSub */
HRESULT WINAPI shz_wine_VarDecSub(const DECIMAL* pDecLeft, const DECIMAL* pDecRight, DECIMAL* pDecOut)
{
  DECIMAL decRight;

  /* Implement as addition of the negative */
  shz_wine_VarDecNeg(pDecRight, &decRight);
  return shz_wine_VarDecAdd(pDecLeft, &decRight, pDecOut);
}

/* Wine vartype.c:5819 VarDecNeg */
HRESULT WINAPI shz_wine_VarDecNeg(const DECIMAL* pDecIn, DECIMAL* pDecOut)
{
  *pDecOut = *pDecIn;
  pDecOut->sign ^= DECIMAL_NEG;
  return S_OK;
}

/* Wine vartype.c:5891 VarDecCmp */
HRESULT WINAPI shz_wine_VarDecCmp(const DECIMAL* pDecLeft, const DECIMAL* pDecRight)
{
  HRESULT hRet;
  DECIMAL result;

  if (!pDecLeft || !pDecRight)
    return VARCMP_NULL;

  if ((!(pDecLeft->sign & DECIMAL_NEG)) && (pDecRight->sign & DECIMAL_NEG) &&
      (pDecLeft->Hi32 || pDecLeft->Lo64))
    return VARCMP_GT;
  else if ((pDecLeft->sign & DECIMAL_NEG) && (!(pDecRight->sign & DECIMAL_NEG)) &&
      (pDecLeft->Hi32 || pDecLeft->Lo64))
    return VARCMP_LT;

  /* Subtract right from left, and compare the result to 0 */
  hRet = shz_wine_VarDecSub(pDecLeft, pDecRight, &result);

  if (SUCCEEDED(hRet))
  {
    int non_zero = result.Hi32 || result.Lo64;

    if ((result.sign & DECIMAL_NEG) && non_zero)
      hRet = (HRESULT)VARCMP_LT;
    else if (non_zero)
      hRet = (HRESULT)VARCMP_GT;
    else
      hRet = (HRESULT)VARCMP_EQ;
  }
  return hRet;
}

/* Wine vartype.c:6479 VARIANT_BstrReplaceDecimal */
static HRESULT VARIANT_BstrReplaceDecimal(WCHAR * buff, LCID lcid, ULONG dwFlags, BSTR *out)
{
  BSTR bstrOut;
  WCHAR lpDecimalSep[16];

  /* Native oleaut32 uses the locale-specific decimal separator even in the
     absence of the LOCALE_USE_NLS flag. For example, the Spanish/Latin 
     American locales will see "one thousand and one tenth" as "1000,1" 
     instead of "1000.1" (notice the comma). The following code checks for
     the need to replace the decimal separator, and if so, will prepare an
     appropriate NUMBERFMTW structure to do the job via GetNumberFormatW().
   */
  if (!GetLocaleInfoW(lcid, LOCALE_SDECIMAL | (dwFlags & LOCALE_NOUSEROVERRIDE),
                 lpDecimalSep, ARRAY_SIZE(lpDecimalSep))) return shz_decimal_provider_error();
  if (lpDecimalSep[0] == '.' && lpDecimalSep[1] == '\0')
  {
    /* locale is compatible with English - return original string */
    bstrOut = SysAllocString(buff);
  }
  else
  {
    WCHAR *p, *e;
    WCHAR numbuff[256];
    WCHAR empty[] = L"";
    NUMBERFMTW minFormat;

    minFormat.NumDigits = 0;
    minFormat.Grouping = 0;
    minFormat.lpDecimalSep = lpDecimalSep;
    minFormat.lpThousandSep = empty;
    minFormat.NegativeOrder = 1; /* NLS_NEG_LEFT */

    if (!GetLocaleInfoW(lcid, LOCALE_ILZERO | LOCALE_RETURN_NUMBER | (dwFlags & LOCALE_NOUSEROVERRIDE),
                   (WCHAR *)&minFormat.LeadingZero, sizeof(DWORD)/sizeof(WCHAR))) return shz_decimal_provider_error();

    /* count number of decimal digits in string */
    p = wcschr(buff, '.');
    e = wcschr(p ? ++p : buff, 'E');
    if (p) minFormat.NumDigits = e ? e - p : lstrlenW(p);

    if (e) *e = '\0';
    numbuff[0] = '\0';
    if (!GetNumberFormatW(lcid, 0, buff, &minFormat, numbuff, ARRAY_SIZE(numbuff)))
    {
      if (e) *e = 'E';
      return shz_decimal_provider_error();
    }
    else
    {
      if (e)
      {
        *e = 'E';
        wcscat(numbuff, e);
      }
      TRACE("created minimal NLS string %s\n", debugstr_w(numbuff));
      bstrOut = SysAllocString(numbuff);
    }
  }
  if (!bstrOut) return E_OUTOFMEMORY;
  *out = bstrOut;
  return S_OK;
}

/* Wine vartype.c:7040 VarBstrFromDec */
HRESULT WINAPI shz_wine_VarBstrFromDec(const DECIMAL* pDecIn, LCID lcid, ULONG dwFlags, BSTR* pbstrOut)
{
  WCHAR buff[256];
  VARIANT_DI temp;

  if (!pbstrOut)
    return E_INVALIDARG;

  VARIANT_DIFromDec(pDecIn, &temp);
  VARIANT_DI_tostringW(&temp, buff, 256);

  if (dwFlags & LOCALE_USE_NLS)
  {
    WCHAR numbuff[256];

    /* Format the number for the locale */
    numbuff[0] = '\0';
    if (!GetNumberFormatW(lcid, dwFlags & LOCALE_NOUSEROVERRIDE,
                     buff, NULL, numbuff, ARRAY_SIZE(numbuff))) return shz_decimal_provider_error();
    TRACE("created NLS string %s\n", debugstr_w(numbuff));
    *pbstrOut = SysAllocString(numbuff);
  }
  else
  {
    HRESULT hr = VARIANT_BstrReplaceDecimal(buff, lcid, dwFlags, pbstrOut);
    if (FAILED(hr)) return hr;
  }
  
  TRACE("returning %s\n", debugstr_w(*pbstrOut));
  return *pbstrOut ? S_OK : E_OUTOFMEMORY;
}

DLLAPI HRESULT WINAPI VarDecAdd(DECIMAL* pDecLeft, DECIMAL* pDecRight, DECIMAL* pDecOut)
{
    DECIMAL left, right;
    if (!shz_decimal_valid(pDecLeft) || !shz_decimal_valid(pDecRight)) return E_INVALIDARG;
    if (!pDecOut) return E_INVALIDARG;
    left = *pDecLeft; right = *pDecRight;
    DECIMAL result = {0};
    HRESULT hr;
    hr = shz_wine_VarDecAdd(&left, &right, &result);
    if (SUCCEEDED(hr)) { result.wReserved = 0; *pDecOut = result; }
    return hr;
}

DLLAPI HRESULT WINAPI VarDecDiv(DECIMAL* pDecLeft, DECIMAL* pDecRight, DECIMAL* pDecOut)
{
    DECIMAL left, right;
    if (!shz_decimal_valid(pDecLeft) || !shz_decimal_valid(pDecRight)) return E_INVALIDARG;
    if (!pDecOut) return E_INVALIDARG;
    left = *pDecLeft; right = *pDecRight;
    DECIMAL result = {0};
    HRESULT hr;
    hr = shz_wine_VarDecDiv(&left, &right, &result);
    if (SUCCEEDED(hr)) { result.wReserved = 0; *pDecOut = result; }
    return hr;
}

DLLAPI HRESULT WINAPI VarDecMul(DECIMAL* pDecLeft, DECIMAL* pDecRight, DECIMAL* pDecOut)
{
    DECIMAL left, right;
    if (!shz_decimal_valid(pDecLeft) || !shz_decimal_valid(pDecRight)) return E_INVALIDARG;
    if (!pDecOut) return E_INVALIDARG;
    left = *pDecLeft; right = *pDecRight;
    DECIMAL result = {0};
    HRESULT hr;
    hr = shz_wine_VarDecMul(&left, &right, &result);
    if (SUCCEEDED(hr)) { result.wReserved = 0; *pDecOut = result; }
    return hr;
}

DLLAPI HRESULT WINAPI VarDecSub(DECIMAL* pDecLeft, DECIMAL* pDecRight, DECIMAL* pDecOut)
{
    DECIMAL left, right;
    if (!shz_decimal_valid(pDecLeft) || !shz_decimal_valid(pDecRight)) return E_INVALIDARG;
    if (!pDecOut) return E_INVALIDARG;
    left = *pDecLeft; right = *pDecRight;
    DECIMAL result = {0};
    HRESULT hr;
    hr = shz_wine_VarDecSub(&left, &right, &result);
    if (SUCCEEDED(hr)) { result.wReserved = 0; *pDecOut = result; }
    return hr;
}

DLLAPI HRESULT WINAPI VarDecNeg(DECIMAL* pDecIn, DECIMAL* pDecOut)
{
    DECIMAL input;
    if (!shz_decimal_valid(pDecIn) || !pDecOut) return E_INVALIDARG;
    input = *pDecIn;
    DECIMAL result = {0};
    HRESULT hr;
    hr = shz_wine_VarDecNeg(&input, &result);
    if (SUCCEEDED(hr)) { result.wReserved = 0; *pDecOut = result; }
    return hr;
}

DLLAPI HRESULT WINAPI VarDecFromUI1(BYTE bIn, DECIMAL* pDecOut)
{
    if (!pDecOut) return E_INVALIDARG;
    DECIMAL result = {0};
    HRESULT hr;
    hr = shz_wine_VarDecFromUI1(bIn, &result);
    if (SUCCEEDED(hr)) { result.wReserved = 0; *pDecOut = result; }
    return hr;
}

DLLAPI HRESULT WINAPI VarDecFromI2(SHORT sIn, DECIMAL* pDecOut)
{
    if (!pDecOut) return E_INVALIDARG;
    DECIMAL result = {0};
    HRESULT hr;
    hr = shz_wine_VarDecFromI2(sIn, &result);
    if (SUCCEEDED(hr)) { result.wReserved = 0; *pDecOut = result; }
    return hr;
}

DLLAPI HRESULT WINAPI VarDecFromI4(LONG lIn, DECIMAL* pDecOut)
{
    if (!pDecOut) return E_INVALIDARG;
    DECIMAL result = {0};
    HRESULT hr;
    hr = shz_wine_VarDecFromI4(lIn, &result);
    if (SUCCEEDED(hr)) { result.wReserved = 0; *pDecOut = result; }
    return hr;
}

DLLAPI HRESULT WINAPI VarDecFromR4(FLOAT fltIn, DECIMAL* pDecOut)
{
    if (!pDecOut) return E_INVALIDARG;
    DECIMAL result = {0};
    HRESULT hr;
    hr = shz_wine_VarDecFromR4(fltIn, &result);
    if (SUCCEEDED(hr)) { result.wReserved = 0; *pDecOut = result; }
    return hr;
}

DLLAPI HRESULT WINAPI VarDecFromR8(DOUBLE dblIn, DECIMAL* pDecOut)
{
    if (!pDecOut) return E_INVALIDARG;
    DECIMAL result = {0};
    HRESULT hr;
    hr = shz_wine_VarDecFromR8(dblIn, &result);
    if (SUCCEEDED(hr)) { result.wReserved = 0; *pDecOut = result; }
    return hr;
}

DLLAPI HRESULT WINAPI VarDecFromStr(const OLECHAR* strIn, LCID lcid, ULONG dwFlags, DECIMAL* pDecOut)
{
    if (!pDecOut) return E_INVALIDARG;
    DECIMAL result = {0};
    HRESULT hr;
    hr = shz_wine_VarDecFromStr(strIn, lcid, dwFlags, &result);
    if (SUCCEEDED(hr)) { result.wReserved = 0; *pDecOut = result; }
    return hr;
}

DLLAPI HRESULT WINAPI VarDecCmp(DECIMAL* pDecLeft, DECIMAL* pDecRight)
{
    DECIMAL left, right;
    if (!shz_decimal_valid(pDecLeft) || !shz_decimal_valid(pDecRight)) return E_INVALIDARG;
    left = *pDecLeft; right = *pDecRight;
    return shz_wine_VarDecCmp(&left, &right);
}

DLLAPI HRESULT WINAPI VarI2FromDec(DECIMAL *pdecIn, SHORT* psOut)
{
    DECIMAL input;
    if (!shz_decimal_valid(pdecIn) || !psOut) return E_INVALIDARG;
    input = *pdecIn;
    SHORT result = 0;
    HRESULT hr;
    hr = shz_wine_VarI2FromDec(&input, &result);
    if (SUCCEEDED(hr)) *psOut = result;
    return hr;
}

DLLAPI HRESULT WINAPI VarI4FromDec(DECIMAL *pdecIn, LONG *piOut)
{
    DECIMAL input;
    if (!shz_decimal_valid(pdecIn) || !piOut) return E_INVALIDARG;
    input = *pdecIn;
    LONG result = 0;
    HRESULT hr;
    hr = shz_wine_VarI4FromDec(&input, &result);
    if (SUCCEEDED(hr)) *piOut = result;
    return hr;
}

DLLAPI HRESULT WINAPI VarR4FromDec(DECIMAL* pDecIn, float *pFltOut)
{
    DECIMAL input;
    if (!shz_decimal_valid(pDecIn) || !pFltOut) return E_INVALIDARG;
    input = *pDecIn;
    float result = 0;
    HRESULT hr;
    hr = shz_wine_VarR4FromDec(&input, &result);
    if (SUCCEEDED(hr)) *pFltOut = result;
    return hr;
}

DLLAPI HRESULT WINAPI VarR8FromDec(DECIMAL* pDecIn, DOUBLE *pDblOut)
{
    DECIMAL input;
    if (!shz_decimal_valid(pDecIn) || !pDblOut) return E_INVALIDARG;
    input = *pDecIn;
    DOUBLE result = 0;
    HRESULT hr;
    hr = shz_wine_VarR8FromDec(&input, &result);
    if (SUCCEEDED(hr)) *pDblOut = result;
    return hr;
}

DLLAPI HRESULT WINAPI VarBstrFromDec(DECIMAL* pDecIn, LCID lcid, ULONG dwFlags, BSTR* pbstrOut)
{
    DECIMAL input;
    if (!shz_decimal_valid(pDecIn) || !pbstrOut) return E_INVALIDARG;
    input = *pDecIn;
    BSTR result = NULL;
    HRESULT hr;
    *pbstrOut = NULL;
    hr = shz_wine_VarBstrFromDec(&input, lcid, dwFlags, &result);
    if (SUCCEEDED(hr)) *pbstrOut = result;
    return hr;
}

DLLAPI HRESULT WINAPI VarUI1FromDec(DECIMAL *pdecIn, BYTE* pbOut)
{
    DECIMAL input;
    if (!shz_decimal_valid(pdecIn) || !pbOut) return E_INVALIDARG;
    input = *pdecIn;
    BYTE result = 0;
    HRESULT hr;
    hr = shz_wine_VarUI1FromDec(&input, &result);
    if (SUCCEEDED(hr)) *pbOut = result;
    return hr;
}

DLLAPI HRESULT WINAPI VarDecFromUI2(USHORT usIn, DECIMAL* pDecOut)
{
    if (!pDecOut) return E_INVALIDARG;
    DECIMAL result = {0};
    HRESULT hr;
    hr = shz_wine_VarDecFromUI2(usIn, &result);
    if (SUCCEEDED(hr)) { result.wReserved = 0; *pDecOut = result; }
    return hr;
}

DLLAPI HRESULT WINAPI VarDecFromUI4(ULONG ulIn, DECIMAL* pDecOut)
{
    if (!pDecOut) return E_INVALIDARG;
    DECIMAL result = {0};
    HRESULT hr;
    hr = shz_wine_VarDecFromUI4(ulIn, &result);
    if (SUCCEEDED(hr)) { result.wReserved = 0; *pDecOut = result; }
    return hr;
}

DLLAPI HRESULT WINAPI VarUI2FromDec(DECIMAL *pdecIn, USHORT* pusOut)
{
    DECIMAL input;
    if (!shz_decimal_valid(pdecIn) || !pusOut) return E_INVALIDARG;
    input = *pdecIn;
    USHORT result = 0;
    HRESULT hr;
    hr = shz_wine_VarUI2FromDec(&input, &result);
    if (SUCCEEDED(hr)) *pusOut = result;
    return hr;
}

DLLAPI HRESULT WINAPI VarUI4FromStr(const OLECHAR* strIn, LCID lcid, ULONG dwFlags, ULONG *pulOut)
{
    if (!pulOut) return E_INVALIDARG;
    ULONG result = 0;
    HRESULT hr;
    hr = shz_wine_VarUI4FromStr(strIn, lcid, dwFlags, &result);
    if (SUCCEEDED(hr)) *pulOut = result;
    return hr;
}

DLLAPI HRESULT WINAPI VarUI4FromDec(DECIMAL *pdecIn, ULONG *pulOut)
{
    DECIMAL input;
    if (!shz_decimal_valid(pdecIn) || !pulOut) return E_INVALIDARG;
    input = *pdecIn;
    ULONG result = 0;
    HRESULT hr;
    hr = shz_wine_VarUI4FromDec(&input, &result);
    if (SUCCEEDED(hr)) *pulOut = result;
    return hr;
}

DLLAPI HRESULT WINAPI VarI8FromDec(DECIMAL *pdecIn, LONG64* pi64Out)
{
    DECIMAL input;
    if (!shz_decimal_valid(pdecIn) || !pi64Out) return E_INVALIDARG;
    input = *pdecIn;
    LONG64 result = 0;
    HRESULT hr;
    hr = shz_wine_VarI8FromDec(&input, &result);
    if (SUCCEEDED(hr)) *pi64Out = result;
    return hr;
}

DLLAPI HRESULT WINAPI VarDecFromI8(LONG64 llIn, DECIMAL* pDecOut)
{
    if (!pDecOut) return E_INVALIDARG;
    DECIMAL result = {0};
    HRESULT hr;
    hr = shz_wine_VarDecFromI8(llIn, &result);
    if (SUCCEEDED(hr)) { result.wReserved = 0; *pDecOut = result; }
    return hr;
}

DLLAPI HRESULT WINAPI VarDecFromUI8(ULONG64 ullIn, DECIMAL* pDecOut)
{
    if (!pDecOut) return E_INVALIDARG;
    DECIMAL result = {0};
    HRESULT hr;
    hr = shz_wine_VarDecFromUI8(ullIn, &result);
    if (SUCCEEDED(hr)) { result.wReserved = 0; *pDecOut = result; }
    return hr;
}

DLLAPI HRESULT WINAPI VarUI8FromDec(DECIMAL *pdecIn, ULONG64* pui64Out)
{
    DECIMAL input;
    if (!shz_decimal_valid(pdecIn) || !pui64Out) return E_INVALIDARG;
    input = *pdecIn;
    ULONG64 result = 0;
    HRESULT hr;
    hr = shz_wine_VarUI8FromDec(&input, &result);
    if (SUCCEEDED(hr)) *pui64Out = result;
    return hr;
}
