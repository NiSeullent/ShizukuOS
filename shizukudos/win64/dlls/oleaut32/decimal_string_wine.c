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
/* The localised characters that make up a valid number */
typedef struct tagVARIANT_NUMBER_CHARS
{
  WCHAR cNegativeSymbol;
  WCHAR cPositiveSymbol;
  WCHAR cDecimalPoint;
  WCHAR cDigitSeparator;
  DWORD sCurrencyLen;
  WCHAR sCurrency[8];
  WCHAR cCurrencyDecimalPoint;
  WCHAR cCurrencyDigitSeparator;
} VARIANT_NUMBER_CHARS;

#define GET_NUMBER_TEXT(fld,name) do { \
  buff[0] = 0; \
  if (!GetLocaleInfoW(lcid, lctype|fld, buff, ARRAY_SIZE(buff))) \
    return shz_decimal_provider_error(); \
  if (buff[0]) lpChars->name = buff[0]; \
} while (0)
#define B_PROCESSING_EXPONENT 0x1
#define B_NEGATIVE_EXPONENT   0x2
#define B_EXPONENT_START      0x4
#define B_INEXACT_ZEROS       0x8
#define B_LEADING_ZERO        0x10
#define B_PROCESSING_HEX      0x20
#define B_PROCESSING_OCT      0x40

/* VTBIT flags indicating an integer value */
#define INTEGER_VTBITS (VTBIT_I1|VTBIT_UI1|VTBIT_I2|VTBIT_UI2|VTBIT_I4|VTBIT_UI4|VTBIT_I8|VTBIT_UI8)
/* VTBIT flags indicating a real number value */
#define REAL_VTBITS (VTBIT_R4|VTBIT_R8|VTBIT_CY)

/* Helper macros to check whether bit pattern fits in VARIANT (x is a ULONG64 ) */
#define FITS_AS_I1(x) ((x) >> 8 == 0)
#define FITS_AS_I2(x) ((x) >> 16 == 0)
#define FITS_AS_I4(x) ((x) >> 32 == 0)


/* Wine variant.c:1509 VARIANT_GetLocalisedNumberChars */
static HRESULT VARIANT_GetLocalisedNumberChars(VARIANT_NUMBER_CHARS *lpChars, LCID lcid, DWORD dwFlags)
{
  static const VARIANT_NUMBER_CHARS defaultChars = { '-','+','.',0,1,{'$',0},0,',' };
  LCTYPE lctype = dwFlags & LOCALE_NOUSEROVERRIDE;
  WCHAR buff[4];

  memcpy(lpChars, &defaultChars, sizeof(defaultChars));
  GET_NUMBER_TEXT(LOCALE_SNEGATIVESIGN, cNegativeSymbol);
  GET_NUMBER_TEXT(LOCALE_SPOSITIVESIGN, cPositiveSymbol);
  GET_NUMBER_TEXT(LOCALE_SDECIMAL, cDecimalPoint);
  GET_NUMBER_TEXT(LOCALE_STHOUSAND, cDigitSeparator);
  GET_NUMBER_TEXT(LOCALE_SMONDECIMALSEP, cCurrencyDecimalPoint);
  GET_NUMBER_TEXT(LOCALE_SMONTHOUSANDSEP, cCurrencyDigitSeparator);

  if (!GetLocaleInfoW(lcid, lctype|LOCALE_SCURRENCY, lpChars->sCurrency, ARRAY_SIZE(lpChars->sCurrency)))
    return shz_decimal_provider_error();
  lpChars->sCurrencyLen = wcslen(lpChars->sCurrency);
  return S_OK;
}

/* Wine variant.c:1544 is_digit */
static inline BOOL is_digit(WCHAR c)
{
    return '0' <= c && c <= '9';
}

/* Wine variant.c:1579 VarParseNumFromStr */
HRESULT WINAPI shz_wine_VarParseNumFromStr(const OLECHAR *lpszStr, LCID lcid, ULONG dwFlags,
                                  NUMPARSE *pNumprs, BYTE *rgbDig)
{
  VARIANT_NUMBER_CHARS chars;
  BYTE rgbTmp[1024];
  DWORD dwState = B_EXPONENT_START|B_INEXACT_ZEROS;
  int iMaxDigits = ARRAY_SIZE(rgbTmp);
  int cchUsed = 0;
  OLECHAR cDigitSeparator2;

  TRACE("%s, %#lx, %#lx, %p, %p.\n", debugstr_w(lpszStr), lcid, dwFlags, pNumprs, rgbDig);

  if (!pNumprs || !rgbDig)
    return E_INVALIDARG;

  if (pNumprs->cDig < iMaxDigits)
    iMaxDigits = pNumprs->cDig;

  pNumprs->cDig = 0;
  pNumprs->dwOutFlags = 0;
  pNumprs->cchUsed = 0;
  pNumprs->nBaseShift = 0;
  pNumprs->nPwr10 = 0;

  if (!lpszStr)
    return DISP_E_TYPEMISMATCH;

  { HRESULT hr = VARIANT_GetLocalisedNumberChars(&chars, lcid, dwFlags);
    if (FAILED(hr)) return hr; }
  if (chars.cDigitSeparator == chars.cDecimalPoint)
    /* The decimal point completely masks the digit separator */
    chars.cDigitSeparator = 0;
  /* Setting the thousands separator to a non-breaking space implies regular
   * spaces are allowed too. But the converse is not true.
   */
  cDigitSeparator2 = chars.cDigitSeparator == 0xa0 ? ' ' : 0;

  /* First consume all the leading symbols and space from the string */
  while (1)
  {
    if (pNumprs->dwInFlags & NUMPRS_DECIMAL &&
        (*lpszStr == chars.cDecimalPoint ||
         *lpszStr == chars.cCurrencyDecimalPoint))
    {
      pNumprs->dwOutFlags |= NUMPRS_DECIMAL;
      if (*lpszStr == chars.cCurrencyDecimalPoint &&
        chars.cDecimalPoint != chars.cCurrencyDecimalPoint)
        pNumprs->dwOutFlags |= NUMPRS_CURRENCY;
      cchUsed++;
      lpszStr++;

      /* If we have no digits so far, skip leading zeros */
      if (!pNumprs->cDig)
      {
        while (*lpszStr == '0')
        {
          dwState |= B_LEADING_ZERO;
          cchUsed++;
          lpszStr++;
          pNumprs->nPwr10--;
        }
      }
      break;
    }
    else if (pNumprs->dwInFlags & NUMPRS_LEADING_WHITE && iswspace(*lpszStr))
    {
      pNumprs->dwOutFlags |= NUMPRS_LEADING_WHITE;
      do
      {
        cchUsed++;
        lpszStr++;
      } while (iswspace(*lpszStr));
    }
    else if (pNumprs->dwInFlags & NUMPRS_THOUSANDS &&
             ((chars.cDigitSeparator && *lpszStr == chars.cDigitSeparator) ||
              (cDigitSeparator2 && *lpszStr == cDigitSeparator2)))
    {
      return DISP_E_TYPEMISMATCH; /* Not allowed before the first digit */
    }
    else if ((pNumprs->dwInFlags & (NUMPRS_THOUSANDS|NUMPRS_CURRENCY)) == (NUMPRS_THOUSANDS|NUMPRS_CURRENCY) &&
             chars.cCurrencyDigitSeparator && *lpszStr == chars.cCurrencyDigitSeparator)
    {
      return DISP_E_TYPEMISMATCH; /* Not allowed before the first digit */
    }
    else if (pNumprs->dwInFlags & NUMPRS_LEADING_PLUS &&
             *lpszStr == chars.cPositiveSymbol &&
             !(pNumprs->dwOutFlags & NUMPRS_LEADING_PLUS))
    {
      pNumprs->dwOutFlags |= NUMPRS_LEADING_PLUS;
      cchUsed++;
      lpszStr++;
    }
    else if (pNumprs->dwInFlags & NUMPRS_LEADING_MINUS &&
             *lpszStr == chars.cNegativeSymbol &&
             !(pNumprs->dwOutFlags & NUMPRS_LEADING_MINUS))
    {
      pNumprs->dwOutFlags |= (NUMPRS_LEADING_MINUS|NUMPRS_NEG);
      cchUsed++;
      lpszStr++;
    }
    else if (pNumprs->dwInFlags & NUMPRS_CURRENCY &&
             !(pNumprs->dwOutFlags & NUMPRS_CURRENCY) &&
             wcsncmp(lpszStr, chars.sCurrency, chars.sCurrencyLen) == 0)
    {
      pNumprs->dwOutFlags |= NUMPRS_CURRENCY;
      cchUsed += chars.sCurrencyLen;
      lpszStr += chars.sCurrencyLen;
    }
    else if (pNumprs->dwInFlags & NUMPRS_PARENS && *lpszStr == '(' &&
             !(pNumprs->dwOutFlags & NUMPRS_PARENS))
    {
      pNumprs->dwOutFlags |= NUMPRS_PARENS;
      cchUsed++;
      lpszStr++;
    }
    else
      break;
  }

  if (!(pNumprs->dwOutFlags & (NUMPRS_CURRENCY|NUMPRS_DECIMAL)))
  {
    if ((*lpszStr == '&' && (*(lpszStr+1) == 'H' || *(lpszStr+1) == 'h')) &&
        pNumprs->dwInFlags & NUMPRS_HEX_OCT)
    {
      dwState |= B_PROCESSING_HEX;
      pNumprs->dwOutFlags |= NUMPRS_HEX_OCT;
      cchUsed=cchUsed+2;
      lpszStr=lpszStr+2;
    }
    else if ((*lpszStr == '&' && (*(lpszStr+1) == 'O' || *(lpszStr+1) == 'o')) &&
             pNumprs->dwInFlags & NUMPRS_HEX_OCT)
    {
      dwState |= B_PROCESSING_OCT;
      pNumprs->dwOutFlags |= NUMPRS_HEX_OCT;
      cchUsed=cchUsed+2;
      lpszStr=lpszStr+2;
    }
  }

  /* Strip Leading zeros */
  while (*lpszStr == '0')
  {
    dwState |= B_LEADING_ZERO;
    cchUsed++;
    lpszStr++;
  }

  while (*lpszStr)
  {
    if (is_digit(*lpszStr))
    {
      if (dwState & B_PROCESSING_EXPONENT)
      {
        int exponentSize = 0;
        if (dwState & B_EXPONENT_START)
        {
          if (!is_digit(*lpszStr))
            break; /* No exponent digits - invalid */
          while (*lpszStr == '0')
          {
            /* Skip leading zero's in the exponent */
            cchUsed++;
            lpszStr++;
          }
        }

        while (is_digit(*lpszStr))
        {
          /* Saturate only beyond any representable DECIMAL/UI4 range, while
           * continuing to consume all exponent digits without signed overflow. */
          if (exponentSize < 1000000) {
            exponentSize = exponentSize * 10 + (*lpszStr - '0');
            if (exponentSize > 1000000) exponentSize = 1000000;
          }
          cchUsed++;
          lpszStr++;
        }
        if (dwState & B_NEGATIVE_EXPONENT)
          exponentSize = -exponentSize;
        /* Add the exponent into the powers of 10 */
        { LONG64 power = (LONG64)pNumprs->nPwr10 + exponentSize;
          pNumprs->nPwr10 = power > 1000000 ? 1000000 : power < -1000000 ? -1000000 : (INT)power; }
        dwState &= ~(B_PROCESSING_EXPONENT|B_EXPONENT_START);
        lpszStr--; /* back up to allow processing of next char */
      }
      else
      {
        if ((pNumprs->cDig >= iMaxDigits) && !(dwState & B_PROCESSING_HEX)
          && !(dwState & B_PROCESSING_OCT))
        {
          pNumprs->dwOutFlags |= NUMPRS_INEXACT;

          if (*lpszStr != '0')
            dwState &= ~B_INEXACT_ZEROS; /* Inexact number with non-trailing zeros */

          /* This digit can't be represented, but count it in nPwr10 */
          if (pNumprs->dwOutFlags & NUMPRS_DECIMAL)
            pNumprs->nPwr10--;
          else
            pNumprs->nPwr10++;
        }
        else
        {
          if ((dwState & B_PROCESSING_OCT) && ((*lpszStr == '8') || (*lpszStr == '9')))
            break;

          if (pNumprs->dwOutFlags & NUMPRS_DECIMAL)
            pNumprs->nPwr10--; /* Count decimal points in nPwr10 */

          rgbTmp[pNumprs->cDig] = *lpszStr - '0';
        }
        pNumprs->cDig++;
        cchUsed++;
      }
    }
    else if (pNumprs->dwInFlags & NUMPRS_THOUSANDS &&
             !(pNumprs->dwOutFlags & NUMPRS_HEX_OCT) &&
             ((chars.cDigitSeparator && *lpszStr == chars.cDigitSeparator) ||
              (cDigitSeparator2 && *lpszStr == cDigitSeparator2)))
    {
      pNumprs->dwOutFlags |= NUMPRS_THOUSANDS;
      cchUsed++;
    }
    else if ((pNumprs->dwInFlags & (NUMPRS_THOUSANDS|NUMPRS_CURRENCY)) == (NUMPRS_THOUSANDS|NUMPRS_CURRENCY) &&
             !(pNumprs->dwOutFlags & NUMPRS_HEX_OCT) &&
             chars.cCurrencyDigitSeparator && *lpszStr == chars.cCurrencyDigitSeparator)
    {
      pNumprs->dwOutFlags |= NUMPRS_THOUSANDS|NUMPRS_CURRENCY;
      cchUsed++;
    }
    else if (pNumprs->dwInFlags & NUMPRS_DECIMAL &&
             (*lpszStr == chars.cDecimalPoint ||
              *lpszStr == chars.cCurrencyDecimalPoint) &&
             !(pNumprs->dwOutFlags & (NUMPRS_HEX_OCT|NUMPRS_DECIMAL|NUMPRS_EXPONENT)))
    {
      pNumprs->dwOutFlags |= NUMPRS_DECIMAL;
      if (*lpszStr == chars.cCurrencyDecimalPoint &&
        chars.cDecimalPoint != chars.cCurrencyDecimalPoint)
        pNumprs->dwOutFlags |= NUMPRS_CURRENCY;
      cchUsed++;

      /* If we have no digits so far, skip leading zeros */
      if (!pNumprs->cDig)
      {
        while (lpszStr[1] == '0')
        {
          dwState |= B_LEADING_ZERO;
          cchUsed++;
          lpszStr++;
          pNumprs->nPwr10--;
        }
      }
    }
    else if (((*lpszStr >= 'a' && *lpszStr <= 'f') ||
             (*lpszStr >= 'A' && *lpszStr <= 'F')) &&
             dwState & B_PROCESSING_HEX)
    {
      if (pNumprs->cDig >= iMaxDigits)
      {
        return DISP_E_OVERFLOW;
      }
      else
      {
        if (*lpszStr >= 'a')
          rgbTmp[pNumprs->cDig] = *lpszStr - 'a' + 10;
        else
          rgbTmp[pNumprs->cDig] = *lpszStr - 'A' + 10;
      }
      pNumprs->cDig++;
      cchUsed++;
    }
    else if ((*lpszStr == 'e' || *lpszStr == 'E') &&
             pNumprs->dwInFlags & NUMPRS_EXPONENT &&
             !(pNumprs->dwOutFlags & (NUMPRS_HEX_OCT|NUMPRS_CURRENCY|NUMPRS_EXPONENT)))
    {
      dwState |= B_PROCESSING_EXPONENT;
      pNumprs->dwOutFlags |= NUMPRS_EXPONENT;
      cchUsed++;
    }
    else if (dwState & B_PROCESSING_EXPONENT && *lpszStr == chars.cPositiveSymbol)
    {
      cchUsed++; /* Ignore positive exponent */
    }
    else if (dwState & B_PROCESSING_EXPONENT && *lpszStr == chars.cNegativeSymbol)
    {
      dwState |= B_NEGATIVE_EXPONENT;
      cchUsed++;
    }
    else
      break; /* Stop at an unrecognised character */

    lpszStr++;
  }

  if (!pNumprs->cDig && dwState & B_LEADING_ZERO)
  {
    /* Ensure a 0 on its own gets stored */
    pNumprs->cDig = 1;
    rgbTmp[0] = 0;
  }

  if (pNumprs->dwOutFlags & NUMPRS_EXPONENT && dwState & B_PROCESSING_EXPONENT)
  {
    pNumprs->cchUsed = cchUsed;
    WARN("didn't completely parse exponent\n");
    return DISP_E_TYPEMISMATCH; /* Failed to completely parse the exponent */
  }

  if (pNumprs->dwOutFlags & NUMPRS_INEXACT)
  {
    if (dwState & B_INEXACT_ZEROS)
      pNumprs->dwOutFlags &= ~NUMPRS_INEXACT; /* All zeros doesn't set NUMPRS_INEXACT */
  } else if(pNumprs->dwInFlags & NUMPRS_HEX_OCT)
  {
    /* copy all of the digits into the output digit buffer */
    /* this is exactly what windows does although it also returns */
    /* cDig of X and writes X+Y where Y>=0 number of digits to rgbDig */
    memcpy(rgbDig, rgbTmp, pNumprs->cDig * sizeof(BYTE));

    if (dwState & B_PROCESSING_HEX) {
      /* hex numbers have always the same format */
      pNumprs->nPwr10=0;
      pNumprs->nBaseShift=4;
    } else {
      if (dwState & B_PROCESSING_OCT) {
        /* oct numbers have always the same format */
        pNumprs->nPwr10=0;
        pNumprs->nBaseShift=3;
      } else {
        while (pNumprs->cDig > 1 && !rgbTmp[pNumprs->cDig - 1])
        {
          pNumprs->nPwr10++;
          pNumprs->cDig--;
        }
      }
    }
  } else
  {
    /* Remove trailing zeros from the last (whole number or decimal) part */
    while (pNumprs->cDig > 1 && !rgbTmp[pNumprs->cDig - 1])
    {
      pNumprs->nPwr10++;
      pNumprs->cDig--;
    }
  }

  if (pNumprs->cDig <= iMaxDigits)
    pNumprs->dwOutFlags &= ~NUMPRS_INEXACT; /* Ignore stripped zeros for NUMPRS_INEXACT */
  else
    pNumprs->cDig = iMaxDigits; /* Only return iMaxDigits worth of digits */

  /* Copy the digits we processed into rgbDig */
  memcpy(rgbDig, rgbTmp, pNumprs->cDig * sizeof(BYTE));

  /* Consume any trailing symbols and space */
  while (1)
  {
    if ((chars.cDigitSeparator && *lpszStr == chars.cDigitSeparator) ||
        (cDigitSeparator2 && *lpszStr == cDigitSeparator2))
    {
      if (pNumprs->dwInFlags & NUMPRS_THOUSANDS &&
          !(pNumprs->dwOutFlags & NUMPRS_HEX_OCT))
      {
        pNumprs->dwOutFlags |= NUMPRS_THOUSANDS;
        cchUsed++;
        lpszStr++;
      }
      else
      {
        /* Not allowed, even with NUMPRS_TRAILING_WHITE */
        break;
      }
    }
    else if (*lpszStr == chars.cCurrencyDigitSeparator)
    {
      if ((pNumprs->dwInFlags & (NUMPRS_THOUSANDS|NUMPRS_CURRENCY)) == (NUMPRS_THOUSANDS|NUMPRS_CURRENCY) &&
          !(pNumprs->dwOutFlags & NUMPRS_HEX_OCT))
      {
        pNumprs->dwOutFlags |= NUMPRS_THOUSANDS|NUMPRS_CURRENCY;
        cchUsed++;
        lpszStr++;
      }
      else
      {
        /* Not allowed, even with NUMPRS_TRAILING_WHITE */
        break;
      }
    }
    else if ((pNumprs->dwInFlags & NUMPRS_TRAILING_WHITE) && iswspace(*lpszStr))
    {
      pNumprs->dwOutFlags |= NUMPRS_TRAILING_WHITE;
      do
      {
        cchUsed++;
        lpszStr++;
      } while (iswspace(*lpszStr));
    }
    else if (pNumprs->dwInFlags & NUMPRS_TRAILING_PLUS &&
             !(pNumprs->dwOutFlags & NUMPRS_LEADING_PLUS) &&
             *lpszStr == chars.cPositiveSymbol)
    {
      pNumprs->dwOutFlags |= NUMPRS_TRAILING_PLUS;
      cchUsed++;
      lpszStr++;
    }
    else if (pNumprs->dwInFlags & NUMPRS_TRAILING_MINUS &&
             !(pNumprs->dwOutFlags & NUMPRS_LEADING_MINUS) &&
             *lpszStr == chars.cNegativeSymbol)
    {
      pNumprs->dwOutFlags |= (NUMPRS_TRAILING_MINUS|NUMPRS_NEG);
      cchUsed++;
      lpszStr++;
    }
    else if (pNumprs->dwInFlags & NUMPRS_PARENS && *lpszStr == ')' &&
             pNumprs->dwOutFlags & NUMPRS_PARENS)
    {
      cchUsed++;
      lpszStr++;
      pNumprs->dwOutFlags |= NUMPRS_NEG;
    }
    else if (pNumprs->dwInFlags & NUMPRS_CURRENCY &&
             !(pNumprs->dwOutFlags & NUMPRS_HEX_OCT) &&
             wcsncmp(lpszStr, chars.sCurrency, chars.sCurrencyLen) == 0)
    {
      pNumprs->dwOutFlags |= NUMPRS_CURRENCY;
      cchUsed += chars.sCurrencyLen;
      lpszStr += chars.sCurrencyLen;
    }
    else
      break;
  }

  if (pNumprs->dwOutFlags & NUMPRS_PARENS && !(pNumprs->dwOutFlags & NUMPRS_NEG))
  {
    pNumprs->cchUsed = cchUsed;
    return DISP_E_TYPEMISMATCH; /* Opening parenthesis not matched */
  }

  if (pNumprs->dwInFlags & NUMPRS_USE_ALL && *lpszStr != '\0')
    return DISP_E_TYPEMISMATCH; /* Not all chars were consumed */

  if (!pNumprs->cDig)
    return DISP_E_TYPEMISMATCH; /* No Number found */

  pNumprs->cchUsed = cchUsed;
  return S_OK;
}

/* Narrow DECIMAL output of the genuine parser. Wine's byte-scale assignment
 * wrapped at 256 and allowed invalid scale >28. Retain all discarded digits
 * while selecting the largest representable scale, then round half to even.
 * Multiplication of limbs follows the selected Wine conversion body below. */
static HRESULT shz_decimal_from_parsed(const NUMPARSE *np, const BYTE *digits, DECIMAL *out)
{
    int scale, i;
    BOOL negative = !!(np->dwOutFlags & NUMPRS_NEG);
    for (i = 0; i < np->cDig && !digits[i]; ++i) {}
    if (i == np->cDig) { memset(out, 0, sizeof(*out)); return S_OK; }
    if ((LONG64)np->cDig + np->nPwr10 > 29) return DISP_E_OVERFLOW;
    scale = np->nPwr10 < 0 ? (np->nPwr10 < -28 ? 28 : -np->nPwr10) : 0;
    for (; scale >= 0; --scale) {
        DECIMAL value = {0};
        LONG64 kept = (LONG64)np->cDig + np->nPwr10 + scale;
        ULONG64 temp;
        ULONG carry;
        BOOL overflow = FALSE, sticky = !!(np->dwOutFlags & NUMPRS_INEXACT);
        BYTE first = 0;
        if (kept > 29) continue;
        for (i = 0; i < kept; ++i) {
            BYTE digit = i < np->cDig ? digits[i] : 0;
            temp = (ULONG64)value.Lo32 * 10 + digit;
            value.Lo32 = (ULONG)temp; carry = (ULONG)(temp >> 32);
            temp = (ULONG64)value.Mid32 * 10 + carry;
            value.Mid32 = (ULONG)temp; carry = (ULONG)(temp >> 32);
            temp = (ULONG64)value.Hi32 * 10 + carry;
            value.Hi32 = (ULONG)temp;
            if (temp >> 32) { overflow = TRUE; break; }
        }
        if (overflow) continue;
        if (kept >= 0 && kept < np->cDig) {
            first = digits[kept];
            for (i = (int)kept + 1; i < np->cDig; ++i) sticky |= digits[i] != 0;
        }
        if (first > 5 || (first == 5 && (sticky || (value.Lo32 & 1)))) {
            temp = (ULONG64)value.Lo32 + 1;
            value.Lo32 = (ULONG)temp; carry = (ULONG)(temp >> 32);
            temp = (ULONG64)value.Mid32 + carry;
            value.Mid32 = (ULONG)temp; carry = (ULONG)(temp >> 32);
            temp = (ULONG64)value.Hi32 + carry;
            value.Hi32 = (ULONG)temp;
            if (temp >> 32) continue;
        }
        value.scale = (BYTE)scale;
        value.sign = negative ? DECIMAL_NEG : DECIMAL_POS;
        *out = value;
        return S_OK;
    }
    return DISP_E_OVERFLOW;
}

/* Wine variant.c:2061 VarNumFromParseNum */
HRESULT WINAPI shz_wine_VarNumFromParseNum(NUMPARSE *pNumprs, BYTE *rgbDig,
                                  ULONG dwVtBits, VARIANT *pVarDst)
{
  if (dwVtBits == VTBIT_DECIMAL) {
    HRESULT hr = shz_decimal_from_parsed(pNumprs, rgbDig, &V_DECIMAL(pVarDst));
    if (SUCCEEDED(hr)) V_VT(pVarDst) = VT_DECIMAL;
    return hr;
  }

  /* Scale factors and limits for double arithmetic */
  static const double dblMultipliers[11] = {
    1.0, 10.0, 100.0, 1000.0, 10000.0, 100000.0,
    1000000.0, 10000000.0, 100000000.0, 1000000000.0, 10000000000.0
  };
  static const double dblMinimums[11] = {
    R8_MIN, R8_MIN*10.0, R8_MIN*100.0, R8_MIN*1000.0, R8_MIN*10000.0,
    R8_MIN*100000.0, R8_MIN*1000000.0, R8_MIN*10000000.0,
    R8_MIN*100000000.0, R8_MIN*1000000000.0, R8_MIN*10000000000.0
  };
  static const double dblMaximums[11] = {
    R8_MAX, R8_MAX/10.0, R8_MAX/100.0, R8_MAX/1000.0, R8_MAX/10000.0,
    R8_MAX/100000.0, R8_MAX/1000000.0, R8_MAX/10000000.0,
    R8_MAX/100000000.0, R8_MAX/1000000000.0, R8_MAX/10000000000.0
  };

  int wholeNumberDigits, fractionalDigits, divisor10 = 0, multiplier10 = 0;

  TRACE("%p, %p, %lx, %p.\n", pNumprs, rgbDig, dwVtBits, pVarDst);

  if (pNumprs->nBaseShift)
  {
    /* nBaseShift indicates a hex or octal number */
    ULONG64 ul64 = 0;
    LONG64 l64;
    int i;

    /* Convert the hex or octal number string into a UI64 */
    for (i = 0; i < pNumprs->cDig; i++)
    {
      if (ul64 > ((UI8_MAX>>pNumprs->nBaseShift) - rgbDig[i]))
      {
        TRACE("Overflow multiplying digits\n");
        return DISP_E_OVERFLOW;
      }
      ul64 = (ul64<<pNumprs->nBaseShift) + rgbDig[i];
    }

    /* also make a negative representation */
    l64=-ul64;

    /* Try signed and unsigned types in size order */
    if (dwVtBits & VTBIT_I1 && FITS_AS_I1(ul64))
    {
      V_VT(pVarDst) = VT_I1;
      V_I1(pVarDst) = ul64;
      return S_OK;
    }
    else if (dwVtBits & VTBIT_UI1 && FITS_AS_I1(ul64))
    {
      V_VT(pVarDst) = VT_UI1;
      V_UI1(pVarDst) = ul64;
      return S_OK;
    }
    else if (dwVtBits & VTBIT_I2 && FITS_AS_I2(ul64))
    {
      V_VT(pVarDst) = VT_I2;
      V_I2(pVarDst) = ul64;
      return S_OK;
    }
    else if (dwVtBits & VTBIT_UI2 && FITS_AS_I2(ul64))
    {
      V_VT(pVarDst) = VT_UI2;
      V_UI2(pVarDst) = ul64;
      return S_OK;
    }
    else if (dwVtBits & VTBIT_I4 && FITS_AS_I4(ul64))
    {
      V_VT(pVarDst) = VT_I4;
      V_I4(pVarDst) = ul64;
      return S_OK;
    }
    else if (dwVtBits & VTBIT_UI4 && FITS_AS_I4(ul64))
    {
      V_VT(pVarDst) = VT_UI4;
      V_UI4(pVarDst) = ul64;
      return S_OK;
    }
    else if (dwVtBits & VTBIT_I8 && ((ul64 <= I8_MAX)||(l64>=I8_MIN)))
    {
      V_VT(pVarDst) = VT_I8;
      V_I8(pVarDst) = ul64;
      return S_OK;
    }
    else if (dwVtBits & VTBIT_UI8)
    {
      V_VT(pVarDst) = VT_UI8;
      V_UI8(pVarDst) = ul64;
      return S_OK;
    }
    else if ((dwVtBits & VTBIT_DECIMAL) == VTBIT_DECIMAL)
    {
      V_VT(pVarDst) = VT_DECIMAL;
      V_DECIMAL(pVarDst).sign = DECIMAL_POS;
      V_DECIMAL(pVarDst).scale = 0;
      V_DECIMAL(pVarDst).Hi32 = 0;
      V_DECIMAL(pVarDst).Lo64 = ul64;
      return S_OK;
    }
    else if (dwVtBits & VTBIT_R4 && ((ul64 <= I4_MAX)||(l64 >= I4_MIN)))
    {
      V_VT(pVarDst) = VT_R4;
      if (ul64 <= I4_MAX)
          V_R4(pVarDst) = ul64;
      else
          V_R4(pVarDst) = l64;
      return S_OK;
    }
    else if (dwVtBits & VTBIT_R8 && ((ul64 <= I4_MAX)||(l64 >= I4_MIN)))
    {
      V_VT(pVarDst) = VT_R8;
      if (ul64 <= I4_MAX)
          V_R8(pVarDst) = ul64;
      else
          V_R8(pVarDst) = l64;
      return S_OK;
    }

    TRACE("Overflow: possible return types: %#lx, value: %s\n", dwVtBits, wine_dbgstr_longlong(ul64));
    return DISP_E_OVERFLOW;
  }

  /* Count the number of relevant fractional and whole digits stored,
   * And compute the divisor/multiplier to scale the number by.
   */
  if (pNumprs->nPwr10 < 0)
  {
    if (-pNumprs->nPwr10 >= pNumprs->cDig)
    {
      /* A real number < +/- 1.0 e.g. 0.1024 or 0.01024 */
      wholeNumberDigits = 0;
      fractionalDigits = pNumprs->cDig;
      divisor10 = -pNumprs->nPwr10;
    }
    else
    {
      /* An exactly represented real number e.g. 1.024 */
      wholeNumberDigits = pNumprs->cDig + pNumprs->nPwr10;
      fractionalDigits = pNumprs->cDig - wholeNumberDigits;
      divisor10 = pNumprs->cDig - wholeNumberDigits;
    }
  }
  else if (pNumprs->nPwr10 == 0)
  {
    /* An exactly represented whole number e.g. 1024 */
    wholeNumberDigits = pNumprs->cDig;
    fractionalDigits = 0;
  }
  else /* pNumprs->nPwr10 > 0 */
  {
    /* A whole number followed by nPwr10 0's e.g. 102400 */
    wholeNumberDigits = pNumprs->cDig;
    fractionalDigits = 0;
    multiplier10 = pNumprs->nPwr10;
  }

  TRACE("cDig %d; nPwr10 %d, whole %d, frac %d mult %d; div %d\n",
        pNumprs->cDig, pNumprs->nPwr10, wholeNumberDigits, fractionalDigits,
        multiplier10, divisor10);

  if (dwVtBits & (INTEGER_VTBITS|VTBIT_DECIMAL) &&
      (!fractionalDigits || !(dwVtBits & (REAL_VTBITS|VTBIT_DECIMAL))))
  {
    /* We have one or more integer output choices, and either:
     *  1) An integer input value, or
     *  2) A real number input value but no floating output choices.
     * Alternately, we have a DECIMAL output available and an integer input.
     *
     * So, place the integer value into pVarDst, using the smallest type
     * possible and preferring signed over unsigned types.
     */
    BOOL bOverflow = FALSE, bNegative;
    ULONG64 ul64 = 0;
    int i;

    /* Convert the integer part of the number into a UI8 */
    for (i = 0; i < wholeNumberDigits; i++)
    {
      if (ul64 > UI8_MAX / 10 || (ul64 == UI8_MAX / 10 && rgbDig[i] > UI8_MAX % 10))
      {
        TRACE("Overflow multiplying digits\n");
        bOverflow = TRUE;
        break;
      }
      ul64 = ul64 * 10 + rgbDig[i];
    }

    /* Account for the scale of the number */
    if (!bOverflow && multiplier10)
    {
      for (i = 0; i < multiplier10; i++)
      {
        if (ul64 > (UI8_MAX / 10))
        {
          TRACE("Overflow scaling number\n");
          bOverflow = TRUE;
          break;
        }
        ul64 = ul64 * 10;
      }
    }

    /* If we have any fractional digits, round the value.
     * Note we don't have to do this if divisor10 is < 1,
     * because this means the fractional part must be < 0.5
     */
    if (!bOverflow && fractionalDigits && divisor10 > 0)
    {
      const BYTE* fracDig = rgbDig + wholeNumberDigits;
      BOOL bAdjust = FALSE;

      TRACE("first decimal value is %d\n", *fracDig);

      if (*fracDig > 5)
        bAdjust = TRUE; /* > 0.5 */
      else if (*fracDig == 5)
      {
        for (i = 1; i < fractionalDigits; i++)
        {
          if (fracDig[i])
          {
            bAdjust = TRUE; /* > 0.5 */
            break;
          }
        }
        /* If exactly 0.5, round only odd values */
        if (i == fractionalDigits && (ul64 & 1))
          bAdjust = TRUE;
      }

      if (bAdjust)
      {
        if (ul64 == UI8_MAX)
        {
          TRACE("Overflow after rounding\n");
          bOverflow = TRUE;
        }
        ul64++;
      }
    }

    /* Zero is not a negative number */
    bNegative = pNumprs->dwOutFlags & NUMPRS_NEG && ul64;

    TRACE("Integer value is 0x%s, bNeg %d\n", wine_dbgstr_longlong(ul64), bNegative);

    /* For negative integers, try the signed types in size order */
    if (!bOverflow && bNegative)
    {
      if (dwVtBits & (VTBIT_I1|VTBIT_I2|VTBIT_I4|VTBIT_I8))
      {
        if (dwVtBits & VTBIT_I1 && ul64 <= -I1_MIN)
        {
          V_VT(pVarDst) = VT_I1;
          V_I1(pVarDst) = -ul64;
          return S_OK;
        }
        else if (dwVtBits & VTBIT_I2 && ul64 <= -I2_MIN)
        {
          V_VT(pVarDst) = VT_I2;
          V_I2(pVarDst) = -ul64;
          return S_OK;
        }
        else if (dwVtBits & VTBIT_I4 && ul64 <= -((LONGLONG)I4_MIN))
        {
          V_VT(pVarDst) = VT_I4;
          V_I4(pVarDst) = -ul64;
          return S_OK;
        }
        else if (dwVtBits & VTBIT_I8 && ul64 <= (ULONGLONG)I8_MAX + 1)
        {
          V_VT(pVarDst) = VT_I8;
          V_I8(pVarDst) = -ul64;
          return S_OK;
        }
        else if ((dwVtBits & (REAL_VTBITS|VTBIT_DECIMAL)) == VTBIT_DECIMAL)
        {
          /* Decimal is only output choice left - fast path */
          V_VT(pVarDst) = VT_DECIMAL;
          V_DECIMAL(pVarDst).sign = DECIMAL_NEG;
          V_DECIMAL(pVarDst).scale = 0;
          V_DECIMAL(pVarDst).Hi32 = 0;
          V_DECIMAL(pVarDst).Lo64 = -ul64;
          return S_OK;
        }
      }
    }
    else if (!bOverflow)
    {
      /* For positive integers, try signed then unsigned types in size order */
      if (dwVtBits & VTBIT_I1 && ul64 <= I1_MAX)
      {
        V_VT(pVarDst) = VT_I1;
        V_I1(pVarDst) = ul64;
        return S_OK;
      }
      else if (dwVtBits & VTBIT_UI1 && ul64 <= UI1_MAX)
      {
        V_VT(pVarDst) = VT_UI1;
        V_UI1(pVarDst) = ul64;
        return S_OK;
      }
      else if (dwVtBits & VTBIT_I2 && ul64 <= I2_MAX)
      {
        V_VT(pVarDst) = VT_I2;
        V_I2(pVarDst) = ul64;
        return S_OK;
      }
      else if (dwVtBits & VTBIT_UI2 && ul64 <= UI2_MAX)
      {
        V_VT(pVarDst) = VT_UI2;
        V_UI2(pVarDst) = ul64;
        return S_OK;
      }
      else if (dwVtBits & VTBIT_I4 && ul64 <= I4_MAX)
      {
        V_VT(pVarDst) = VT_I4;
        V_I4(pVarDst) = ul64;
        return S_OK;
      }
      else if (dwVtBits & VTBIT_UI4 && ul64 <= UI4_MAX)
      {
        V_VT(pVarDst) = VT_UI4;
        V_UI4(pVarDst) = ul64;
        return S_OK;
      }
      else if (dwVtBits & VTBIT_I8 && ul64 <= I8_MAX)
      {
        V_VT(pVarDst) = VT_I8;
        V_I8(pVarDst) = ul64;
        return S_OK;
      }
      else if (dwVtBits & VTBIT_UI8)
      {
        V_VT(pVarDst) = VT_UI8;
        V_UI8(pVarDst) = ul64;
        return S_OK;
      }
      else if ((dwVtBits & (REAL_VTBITS|VTBIT_DECIMAL)) == VTBIT_DECIMAL)
      {
        /* Decimal is only output choice left - fast path */
        V_VT(pVarDst) = VT_DECIMAL;
        V_DECIMAL(pVarDst).sign = DECIMAL_POS;
        V_DECIMAL(pVarDst).scale = 0;
        V_DECIMAL(pVarDst).Hi32 = 0;
        V_DECIMAL(pVarDst).Lo64 = ul64;
        return S_OK;
      }
    }
  }

  if (dwVtBits & REAL_VTBITS)
  {
    /* Try to put the number into a float or real */
    BOOL bOverflow = FALSE, bNegative = pNumprs->dwOutFlags & NUMPRS_NEG;
    double whole = 0.0;
    int i;

    /* Convert the number into a double */
    for (i = 0; i < pNumprs->cDig; i++)
      whole = whole * 10.0 + rgbDig[i];

    TRACE("Whole double value is %16.16g\n", whole);

    /* Account for the scale */
    while (multiplier10 > 10)
    {
      if (whole > dblMaximums[10])
      {
        dwVtBits &= ~(VTBIT_R4|VTBIT_R8|VTBIT_CY);
        bOverflow = TRUE;
        break;
      }
      whole = whole * dblMultipliers[10];
      multiplier10 -= 10;
    }
    if (multiplier10 && !bOverflow)
    {
      if (whole > dblMaximums[multiplier10])
      {
        dwVtBits &= ~(VTBIT_R4|VTBIT_R8|VTBIT_CY);
        bOverflow = TRUE;
      }
      else
        whole = whole * dblMultipliers[multiplier10];
    }

    if (!bOverflow)
        TRACE("Scaled double value is %16.16g\n", whole);

    while (divisor10 > 10 && !bOverflow)
    {
      if (whole < dblMinimums[10] && whole != 0)
      {
        whole = 0; /* ignore underflow */
        divisor10 = 0;
        break;
      }
      whole = whole / dblMultipliers[10];
      divisor10 -= 10;
    }
    if (divisor10 && !bOverflow)
    {
      if (whole < dblMinimums[divisor10] && whole != 0)
      {
        whole = 0; /* ignore underflow */
        divisor10 = 0;
      }
      else
        whole = whole / dblMultipliers[divisor10];
    }
    if (!bOverflow)
      TRACE("Final double value is %16.16g\n", whole);

    if (dwVtBits & VTBIT_R4 &&
        ((whole <= R4_MAX && whole >= R4_MIN) || whole == 0.0))
    {
      TRACE("Set R4 to final value\n");
      V_VT(pVarDst) = VT_R4; /* Fits into a float */
      V_R4(pVarDst) = pNumprs->dwOutFlags & NUMPRS_NEG ? -whole : whole;
      return S_OK;
    }

    if (dwVtBits & VTBIT_R8)
    {
      TRACE("Set R8 to final value\n");
      V_VT(pVarDst) = VT_R8; /* Fits into a double */
      V_R8(pVarDst) = pNumprs->dwOutFlags & NUMPRS_NEG ? -whole : whole;
      return S_OK;
    }

    if (dwVtBits & VTBIT_CY)
    {
      if (SUCCEEDED(shz_wine_VarCyFromR8(bNegative ? -whole : whole, &V_CY(pVarDst))))
      {
        V_VT(pVarDst) = VT_CY; /* Fits into a currency */
        TRACE("Set CY to final value\n");
        return S_OK;
      }
      TRACE("Value Overflows CY\n");
    }
  }

  if (dwVtBits & VTBIT_DECIMAL)
  {
    int i;
    ULONG carry;
    ULONG64 tmp;
    DECIMAL* pDec = &V_DECIMAL(pVarDst);

    DECIMAL_SETZERO(*pDec);
    pDec->Lo32 = 0;

    if (pNumprs->dwOutFlags & NUMPRS_NEG)
      pDec->sign = DECIMAL_NEG;
    else
      pDec->sign = DECIMAL_POS;

    /* Factor the significant digits */
    for (i = 0; i < pNumprs->cDig; i++)
    {
      tmp = (ULONG64)pDec->Lo32 * 10 + rgbDig[i];
      carry = (ULONG)(tmp >> 32);
      pDec->Lo32 = (ULONG)tmp;
      tmp = (ULONG64)pDec->Mid32 * 10 + carry;
      carry = (ULONG)(tmp >> 32);
      pDec->Mid32 = (ULONG)tmp;
      tmp = (ULONG64)pDec->Hi32 * 10 + carry;
      pDec->Hi32 = (ULONG)tmp;

      if (tmp >> 32)
      {
VarNumFromParseNum_DecOverflow:
        TRACE("Overflow\n");
        pDec->Lo32 = pDec->Mid32 = pDec->Hi32 = UI4_MAX;
        return DISP_E_OVERFLOW;
      }
    }

    /* Account for the scale of the number */
    while (multiplier10 > 0)
    {
      tmp = (ULONG64)pDec->Lo32 * 10;
      carry = (ULONG)(tmp >> 32);
      pDec->Lo32 = (ULONG)tmp;
      tmp = (ULONG64)pDec->Mid32 * 10 + carry;
      carry = (ULONG)(tmp >> 32);
      pDec->Mid32 = (ULONG)tmp;
      tmp = (ULONG64)pDec->Hi32 * 10 + carry;
      pDec->Hi32 = (ULONG)tmp;

      if (tmp >> 32)
        goto VarNumFromParseNum_DecOverflow;
      multiplier10--;
    }
    pDec->scale = divisor10;

    V_VT(pVarDst) = VT_DECIMAL;
    return S_OK;
  }
  return DISP_E_OVERFLOW; /* No more output choices */
}
