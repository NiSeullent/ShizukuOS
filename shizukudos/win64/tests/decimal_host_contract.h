/* SPDX-License-Identifier: GPL-2.0-only
 * Windows AMD64 Automation ABI and explicitly bounded host NLS/BSTR adapters.
 * These adapters validate error paths; they are not guest locale/backend evidence. */
#ifndef SHZ_DECIMAL_HOST_CONTRACT_H
#define SHZ_DECIMAL_HOST_CONTRACT_H
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>
#include <pthread.h>
typedef int32_t HRESULT, LONG, BOOL, INT;
typedef uint32_t DWORD, ULONG, UINT, LCID, LCTYPE;
typedef uint8_t BYTE;
typedef uint16_t WORD, USHORT, WCHAR, OLECHAR, VARTYPE;
typedef int16_t SHORT, VARIANT_BOOL;
typedef int64_t LONG64, LONGLONG, INT_PTR;
typedef uint64_t ULONG64, ULONGLONG;
typedef double DOUBLE, DATE;
typedef float FLOAT;
typedef union { uint64_t QuadPart; struct {uint32_t LowPart, HighPart;}; } ULARGE_INTEGER;
typedef OLECHAR *BSTR;
typedef union { int64_t int64; struct {uint32_t Lo; int32_t Hi;}; } CY;
typedef struct { WORD wReserved; BYTE scale, sign; DWORD Hi32; union { struct { DWORD Lo32, Mid32; }; ULONG64 Lo64; }; } DECIMAL;
typedef union { DECIMAL decVal; struct { WORD vt, reserved[3]; union { BYTE bVal; int8_t cVal; SHORT iVal; USHORT uiVal; LONG lVal; ULONG ulVal; LONG64 llVal; ULONG64 ullVal; float fltVal; DOUBLE dblVal; CY cyVal; BSTR bstrVal; INT_PTR intPtrVal; void *record[2]; }; }; } VARIANT, VARIANTARG;
#define V_VT(v) ((v)->vt)
#define V_DECIMAL(v) ((v)->decVal)
#define V_UI1(v) ((v)->bVal)
#define V_I1(v) ((v)->cVal)
#define V_UI2(v) ((v)->uiVal)
#define V_I2(v) ((v)->iVal)
#define V_UI4(v) ((v)->ulVal)
#define V_I4(v) ((v)->lVal)
#define V_UI8(v) ((v)->ullVal)
#define V_I8(v) ((v)->llVal)
#define V_R4(v) ((v)->fltVal)
#define V_R8(v) ((v)->dblVal)
#define V_CY(v) ((v)->cyVal)
#define V_BSTR(v) ((v)->bstrVal)
#define V_INT_PTR(v) ((v)->intPtrVal)
enum {VT_EMPTY=0, VT_NULL=1, VT_I2=2, VT_I4=3, VT_R4=4, VT_R8=5, VT_CY=6, VT_DATE=7, VT_BSTR=8, VT_BOOL=11, VT_DECIMAL=14, VT_I1=16, VT_UI1=17, VT_UI2=18, VT_UI4=19, VT_I8=20, VT_UI8=21, VT_INT=22, VT_UINT=23, VT_INT_PTR=37};
#define DECIMAL_NEG 0x80
#define DECIMAL_SETZERO(d) memset(&(d),0,sizeof(d))
#define WINAPI
#define DLLAPI
#define TRUE 1
#define FALSE 0
#define S_OK ((HRESULT)0)
#define E_INVALIDARG ((HRESULT)0x80070057u)
#define E_OUTOFMEMORY ((HRESULT)0x8007000eu)
#define DISP_E_OVERFLOW ((HRESULT)0x8002000au)
#define DISP_E_TYPEMISMATCH ((HRESULT)0x80020005u)
#define DISP_E_BADVARTYPE ((HRESULT)0x80020008u)
#define DISP_E_DIVBYZERO ((HRESULT)0x80020012u)
#define VARCMP_LT 0
#define VARCMP_EQ 1
#define VARCMP_GT 2
#define VARCMP_NULL 3
#define SUCCEEDED(hr) ((HRESULT)(hr)>=0)
#define FAILED(hr) ((HRESULT)(hr)<0)
#define HRESULT_FROM_WIN32(e) ((HRESULT)(((DWORD)(e)!=0)?(0x80070000u|((e)&0xffff)):0))
#define ERROR_INVALID_PARAMETER 87
#define ERROR_INVALID_FLAGS 1004
#define ERROR_INSUFFICIENT_BUFFER 122
#define ERROR_ACCESS_DENIED 5
#define LOCALE_NOUSEROVERRIDE 0x80000000u
#define LOCALE_RETURN_NUMBER 0x20000000u
#define LOCALE_USE_NLS 0x10000000u
typedef struct { INT cDig; ULONG dwInFlags, dwOutFlags; INT cchUsed, nBaseShift, nPwr10; } NUMPARSE;
typedef struct { UINT NumDigits, LeadingZero, Grouping; WCHAR *lpDecimalSep, *lpThousandSep; UINT NegativeOrder; } NUMBERFMTW;
_Static_assert(sizeof(DECIMAL)==16 && offsetof(DECIMAL,Hi32)==4 && offsetof(DECIMAL,Lo64)==8,"Windows DECIMAL ABI");
_Static_assert(sizeof(VARIANT)==24 && offsetof(VARIANT,llVal)==8,"Windows AMD64 VARIANT ABI");
#define NUMPRS_LEADING_WHITE 0x0001
#define NUMPRS_TRAILING_WHITE 0x0002
#define NUMPRS_LEADING_PLUS 0x0004
#define NUMPRS_TRAILING_PLUS 0x0008
#define NUMPRS_LEADING_MINUS 0x0010
#define NUMPRS_TRAILING_MINUS 0x0020
#define NUMPRS_HEX_OCT 0x0040
#define NUMPRS_PARENS 0x0080
#define NUMPRS_DECIMAL 0x0100
#define NUMPRS_THOUSANDS 0x0200
#define NUMPRS_CURRENCY 0x0400
#define NUMPRS_EXPONENT 0x0800
#define NUMPRS_USE_ALL 0x1000
#define NUMPRS_STD 0x1FFF
#define NUMPRS_NEG 0x10000
#define NUMPRS_INEXACT 0x20000
#define VTBIT_I1 (1 << VT_I1)
#define VTBIT_UI1 (1 << VT_UI1)
#define VTBIT_I2 (1 << VT_I2)
#define VTBIT_UI2 (1 << VT_UI2)
#define VTBIT_I4 (1 << VT_I4)
#define VTBIT_UI4 (1 << VT_UI4)
#define VTBIT_I8 (1 << VT_I8)
#define VTBIT_UI8 (1 << VT_UI8)
#define VTBIT_R4 (1 << VT_R4)
#define VTBIT_R8 (1 << VT_R8)
#define VTBIT_CY (1 << VT_CY)
#define VTBIT_DECIMAL (1 << VT_DECIMAL)
#define LOCALE_SNEGATIVESIGN 0x00000051
#define LOCALE_SPOSITIVESIGN 0x00000050
#define LOCALE_SDECIMAL 0x0000000e
#define LOCALE_STHOUSAND 0x0000000f
#define LOCALE_SMONDECIMALSEP 0x00000016
#define LOCALE_SMONTHOUSANDSEP 0x00000017
#define LOCALE_SCURRENCY 0x00000014
#define LOCALE_ILZERO 0x00000012
DWORD GetLastError(void);
int GetLocaleInfoW(LCID,LCTYPE,WCHAR *,int);
int GetNumberFormatW(LCID,DWORD,const WCHAR *,const NUMBERFMTW *,WCHAR *,int);
int lstrlenW(const WCHAR *);
BSTR SysAllocString(const OLECHAR *);
void SysFreeString(BSTR);
size_t host_wcslen(const WCHAR *);
WCHAR *host_wcschr(const WCHAR *, WCHAR);
WCHAR *host_wcscat(WCHAR *,const WCHAR *);
WCHAR *host_wcscpy(WCHAR *,const WCHAR *);
int host_wcsncmp(const WCHAR *,const WCHAR *,size_t);
int host_iswspace(unsigned int);
#define wcslen host_wcslen
#define wcschr host_wcschr
#define wcscat host_wcscat
#define wcscpy host_wcscpy
#define wcsncmp host_wcsncmp
#define iswspace host_iswspace
#endif
