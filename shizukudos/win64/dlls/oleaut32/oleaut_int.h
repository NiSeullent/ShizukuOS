/* SPDX-License-Identifier: GPL-2.0-only
 * Internal header of the Shizuku oleaut32.dll implementation (BSTR, VARIANT, SAFEARRAY core).
 *
 * Scope: automation string, variant and array *data* management with real bodies. Anything that needs a type library
 * or the registry (LoadRegTypeLib, ITypeInfo helpers), locale tables (VarBstrCmp, VarFormat*, date/currency parsing),
 * or IRecordInfo-carrying arrays (SafeArrayCreateEx, SafeArray{Get,Set}RecordInfo) is not provided.
 */
#ifndef SHZ_OLEAUT_INT_H
#define SHZ_OLEAUT_INT_H
#include "nt.h"
#include <string.h>
#define _OLEAUT32_
#define COBJMACROS
#include <oleauto.h>

#define FADF_DATADELETED_ 0x1000

BSTR shz_bstr_alloc_bytes(const void *src, UINT bytes);        /* internal helper shared by the .c files */
int shz_vt_valid(VARTYPE vt);                                  /* is this a legal VARIANT type (VariantClear rules)? */
#endif
