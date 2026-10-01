/* SPDX-License-Identifier: GPL-2.0-only
 * Ordinal WCHAR casing uses the runtime's existing immutable Unicode 14 table.
 * This is simple per-code-unit casing, without a kernel32 link or locale facade.
 * The table is generated Unicode data, not Windows NLS data. */
#ifdef SHZ_RTL_BOOTSTRAP_HOST
#include "../tests/rtl_bootstrap_host_contract.h"
#else
#include "nt.h"
#endif
#define UNI_DEFINE_TABLES
#include "../kernel32/unidata.h"

WCHAR ShzBootstrapUpcase(WCHAR ch)
{
    unsigned low=0,high=UNI_NCASE;
    while(low<high) {
        unsigned middle=low+(high-low)/2;
        if(uni_case[middle].cp<ch)low=middle+1;else high=middle;
    }
    if(low<UNI_NCASE && uni_case[low].cp==ch) {
        uint32_t result=(uint32_t)((int32_t)ch+uni_case[low].up);
        if(result<=0xffff)return (WCHAR)result;
    }
    return ch;
}
