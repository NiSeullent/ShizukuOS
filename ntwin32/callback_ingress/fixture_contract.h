/* SPDX-License-Identifier: GPL-2.0-only -- own zero-import fixture protocol */
#ifndef CI_FIXTURE_CONTRACT_H
#define CI_FIXTURE_CONTRACT_H
#include "../native_loader/pe.h"
/* Successful immutable np_parse input. GNU ld may emit the legal20-byte null
 * import descriptor even with zero imported DLLs/functions. Admit exactly
 * that representation or an absent directory; no dependency is initialized.
 * A named empty DLL descriptor is still a dependency and is not admitted.
 */
static int ci_fixture_zero_imports(const np_image *p)
{
    const uint8_t *d; uint32_t i;
    if(!p->directory[1][0]) return p->directory[1][1]==0;
    if(p->directory[1][1]!=20 || !(d=np_raw(p,p->directory[1][0],20))) return 0;
    for(i=0;i<20;i+=4) if(np_u32(d+i)) return 0;
    return 1;
}
#endif
