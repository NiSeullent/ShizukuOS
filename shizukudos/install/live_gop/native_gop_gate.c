/* SPDX-License-Identifier: GPL-2.0-only
 * Read-only real Win16 -> currently loaded native GOP VxD admission.
 */
#include <windows.h>
#include <thunks.h> /* Original Win98 ABI: MapLS(DWORD), UnMapLS(LPVOID). */
#include <string.h>
#include <i86.h>
#include "native_gop_gate.h"
#include "gop_live_contract.h"
extern WORD _F000H;
typedef DWORD (WINAPI *MapLinear)(DWORD);
typedef VOID (WINAPI *UnmapLinear)(LPVOID);
static DWORD vxd_entry,query_linear;
static WORD query_result;

static void find_vxd(void) {
    vxd_entry=0;
    _asm {
        push es
        push ax
        push bx
        push di
        xor di,di
        mov es,di
        mov ax,1684h
        mov bx,SHZGOP_PM16_DEVICE
        int 2fh
        mov word ptr [vxd_entry],di
        mov word ptr [vxd_entry+2],es
        pop di
        pop bx
        pop ax
        pop es
    }
}
static void query_vxd(void) {
    query_linear=0;query_result=0xffff;
    _asm {
        .386
        push eax
        push ebx
        push ecx
        push edx
        push esi
        push edi
        mov edx,OP_SHZGOP_CURRENT_BOOT
        xor ecx,ecx
        call dword ptr [vxd_entry]
        mov word ptr [query_result],ax
        mov dword ptr [query_linear],ecx
        pop edi
        pop esi
        pop edx
        pop ecx
        pop ebx
        pop eax
    }
}
static int live_fsegment(const unsigned char *probe) {
    const unsigned char FAR *rom;unsigned char slot[48];DWORD at;unsigned i,found=0;
    WORD selector=FP_SEG(&_F000H);shzgop_locator locator;
    if(FP_OFF(&_F000H)!=0 || GetSelectorBase(selector)!=SHZGOP_LOCATOR_BASE ||
       GetSelectorLimit(selector)<0xffffUL) return 0;
    for(at=0;at<SHZGOP_LOCATOR_REGION_BYTES;at+=SHZGOP_LOCATOR_ALIGN) {
        rom=(const unsigned char FAR *)MK_FP(selector,(WORD)at);
        for(i=0;i<8;i++) if(rom[i]!=(unsigned char)"SHZLOC1"[i]) break;
        if(i!=8) continue;
        if(found || at>SHZGOP_LOCATOR_REGION_BYTES-SHZGOP_LOCATOR_BYTES) return 0;
        _fmemcpy(slot,rom,sizeof slot);
        if(!shzgop_slot_admit(slot,SHZGOP_LOCATOR_BASE+at,&locator) ||
           locator.address!=shzgop_u32(probe+48) || memcmp(slot,probe+64,48)) return 0;
        found=1;
    }
    return found==1;
}
int shz_gop_current_boot_ready(const unsigned char *expected_provider,unsigned char *snapshot,unsigned bytes) {
    HMODULE kernel;MapLinear map;UnmapLinear unmap;
    DWORD alias;unsigned char first[SHZGOP_PROBE_BYTES],second[SHZGOP_PROBE_BYTES];
    shzgop_mode mode;
    if(!expected_provider || !snapshot || bytes!=SHZGOP_PROBE_BYTES) return 0;
    find_vxd();if(!vxd_entry || !(vxd_entry>>16)) return 0; /* No loading fallback. */
    kernel=GetModuleHandle("KERNEL");if(!kernel) return 0;
    map=(MapLinear)GetProcAddress(kernel,"MapLS");
    if(!map) map=(MapLinear)GetProcAddress(kernel,"MAPLS");
    unmap=(UnmapLinear)GetProcAddress(kernel,"UnMapLS");
    if(!unmap) unmap=(UnmapLinear)GetProcAddress(kernel,"UNMAPLS");
    if(!map || !unmap) return 0;
    query_vxd();if(query_result!=1 || !query_linear) return 0;
    alias=map(query_linear);if(!alias || !(alias>>16)) return 0;
    if((WORD)alias>0x10000UL-sizeof first ||
       GetSelectorLimit((WORD)(alias>>16))<(DWORD)(WORD)alias+sizeof first-1) {unmap((LPVOID)alias);return 0;}
    _fmemcpy(first,(const void FAR *)alias,sizeof first);unmap((LPVOID)alias);
    if(!shzgop_probe_admit(first,sizeof first,expected_provider,&mode) || !live_fsegment(first)) return 0;
    query_vxd();if(query_result!=1 || !query_linear) return 0;
    alias=map(query_linear);if(!alias || !(alias>>16)) return 0;
    if((WORD)alias>0x10000UL-sizeof second ||
       GetSelectorLimit((WORD)(alias>>16))<(DWORD)(WORD)alias+sizeof second-1) {unmap((LPVOID)alias);return 0;}
    _fmemcpy(second,(const void FAR *)alias,sizeof second);unmap((LPVOID)alias);
    /* No cached snapshot or historical receipt can admit this operation. The
       VxD re-reads descriptor and PCI ownership on each query in this boot. */
    if(memcmp(first,second,sizeof first) ||
       !shzgop_probe_admit(second,sizeof second,expected_provider,&mode) || !live_fsegment(second)) return 0;
    memcpy(snapshot,second,sizeof second);return 1;
}
