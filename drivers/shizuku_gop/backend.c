/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku basic graphics: fixed firmware GOP -> Win98 DIB Engine.
 * The VESA-named entry points retain VMDisp9x's MIT frontend ABI; this
 * implementation makes no BIOS/UEFI mode-setting calls or VGA register writes.
 */
#define VESA
#include "winhack.h"
#include "vmm.h"
#include "vxd.h"
#include "vxd_lib.h"
#include "3d_accel.h"
#include "wram.h"
#include "async.h"
#include "gop_contract.h"
#include "gop_live_contract.h"
#include "gop_provider_identity.h"
typedef char shzgop_hda_layout[(sizeof(FBHDA_t)==SHZGOP_HDA_BYTES && offsetof(FBHDA_t,vxdname)==64)?1:-1];
extern FBHDA_t *hda;
extern LONG fb_lock_cnt;
static shzgop_mode native_mode;
static unsigned char *native_rom=NULL,*native_descriptor=NULL;
static DWORD native_descriptor_address=0;
static blit_t frame;
static BOOL ready=FALSE, hires=FALSE;
static BOOL timer_running=FALSE;
WORD vesa_version=0x0200;
DWORD vram_phy=0;
static DWORD cfg_in(WORD port);
#pragma aux cfg_in = "in eax,dx" parm [dx] value [eax];
static void cfg_out(WORD port,DWORD value);
#pragma aux cfg_out = "out dx,eax" parm [dx] [eax];
static void draw(blit_t *b) {
    if(ready && hires && b->num_changes) { wram_blit(b); b->num_changes=0; }
}
BOOL VESA_init_hw(void) {
    unsigned char *rom, *descriptor;
    shzgop_locator locator;
    DWORD address, bytes;
    void *physical;
    rom=(unsigned char *)_MapPhysToLinear(SHZGOP_LOCATOR_BASE,SHZGOP_LOCATOR_REGION_BYTES,0);
    if(!rom || (DWORD)rom==0xffffffffUL ||
       !shzgop_locator_scan(rom,SHZGOP_LOCATOR_REGION_BYTES,&locator)) {
        dbg_printf("SHZGOP FAIL persistent-locator\n"); return FALSE;
    }
    address=locator.descriptor_address;
    descriptor=(unsigned char *)_MapPhysToLinear(address,4096,0);
    if(!descriptor || (DWORD)descriptor==0xffffffffUL ||
       !shzgop_locator_bind(&locator,descriptor,96,&native_mode)) {
        dbg_printf("SHZGOP FAIL descriptor\n"); return FALSE;
    }
    dbg_printf("SHZGOP LOCATOR anchor=%lX descriptor=%lX checksum=%lX\n",
       locator.address,address,locator.descriptor_checksum);
    /* Match the recorded PCI owner without touching its BARs or command. */
    {
        DWORD identity, port, saved, bar, i;
        BOOL matching_bar=FALSE;
        port=0x80000000UL|((DWORD)native_mode.bus<<16)|((DWORD)native_mode.devfn<<8);
        saved=cfg_in(0xcf8); cfg_out(0xcf8,port); identity=cfg_in(0xcfc);
        if(identity==((DWORD)native_mode.vendor|((DWORD)native_mode.device<<16))) {
            for(i=0;i<6;i++) {
                cfg_out(0xcf8,port+0x10+i*4); bar=cfg_in(0xcfc);
                if(!(bar&1u) && bar && (bar&~15UL)==native_mode.base) {
                    if((bar&6u)==0) matching_bar=TRUE;
                    else if((bar&6u)==4 && i<5) {
                        cfg_out(0xcf8,port+0x14+i*4);
                        if(!cfg_in(0xcfc)) matching_bar=TRUE;
                    }
                }
                if(!(bar&1u) && (bar&6u)==4) i++;
            }
        }
        cfg_out(0xcf8,saved);
        if(!matching_bar) { dbg_printf("SHZGOP FAIL PCI-owner/BAR\n"); return FALSE; }
    }
    physical=(void *)_MapPhysToLinear(native_mode.base,native_mode.visible,0);
    if(!physical || (DWORD)physical==0xffffffffUL) return FALSE;
    bytes=(native_mode.visible+WRAM_FB_TOP+4095UL)&~4095UL;
    if(!wram_init(bytes) || !FBHDA_init_hw()) return FALSE;
    memcpy(hda->vxdname,"SHZGOP.VXD",11);
    hda->width=native_mode.width; hda->height=native_mode.height;
    hda->bpp=32; hda->pitch=native_mode.pitch; hda->stride=native_mode.visible;
    hda->vram_size=native_mode.visible; hda->vram_size_bar=native_mode.aperture;
    hda->vram_phylin=physical; hda->vram_pm32=(BYTE*)wram+WRAM_FB_TOP;
    hda->vram_size_virt=native_mode.visible;
    hda->flags=FB_VESA_MODES|FB_FORCE_SOFTWARE;
    vram_phy=native_mode.base;
    memset(&frame,0,sizeof(frame));
    frame.base.ptr=physical; frame.dst[0].flat.ptr=physical;
    frame.dst_w=native_mode.width; frame.dst_h=native_mode.height;
    frame.dst_pitch=native_mode.pitch; frame.dst_mode=MODE_32; frame.dst_scans=1;
    wram->regs.s.width=native_mode.width; wram->regs.s.height=native_mode.height;
    wram->regs.s.pitch=native_mode.pitch; wram->regs.s.mode=MODE_32;
    native_rom=rom;native_descriptor=descriptor;native_descriptor_address=address;
    ready=TRUE;
    timer_running=async_blit_init(&frame,draw);
    dbg_printf("SHZGOP READY base=%lX aperture=%ld width=%ld height=%ld pitch=%ld\n",
       native_mode.base,native_mode.aperture,native_mode.width,native_mode.height,native_mode.pitch);
    return TRUE;
}
/* This query only reads current native state. It never sets a mode, loads a
 * driver, allocates WRAM, changes PCI ownership, or writes the framebuffer. */
static unsigned char current_probe[SHZGOP_PROBE_BYTES];
static void probe_u32(unsigned char *p,DWORD v) {
    p[0]=(BYTE)v;p[1]=(BYTE)(v>>8);p[2]=(BYTE)(v>>16);p[3]=(BYTE)(v>>24);
}
static DWORD current_boot_probe_inner(void) {
    unsigned char *rom,*descriptor;shzgop_locator locator,again;
    shzgop_mode observed;DWORD i,saved,port,identity,bar;BOOL matching=FALSE;
    memset(current_probe,0,sizeof(current_probe));
    if(!ready || !hda) return 0;
    /* Re-read the actual physical mappings retained by successful native init.
       No new mapping allocation occurs on each observation. */
    rom=native_rom;descriptor=native_descriptor;
    if(!rom || !descriptor || (DWORD)rom==0xffffffffUL || (DWORD)descriptor==0xffffffffUL ||
       !shzgop_locator_scan(rom,SHZGOP_LOCATOR_REGION_BYTES,&locator) ||
       locator.descriptor_address!=native_descriptor_address) return 0;
    memcpy(current_probe+64,rom+locator.address-SHZGOP_LOCATOR_BASE,48);
    memcpy(current_probe+112,descriptor,96);memcpy(current_probe+208,hda,80);
    memcpy(current_probe,"SHZGPB1",8);current_probe[8]=1;
    probe_u32(current_probe+12,SHZGOP_PROBE_BYTES);
    memcpy(current_probe+16,shzgop_provider_identity,32);
    probe_u32(current_probe+48,locator.address);
    probe_u32(current_probe+52,locator.descriptor_address);
    probe_u32(current_probe+56,locator.descriptor_checksum);
    if(!shzgop_probe_admit(current_probe,sizeof(current_probe),shzgop_provider_identity,&observed) ||
       observed.base!=native_mode.base || observed.aperture!=native_mode.aperture ||
       observed.visible!=native_mode.visible || observed.width!=native_mode.width ||
       observed.height!=native_mode.height || observed.pitch!=native_mode.pitch ||
       observed.bus!=native_mode.bus || observed.devfn!=native_mode.devfn ||
       observed.vendor!=native_mode.vendor || observed.device!=native_mode.device) return 0;
    port=0x80000000UL|((DWORD)observed.bus<<16)|((DWORD)observed.devfn<<8);
    saved=cfg_in(0xcf8);cfg_out(0xcf8,port);identity=cfg_in(0xcfc);
    if(identity==((DWORD)observed.vendor|((DWORD)observed.device<<16))) {
        for(i=0;i<6;i++) {
            cfg_out(0xcf8,port+0x10+i*4);bar=cfg_in(0xcfc);
            if(!(bar&1u) && bar && (bar&~15UL)==observed.base) {
                if((bar&6u)==0) matching=TRUE;
                else if((bar&6u)==4 && i<5) {cfg_out(0xcf8,port+0x14+i*4);
                    if(!cfg_in(0xcfc)) matching=TRUE;}
            }
            if(!(bar&1u) && (bar&6u)==4) i++;
        }
    }
    cfg_out(0xcf8,saved);
    if(!matching || !ready || !shzgop_locator_scan(rom,SHZGOP_LOCATOR_REGION_BYTES,&again) ||
       again.address!=locator.address || again.descriptor_address!=locator.descriptor_address ||
       again.descriptor_checksum!=locator.descriptor_checksum ||
       memcmp(current_probe+64,rom+locator.address-SHZGOP_LOCATOR_BASE,48) ||
       memcmp(current_probe+112,descriptor,96) || memcmp(current_probe+208,hda,80)) return 0;
    return (DWORD)current_probe;
}
DWORD SHZGOP_current_boot_probe(void) {
    DWORD result;
    /* Keep CF8 selection and the captured native state together. Restore the
       prior selector before leaving the same VMM critical section. */
    critical_section_enter();result=current_boot_probe_inner();critical_section_leave();
    return result;
}
BOOL VESA_valid(void) { return ready; }
BOOL VESA_validmode(DWORD w,DWORD h,DWORD bpp) {
    return ready && w==native_mode.width && h==native_mode.height && bpp==32;
}
BOOL VESA_setmode(DWORD w,DWORD h,DWORD bpp,DWORD rr_min,DWORD rr_max) {
    (void)rr_min; (void)rr_max;
    if(!VESA_validmode(w,h,bpp)) return FALSE;
    hires=TRUE; wram_changes(&frame,0,0,w,h); draw(&frame);
    dbg_printf("SHZGOP MODE %ldx%ldx32 pitch=%ld\n",w,h,native_mode.pitch);
    return TRUE;
}
void VESA_clear(void) { if(ready) memset(hda->vram_pm32,0,hda->stride); }
void VESA_HIRES_enable(void) { hires=TRUE; }
void VESA_HIRES_disable(void) { hires=FALSE; }
BOOL VESA_check_switch(DWORD mode) { (void)mode; return FALSE; }
BOOL VESA_check_int10h(DWORD vm,PCRS_32 regs) {
    (void)vm;
    /* DOS windows cannot replace the firmware mode while the desktop owns it. */
    if(hires && ((regs->Client_EAX&0xff00)==0 || (regs->Client_EAX&0xffff)==0x4f02)) {
        if((regs->Client_EAX&0xffff)==0x4f02) regs->Client_EAX=0x014f;
        return FALSE;
    }
    return TRUE;
}
BOOL FBHDA_mode_query(DWORD index,FBHDA_mode_t *m) {
    if(!ready || index) return FALSE;
    if(m) { memset(m,0,sizeof(*m)); m->cb=sizeof(*m); m->width=native_mode.width;
        m->height=native_mode.height; m->bpp=32; }
    return TRUE;
}
void FBHDA_access_begin(DWORD flags) {
    (void)flags; if(!ready) return;
    FBHDA_lock(); wram_changes(&frame,0,0,hda->width,hda->height); FBHDA_unlock();
}
void FBHDA_access_rect(DWORD l,DWORD t,DWORD r,DWORD b) {
    if(!ready) return;
    if(l>hda->width) l=hda->width; if(r>hda->width) r=hda->width;
    if(t>hda->height) t=hda->height; if(b>hda->height) b=hda->height;
    if(l>=r || t>=b) return;
    FBHDA_lock(); wram_changes(&frame,l,t,r,b); FBHDA_unlock();
}
void FBHDA_access_end(DWORD flags) {
    (void)flags; if(!ready) return;
    FBHDA_lock(); if(fb_lock_cnt>0) fb_lock_cnt--;
    if(!timer_running && !fb_lock_cnt) draw(&frame); FBHDA_unlock();
}
BOOL FBHDA_swap(DWORD offset,DWORD flags) {
    if(!ready || offset) return FALSE;
    if(flags&FBHDA_SWAP_QUERY) return FALSE;
    FBHDA_access_begin(0); FBHDA_access_end(0); return TRUE;
}
void FBHDA_palette_set(unsigned char index,DWORD rgb) { (void)index; (void)rgb; }
DWORD FBHDA_palette_get(unsigned char index) { (void)index; return 0; }
DWORD FBHDA_overlay_setup(DWORD o,DWORD w,DWORD h,DWORD bpp) {
    (void)o; (void)w; (void)h; (void)bpp; return 0;
}
void FBHDA_overlay_lock(DWORD l,DWORD t,DWORD r,DWORD b) { (void)l;(void)t;(void)r;(void)b; }
void FBHDA_overlay_unlock(DWORD flags) { (void)flags; }
