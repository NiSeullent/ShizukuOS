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
extern FBHDA_t *hda;
extern LONG fb_lock_cnt;
static shzgop_mode native_mode;
static blit_t frame;
static BOOL ready=FALSE, hires=FALSE;
static BOOL timer_running=FALSE;
/* Ring-0, single-CPU publication metadata. Never held across a VMM wait. */
static volatile DWORD publication_depth=0;
static volatile BOOL publication_inflight=FALSE, publication_fault=FALSE;
static wram_publication_cursor_t publication_cursor;
typedef char publication_cursor_size[(sizeof(wram_publication_cursor_t)==8212)?1:-1];
static DWORD publication_irq_enter(void);
#pragma aux publication_irq_enter = "pushfd" "pop eax" "cli" value [eax] modify [];
static void publication_irq_leave(DWORD saved);
#pragma aux publication_irq_leave = "push eax" "popfd" parm [eax] modify [];

static void publication_damage(DWORD l,DWORD t,DWORD r,DWORD b) {
    /* This field is a pending boolean; do not let upstream's ++ wrap it. */
    if(frame.num_changes) frame.num_changes=1;
    wram_changes(&frame,l,t,r,b);
    frame.num_changes=1;
}
static void publication_begin(void) {
    if(publication_depth==0xffffffffUL) publication_fault=TRUE;
    else publication_depth++;
}
static void publication_snapshot_cursor(void) {
    publication_cursor.visible=wram->regs.s.cursor_visible;
    publication_cursor.x=wram->regs.s.cursor_x;
    publication_cursor.y=wram->regs.s.cursor_y;
    publication_cursor.w=wram->regs.s.cursor_w;
    publication_cursor.h=wram->regs.s.cursor_h;
    memcpy(publication_cursor.andmask,wram->cursor.andmask,sizeof(publication_cursor.andmask));
    memcpy(publication_cursor.xormask,wram->cursor.xormask,sizeof(publication_cursor.xormask));
}
WORD vesa_version=0x0200;
DWORD vram_phy=0;
static DWORD cfg_in(WORD port);
#pragma aux cfg_in = "in eax,dx" parm [dx] value [eax];
static void cfg_out(WORD port,DWORD value);
#pragma aux cfg_out = "out dx,eax" parm [dx] [eax];
static void draw(blit_t *b) {
    DWORD saved;
    unsigned pass;
    BOOL again;
    blit_t pending;
    /* A failed timer gets one bounded follow-up, never an unbounded drain. */
    for(pass=0;pass<2;pass++) {
        saved=publication_irq_enter();
        if(!ready || !hires || publication_depth || publication_fault ||
           publication_inflight || !b->num_changes) {
            publication_irq_leave(saved); return;
        }
        pending=*b;
        b->num_changes=0;
        publication_inflight=TRUE;
        /* 8,212 bounded bytes; pixel copy happens with caller EFLAGS restored. */
        publication_snapshot_cursor();
        publication_irq_leave(saved);
        wram_publication_blit(&pending,&publication_cursor);
        saved=publication_irq_enter();
        publication_inflight=FALSE;
        /* New damage belongs to the live descriptor and must survive this copy. */
        again=!timer_running && !publication_depth && b->num_changes;
        publication_irq_leave(saved);
        if(!again) return;
    }
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
    publication_depth=0; publication_inflight=FALSE; publication_fault=FALSE;
    ready=TRUE;
    timer_running=async_blit_init(&frame,draw);
    dbg_printf("SHZGOP READY base=%lX aperture=%ld width=%ld height=%ld pitch=%ld\n",
       native_mode.base,native_mode.aperture,native_mode.width,native_mode.height,native_mode.pitch);
    return TRUE;
}
BOOL VESA_valid(void) { return ready; }
BOOL VESA_validmode(DWORD w,DWORD h,DWORD bpp) {
    return ready && w==native_mode.width && h==native_mode.height && bpp==32;
}
BOOL VESA_setmode(DWORD w,DWORD h,DWORD bpp,DWORD rr_min,DWORD rr_max) {
    DWORD saved;
    (void)rr_min; (void)rr_max;
    if(!VESA_validmode(w,h,bpp)) return FALSE;
    saved=publication_irq_enter();
    hires=TRUE; publication_damage(0,0,w,h);
    publication_irq_leave(saved); draw(&frame);
    dbg_printf("SHZGOP MODE %ldx%ldx32 pitch=%ld\n",w,h,native_mode.pitch);
    return TRUE;
}
void VESA_clear(void) {
    if(!ready) return;
    FBHDA_access_begin(0); memset(hda->vram_pm32,0,hda->stride); FBHDA_access_end(0);
}
void VESA_HIRES_enable(void) {
    DWORD saved=publication_irq_enter();
    hires=TRUE;
    if(ready) publication_damage(0,0,hda->width,hda->height);
    publication_irq_leave(saved);
}
void VESA_HIRES_disable(void) {
    DWORD saved=publication_irq_enter(); hires=FALSE; publication_irq_leave(saved);
}
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
    DWORD saved;
    (void)flags; if(!ready) return;
    saved=publication_irq_enter(); publication_begin();
    publication_damage(0,0,hda->width,hda->height); publication_irq_leave(saved);
}
void FBHDA_access_rect(DWORD l,DWORD t,DWORD r,DWORD b) {
    DWORD saved;
    if(!ready) return;
    saved=publication_irq_enter();
    /* Even an empty/clipped BeginAccess has a matching EndAccess. */
    publication_begin();
    if(l>hda->width) l=hda->width; if(r>hda->width) r=hda->width;
    if(t>hda->height) t=hda->height; if(b>hda->height) b=hda->height;
    if(l<r && t<b) publication_damage(l,t,r,b);
    publication_irq_leave(saved);
}
void FBHDA_access_end(DWORD flags) {
    DWORD saved;
    BOOL publish;
    (void)flags; if(!ready) return;
    saved=publication_irq_enter();
    if(publication_depth) publication_depth--;
    else publication_fault=TRUE;
    publish=!timer_running && !publication_depth;
    publication_irq_leave(saved);
    if(publish) draw(&frame);
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
