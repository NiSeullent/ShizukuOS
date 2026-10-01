/* SPDX-License-Identifier: GPL-2.0-only
 * Included after mechanically extracted, actually compiled driver functions.
 * Hooks substitute interrupt delivery and instrument the actual pixel loop.
 */
static unsigned cases,checks,blits,pixels,irq_entries,irq_leaves;
static DWORD host_flags=0x202;
static int hook_mode,hook_fired,leave_timer;
static blit_t seen;
#define CHECK(x) do { checks++; if(!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); exit(1); } } while(0)
#define CASE() do { cases++; } while(0)
static DWORD host_source[64],host_target[64];
static DWORD publication_irq_enter(void) {
    DWORD saved=host_flags; irq_entries++; host_flags&=~0x200u; return saved;
}
static void publication_irq_leave(DWORD saved) {
    irq_leaves++; host_flags=saved;
    if(leave_timer && (saved&0x200u)) { leave_timer=0; async_timeout(0,0); }
}
static void host_blit_enter(blit_t *b) { blits++; pixels=0; seen=*b; if(hook_mode==4) hook_fired=0; }
static void host_pixel_hook(blit_t *b) {
    unsigned i;
    pixels++;
    if(hook_fired || !hook_mode || pixels!=2) return;
    hook_fired=1;
    if(hook_mode==1) {
        FBHDA_access_rect(7,7,8,8); host_source[63]=0x556677;
        ((DWORD*)((BYTE*)wram+WRAM_FB_TOP))[63]=host_source[63];
        FBHDA_access_end(0);
    } else if(hook_mode==2) {
        draw(&frame);
    } else if(hook_mode==3 || hook_mode==4) {
        FBHDA_access_begin(0);
        if(hook_mode==4) FBHDA_access_rect(2,2,3,3);
        for(i=0;i<CURSOR_DMAX*CURSOR_DMAX;i++) wram->cursor.xormask[i]=0x222222+blits;
        if(hook_mode==4) FBHDA_access_end(0);
        FBHDA_access_end(0);
    }
#ifndef BASELINE
    CHECK(b!=&frame); CHECK(b->src_sx==seen.src_sx && b->src_ex==seen.src_ex);
    CHECK(b->src_sy==seen.src_sy && b->src_ey==seen.src_ey);
#else
    (void)b;
#endif
}
static void reset(void) {
    unsigned i;
    memset(wram,0,WRAM_FB_TOP+sizeof(host_source));
    memset(&frame,0,sizeof(frame)); memset(host_target,0,sizeof(host_target));
    hda->width=8;hda->height=8;hda->stride=sizeof(host_source);
    hda->vram_pm32=(BYTE*)wram+WRAM_FB_TOP;
    native_mode.width=8;native_mode.height=8;native_mode.pitch=32;
    wram->regs.s.width=8;wram->regs.s.height=8;wram->regs.s.pitch=32;
    wram->regs.s.mode=MODE_32;wram->regs.s.fbstart=WRAM_FB_TOP;
    frame.dst[0].flat.ptr=host_target;frame.dst_pitch=32;frame.dst_mode=MODE_32;
    frame.dst_w=8;frame.dst_h=8;frame.dst_scans=1;
    for(i=0;i<64;i++) host_source[i]=0x102030+i;
    memcpy(hda->vram_pm32,host_source,sizeof(host_source));
    ready=TRUE;hires=TRUE;fb_lock_cnt=0;
    blits=pixels=0;hook_mode=hook_fired=leave_timer=0;host_flags=0x202;
    host_timeout_result=1;host_timeout_calls=0;host_time=16;
    timer_running=async_blit_init(&frame,draw);CHECK(timer_running && host_timeout_calls==1);
#ifndef BASELINE
    publication_depth=0;publication_inflight=publication_fault=FALSE;
    memset(&publication_cursor,0,sizeof(publication_cursor));
#endif
}
static void fail_timer(void) {
    host_timeout_result=0;timer_running=async_blit_init(&frame,draw);
    CHECK(!timer_running && draw_callback==draw && blit==&frame);
}
static void set_cursor(void) {
    unsigned i;
    wram->regs.s.cursor_visible=1;wram->regs.s.cursor_w=8;wram->regs.s.cursor_h=8;
    for(i=0;i<CURSOR_DMAX*CURSOR_DMAX;i++) {
        wram->cursor.andmask[i]=0;wram->cursor.xormask[i]=0x111111;
    }
}
int main(void) {
#ifndef BASELINE
    unsigned i;
#endif
    wram=calloc(1,WRAM_FB_TOP+sizeof(host_source));CHECK(wram!=NULL);
#ifdef BASELINE
    CASE(); reset(); FBHDA_access_rect(0,0,1,1); async_timeout(0,0);
    CHECK(blits==1 && host_target[0]==host_source[0]);
    ((DWORD*)hda->vram_pm32)[0]=0xabcdef;FBHDA_access_end(0);draw(&frame);
    CHECK(blits==1 && host_target[0]!=0xabcdef && frame.num_changes==0);
    CASE(); reset(); FBHDA_access_begin(0);FBHDA_access_begin(0);FBHDA_access_end(0);
    draw(&frame);CHECK(blits==1); /* Drawing is still inside the outer begin. */
    CASE(); reset();FBHDA_access_rect(0,0,2,2);FBHDA_access_end(0);hook_mode=1;draw(&frame);
    CHECK(hook_fired && frame.num_changes==0); /* Reentrant damage was erased. */
    CASE(); reset();set_cursor();FBHDA_access_begin(0);FBHDA_access_end(0);
    hook_mode=3;draw(&frame);CHECK(host_target[0]==0x111111 && host_target[1]==0x222223);
#else
    CASE();reset();FBHDA_access_rect(0,0,1,1);async_timeout(0,0);CHECK(blits==0);
    ((DWORD*)hda->vram_pm32)[0]=0xabcdef;FBHDA_access_end(0);async_timeout(0,0);
    CHECK(blits==1 && host_target[0]==0xabcdef && frame.num_changes==0);
    CASE();reset();FBHDA_access_rect(0,0,2,2);FBHDA_access_rect(6,6,8,8);
    CHECK(publication_depth==2 && frame.src_sx==0 && frame.src_ex==8);
    FBHDA_access_end(0);draw(&frame);CHECK(blits==0 && publication_depth==1);
    FBHDA_access_end(0);draw(&frame);CHECK(blits==1 && publication_depth==0);
    CASE();reset();FBHDA_access_rect(1,2,3,4);FBHDA_access_rect(99,99,100,100);
    CHECK(publication_depth==2 && frame.src_sx==1 && frame.src_ex==3);
    FBHDA_access_end(0);draw(&frame);CHECK(blits==0);
    FBHDA_access_end(0);draw(&frame);CHECK(blits==1 && !publication_fault);
    CASE();reset();FBHDA_access_rect(0,0,0,0);CHECK(publication_depth==1 && !frame.num_changes);
    FBHDA_access_end(0);draw(&frame);CHECK(!publication_fault && blits==0);
    CASE();reset();FBHDA_access_rect(5,5,2,2);FBHDA_access_end(0);CHECK(!frame.num_changes);
    CASE();reset();FBHDA_access_rect(7,7,0xffffffffu,0xffffffffu);
    CHECK(frame.src_ex==8 && frame.src_ey==8);FBHDA_access_end(0);draw(&frame);
    CHECK(host_target[63]==host_source[63] && !host_target[0]);
    CASE();reset();ready=FALSE;FBHDA_access_begin(0);FBHDA_access_end(0);draw(&frame);
    CHECK(!publication_depth && !publication_fault && !blits);
    CASE();reset();VESA_HIRES_disable();FBHDA_access_rect(0,0,1,1);FBHDA_access_end(0);draw(&frame);
    CHECK(!blits && frame.num_changes);VESA_HIRES_enable();draw(&frame);
    CHECK(blits==1 && host_target[63]==host_source[63]);
    CASE();reset();fail_timer();FBHDA_access_rect(2,2,3,3);CHECK(!blits);
    FBHDA_access_end(0);CHECK(blits==1 && host_target[18]==host_source[18]);
    CASE();reset();fail_timer();FBHDA_access_rect(0,0,2,2);FBHDA_access_rect(7,7,8,8);
    FBHDA_access_end(0);CHECK(!blits && publication_depth==1);
    FBHDA_access_end(0);CHECK(blits==1 && !publication_depth && host_target[63]==host_source[63]);
    CASE();reset();fail_timer();publication_depth=UINT32_MAX;FBHDA_access_rect(0,0,2,2);
    FBHDA_access_end(0);CHECK(publication_fault && frame.num_changes && !blits);
    CASE();reset();leave_timer=1;FBHDA_access_rect(0,0,1,1);CHECK(!blits);
    FBHDA_access_end(0);draw(&frame);CHECK(blits==1);
    CASE();reset();FBHDA_access_rect(0,0,2,2);FBHDA_access_end(0);hook_mode=1;draw(&frame);
    CHECK(blits==1 && hook_fired && frame.num_changes && frame.src_sx==7 && frame.src_ex==8);
    CHECK(!host_target[63]);hook_mode=0;draw(&frame);
    CHECK(blits==2 && host_target[63]==0x556677 && !frame.num_changes);
    CASE();reset();FBHDA_access_begin(0);FBHDA_access_end(0);hook_mode=2;draw(&frame);
    CHECK(blits==1 && !publication_inflight && !publication_depth);
    CASE();reset();set_cursor();FBHDA_access_begin(0);FBHDA_access_end(0);hook_mode=3;draw(&frame);
    for(i=0;i<64;i++) CHECK(host_target[i]==0x111111);
    CHECK(frame.num_changes);hook_mode=0;draw(&frame);
    for(i=0;i<64;i++) CHECK(host_target[i]==0x222223);
    CASE();reset();set_cursor();fail_timer();hook_mode=3;FBHDA_access_begin(0);
    FBHDA_access_end(0);CHECK(blits==2 && !frame.num_changes && !publication_inflight);
    for(i=0;i<64;i++) CHECK(host_target[i]==0x222223);
    CASE();reset();set_cursor();fail_timer();hook_mode=4;FBHDA_access_begin(0);
    FBHDA_access_end(0);CHECK(blits==2 && frame.num_changes && !publication_inflight);
    CHECK(publication_depth==0);hook_mode=0;FBHDA_access_rect(7,7,8,8);FBHDA_access_end(0);
    CHECK(blits==3 && !frame.num_changes);for(i=0;i<64;i++) CHECK(host_target[i]==0x222224);
    CASE();reset();set_cursor();wram->regs.s.cursor_x=INT32_MAX;wram->regs.s.cursor_y=INT32_MIN;
    FBHDA_access_begin(0);FBHDA_access_end(0);draw(&frame);CHECK(host_target[0]==host_source[0]);
    CASE();reset();set_cursor();wram->regs.s.cursor_w=33;FBHDA_access_begin(0);
    FBHDA_access_end(0);draw(&frame);CHECK(host_target[0]==host_source[0]);
    CASE();reset();set_cursor();wram->regs.s.cursor_h=-1;FBHDA_access_begin(0);
    FBHDA_access_end(0);draw(&frame);CHECK(host_target[0]==host_source[0]);
    CASE();reset();publication_depth=UINT32_MAX;FBHDA_access_begin(0);
    CHECK(publication_fault && publication_depth==UINT32_MAX);FBHDA_access_end(0);draw(&frame);
    CHECK(!blits && frame.num_changes);
    CASE();reset();FBHDA_access_end(0);CHECK(publication_fault && !publication_depth);
    FBHDA_access_begin(0);FBHDA_access_end(0);draw(&frame);CHECK(!blits && frame.num_changes);
    CASE();reset();frame.num_changes=UINT32_MAX;frame.src_sx=1;frame.src_sy=1;
    frame.src_ex=2;frame.src_ey=2;FBHDA_access_rect(6,6,7,7);
    CHECK(frame.num_changes==1 && frame.src_sx==1 && frame.src_ex==7);
    FBHDA_access_end(0);draw(&frame);CHECK(blits==1);
    CASE();reset();for(i=0;i<1000;i++) FBHDA_access_rect(i%8,i%8,i%8+1,i%8+1);
    CHECK(publication_depth==1000);for(i=0;i<1000;i++) {
        FBHDA_access_end(0);draw(&frame);CHECK(blits==(i==999));
    } CHECK(!publication_depth && !publication_fault);
    CASE();reset();VESA_clear();CHECK(publication_depth==0 && frame.num_changes);
    draw(&frame);for(i=0;i<64;i++) CHECK(host_target[i]==0);
    CASE();reset();CHECK(VESA_setmode(8,8,32,0,0));CHECK(blits==1);
    CASE();reset();CHECK(!VESA_setmode(9,8,32,0,0));CHECK(!blits && !frame.num_changes);
    CASE();reset();for(i=0;i<2;i++) {
        DWORD saved=i?0x2:0x202;host_flags=saved;FBHDA_access_begin(0);CHECK(host_flags==saved);
        FBHDA_access_end(0);CHECK(host_flags==saved);draw(&frame);CHECK(host_flags==saved);
        VESA_HIRES_disable();CHECK(host_flags==saved);VESA_HIRES_enable();CHECK(host_flags==saved);
    } CHECK(irq_entries==irq_leaves);
#endif
    free(wram);printf("{\"cases\":%u,\"checks\":%u,\"baseline_negative_controls\":%s}\n",cases,checks,
#ifdef BASELINE
        "true"
#else
        "false"
#endif
    );return 0;
}
