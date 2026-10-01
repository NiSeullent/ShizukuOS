/* SPDX-License-Identifier: GPL-2.0-only
 * Real production compositor/resize/present bodies extracted by the paired
 * driver, with owned host allocations, injected OOM/row faults and an
 * independent per-pixel boolean oracle. No guest/native98 proof. */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "../gfx_present_layout.h"
#include "../gfx_written_coverage.h"
#define GFX_MAX_WINDOWS 256
#define GFX_MAX_SURF_BYTES (16u<<20)
#define FACE 0x00c0c0c0u
#define WS_EX_TRANSPARENT_ 0x20u
#define WS_EX_LAYERED_ 0x80000u
#define ULW_ALPHA_ 2u
#define ULW_COLORKEY_ 1u
#define LWA_ALPHA_ 2u
#define LWA_COLORKEY_ 1u
#define CS_HREDRAW 2u
#define CS_VREDRAW 1u
#define STATUS_SUCCESS 0
#define STATUS_INVALID_HANDLE ((int32_t)0xc0000008u)
#define STATUS_INVALID_PARAMETER ((int32_t)0xc000000du)
#define STATUS_NO_MEMORY ((int32_t)0xc0000017u)
#define STATUS_ACCESS_VIOLATION ((int32_t)0xc0000005u)
#define USER_MIN 0x10000u
#define USER_TOP UINT64_C(0x800000000000)
typedef struct { uint32_t style,nwin; } gclass_t;
typedef struct gwin gwin_t;
struct gwin {
    int used,destroying,msgonly; uint64_t handle;
    gwin_t *parent,*child,*next,*prev;gclass_t *cls;
    uint32_t style,exstyle,pid;int32_t x,y,w,h,ncl,nct,ncr,ncb,sw,sh;
    uint32_t *surf;uint8_t *written;
    uint16_t *title;uint8_t *extra;shz_rect_t *rgn;uint32_t nrgn;
    uint32_t *layer;int32_t lw,lh;uint32_t lflags,lkey;uint8_t lmode,lalpha,lppa;
};
typedef struct { int pid; } process_t;
static gwin_t windows[GFX_MAX_WINDOWS],*g_win=windows;
#define DESKTOP (&g_win[0])
static struct { int ready;uint32_t width,height;uint32_t *back;uint64_t stat_presents; } g_fb;
static int gfx_lock,locked,allocation_call,fail_allocation,read_call,fail_read;
static unsigned checks;
static uint64_t live_allocations;
typedef struct allocation { struct allocation *next;void *p;uint64_t n; } allocation_t;
static allocation_t *allocations;
static void mutex_lock(int *m) { (void)m;if(locked++) abort(); }
static void mutex_unlock(int *m) { (void)m;if(--locked) abort(); }
static void *gfx_pages_alloc(uint64_t n)
{
    allocation_t *a;
    if(++allocation_call==fail_allocation || !n) return NULL;
    a=malloc(sizeof *a);if(!a) abort();a->p=calloc(1,(size_t)n);if(!a->p) abort();
    a->n=n;a->next=allocations;allocations=a;++live_allocations;return a->p;
}
static void gfx_pages_free(void *p,uint64_t n)
{
    allocation_t **pp;
    for(pp=&allocations;*pp && (*pp)->p!=p;pp=&(*pp)->next) {}
    if(!*pp || (*pp)->n!=n) abort();
    { allocation_t *a=*pp;*pp=a->next;free(a->p);free(a);--live_allocations; }
}
static void kfree(void *p) { free(p); }
static int copy_from_user(process_t *p,void *dst,uint64_t src,uint64_t n)
{
    (void)p;if(++read_call==fail_read) return -1;memcpy(dst,(void *)(uintptr_t)src,(size_t)n);return 0;
}
static int copy_to_user(process_t *p,uint64_t dst,const void *src,uint64_t n)
{ (void)p;memcpy((void *)(uintptr_t)dst,src,(size_t)n);return 0; }
static void draw_nc(gwin_t *w,int x,int y,const shz_rect_t *clip) { (void)w;(void)x;(void)y;(void)clip; }
static void gin_draw_pointer(const shz_rect_t *r) { (void)r; }
static void gfx_fb_present(int x,int y,int w,int h) { (void)x;(void)y;(void)w;(void)h;++g_fb.stat_presents; }
static void gfx_render_trace_present(process_t *p,const shz_present_t *arg,gwin_t *w,int32_t st,
 const uint32_t *pixels,const shz_present_layout_t *l,const shz_rect_t *d,uint64_t old)
{ (void)p;(void)arg;(void)w;(void)st;(void)pixels;(void)l;(void)d;(void)old;if(!locked) abort(); }
#include "written_coverage_production.inc"
#define CHECK(x) do { ++checks;if(!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1); } } while(0)
static uint32_t random_state=0xcb430719u;
static uint32_t rng(void) { random_state=random_state*1664525u+1013904223u;return random_state; }
static void bitmap_oracle(void)
{
    unsigned trial;
    CHECK(!shz_written_bytes(-1,20));CHECK(!shz_written_bytes(20,0));
    CHECK(shz_written_bytes(4096,1024)==524288);
    for(trial=0;trial<600;++trial) {
        int w=(int)(rng()%31)+1,h=(int)(rng()%23)+1,iteration,x,y;
        uint64_t n=shz_written_bytes(w,h);uint8_t *mask=calloc(1,(size_t)n+2);
        uint8_t oracle[31*23]={0};mask[n]=0x43;mask[n+1]=0xcb;
        for(iteration=0;iteration<25;++iteration) {
            int left=(int)(rng()%45)-7,top=(int)(rng()%35)-6;
            int right=left+(int)(rng()%39),bottom=top+(int)(rng()%29);
            shz_written_mark(mask,w,h,left,top,right,bottom);
            for(y=0;y<h;++y) for(x=0;x<w;++x) {
                if(x>=left && x<right && y>=top && y<bottom) oracle[y*w+x]=1;
                CHECK(shz_written_has(mask,w,h,x,y)==oracle[y*w+x]);
            }
            CHECK(mask[n]==0x43 && mask[n+1]==0xcb);
        }
        { int dw=(int)(rng()%37)+1,dh=(int)(rng()%27)+1;uint64_t bytes=shz_written_bytes(dw,dh);
          uint8_t *copied=calloc(1,(size_t)bytes+1);copied[bytes]=0x43;
          shz_written_copy(copied,dw,dh,mask,w,h);
          for(y=0;y<dh;++y) for(x=0;x<dw;++x)
              CHECK(shz_written_has(copied,dw,dh,x,y)==(x<w && y<h ? oracle[y*w+x] : 0));
          CHECK(copied[bytes]==0x43);free(copied); }
        free(mask);
    }
}
static void setup(gwin_t *w,unsigned index,int x,int y,int width,int height,gwin_t *parent)
{
    memset(w,0,sizeof *w);w->used=1;w->handle=0x1000+index+1;
    w->style=SHZ_WS_VISIBLE;w->x=x;w->y=y;w->parent=parent;
    CHECK(win_apply_size(w,width,height,NULL)==0);
}
static int32_t submit(gwin_t *w,uint32_t color,int x,int y,int width,int height)
{
    uint32_t pixels[32*24];shz_present_t p;unsigned i;process_t proc={336};
    for(i=0;i<(unsigned)(w->sw*w->sh);++i) pixels[i]=color;
    memset(&p,0,sizeof p);p.hwnd=w->handle;p.bits=(uint64_t)(uintptr_t)pixels;
    p.surf_w=w->sw;p.surf_h=w->sh;p.stride=(uint32_t)w->sw*4;p.x=x;p.y=y;p.w=width;p.h=height;
    return gfx_syscall_present(&proc,(uint64_t)(uintptr_t)&p);
}
static uint32_t pixel(int x,int y) { return g_fb.back[y*g_fb.width+x]; }
static void compositor(void)
{
    gwin_t *parent=&windows[1],*child=&windows[2],*normal=&windows[3];
    uint8_t *mask;uint32_t *surface;uint64_t before;shz_rect_t full={0,0,24,18};
    memset(windows,0,sizeof windows);DESKTOP->used=1;DESKTOP->handle=0x1001;
    g_fb.ready=1;g_fb.width=24;g_fb.height=18;g_fb.back=calloc(24*18,4);
    setup(parent,1,0,0,24,18,DESKTOP);DESKTOP->child=parent;
    CHECK(submit(parent,0xff1e1f22,0,0,24,18)==0);
    setup(child,2,2,2,12,10,parent);child->exstyle=WS_EX_TRANSPARENT_;parent->child=child;
    wm_damage(&full);
    CHECK(pixel(3,3)==0xff1e1f22); /* exact old compositor fails here */
    setup(normal,3,2,2,12,10,parent);normal->next=child;child->prev=normal;parent->child=normal;
    wm_damage(&full);CHECK(pixel(3,3)==FACE);
    parent->child=child;child->prev=NULL;free_window_memory(normal);memset(normal,0,sizeof *normal);wm_damage(&full);
    CHECK(submit(child,0xff102030,2,2,3,2)==0);CHECK(pixel(4,4)==0xff102030 && pixel(8,7)==0xff1e1f22);
    CHECK(submit(parent,0xff224466,0,0,24,18)==0);CHECK(pixel(4,4)==0xff102030 && pixel(8,7)==0xff224466);
    CHECK(submit(child,FACE,0,0,1,1)==0);CHECK(pixel(2,2)==FACE);
    CHECK(submit(child,0xffabcdef,11,9,1,1)==0);
    CHECK(win_apply_size(child,16,12,NULL)==0);wm_damage(&full);
    CHECK(pixel(13,11)==0xffabcdef && pixel(17,13)==0xff224466);
    CHECK(win_apply_size(child,8,6,NULL)==0);CHECK(win_apply_size(child,16,12,NULL)==0);wm_damage(&full);
    CHECK(pixel(4,4)==0xff102030 && pixel(13,11)==0xff224466);
    child->exstyle=0;wm_damage(&full);CHECK(pixel(17,13)==FACE);
    child->exstyle=WS_EX_TRANSPARENT_;wm_damage(&full);CHECK(pixel(17,13)==0xff224466 && pixel(4,4)==0xff102030);
    /* Private isolated-window readback has an empty zeroed target, rather
     * than the parent desktop below it; only actual child pixels are copied. */
    { uint32_t printed[16*12];shz_winop_t o={0};process_t proc={336};
      memset(printed,0xff,sizeof printed);o.flags=1;o.w=16;o.h=12;o.stride=16*4;o.bits=(uint64_t)(uintptr_t)printed;
      CHECK(winop_print(&proc,child,&o)==0 && printed[0]==FACE && printed[2+2*16]==0xff102030 && printed[15+11*16]==0);
      memset(printed,0x43,sizeof printed);before=live_allocations;fail_allocation=allocation_call+1;
      CHECK(winop_print(&proc,child,&o)==STATUS_NO_MEMORY && printed[0]==0x43434343 && live_allocations==before);
      fail_allocation=0; }
    /* Neither injected allocation site may alter old geometry/coverage/data. */
    mask=child->written;surface=child->surf;before=live_allocations;
    fail_allocation=allocation_call+1;CHECK(win_apply_size(child,20,16,NULL)==STATUS_NO_MEMORY);
    CHECK(child->written==mask && child->surf==surface && child->sw==16 && live_allocations==before);
    fail_allocation=allocation_call+2;CHECK(win_apply_size(child,20,16,NULL)==STATUS_NO_MEMORY);
    CHECK(child->written==mask && child->surf==surface && child->sw==16 && live_allocations==before);
    fail_allocation=0;
    fail_read=read_call+3;CHECK(submit(child,0xffabcdef,6,0,2,2)==STATUS_ACCESS_VIOLATION);
    CHECK(!shz_written_has(child->written,16,12,6,0) && pixel(8,2)==0xff224466);
    fail_read=0;
    /* Real coverage allocation failure happens after all caller rows stage. */
    setup(normal,3,0,0,4,4,parent);before=live_allocations;
    fail_allocation=allocation_call+2;CHECK(submit(normal,0xffabcdef,0,0,4,4)==STATUS_NO_MEMORY);
    CHECK(!normal->written && normal->surf[0]==FACE && live_allocations==before);
    fail_allocation=0;free_window_memory(normal);memset(normal,0,sizeof *normal);
    /* Actual compositor clip/region paths must keep mask coordinates in the
     * source client space when only an edge is visible on the desktop. */
    setup(normal,3,22,16,6,4,parent);normal->exstyle=WS_EX_TRANSPARENT_;
    normal->next=child;child->prev=normal;parent->child=normal;
    CHECK(submit(normal,0xff778899,0,0,6,4)==0);
    CHECK(pixel(23,17)==0xff778899 && pixel(0,0)==0xff224466);
    normal->rgn=calloc(1,sizeof *normal->rgn);normal->nrgn=1;
    *normal->rgn=(shz_rect_t){0,0,1,1};wm_damage(&full);
    CHECK(pixel(22,16)==0xff778899 && pixel(23,17)==0xff224466);
    normal->x=-2;normal->y=-1;wm_damage(&full);CHECK(pixel(0,0)==0xff224466);
    free(normal->rgn);normal->rgn=NULL;normal->nrgn=0;wm_damage(&full);
    CHECK(pixel(0,0)==0xff778899 && pixel(4,0)==0xff224466);
    parent->child=child;child->prev=NULL;free_window_memory(normal);memset(normal,0,sizeof *normal);wm_damage(&full);
    /* Top-level transparent no-content window cannot hide lower composition. */
    setup(normal,3,0,0,24,18,DESKTOP);normal->exstyle=WS_EX_TRANSPARENT_;
    normal->next=parent;parent->prev=normal;DESKTOP->child=normal;wm_damage(&full);
    CHECK(!covers_opaquely(normal,&full) && pixel(17,13)==0xff224466);
    CHECK(submit(normal,0xff778899,20,14,2,2)==0);CHECK(pixel(20,14)==0xff778899 && pixel(19,14)==0xff224466);
    /* Layered style keeps the old independent layer route rather than using
     * this non-layered client coverage to invent alpha blending. */
#ifndef SHZ_COVERAGE_BEFORE
    CHECK(!has_transparent_client(&(gwin_t){.exstyle=WS_EX_TRANSPARENT_|WS_EX_LAYERED_}));
#endif
    DESKTOP->child=parent;parent->prev=NULL;free_window_memory(normal);memset(normal,0,sizeof *normal);
    parent->child=NULL;free_window_memory(child);memset(child,0,sizeof *child);wm_damage(&full);
    CHECK(pixel(4,4)==0xff224466 && pixel(2,2)==0xff224466);
    free_window_memory(parent);memset(parent,0,sizeof *parent);free(g_fb.back);g_fb.back=NULL;
    CHECK(!live_allocations && !locked);
}
int main(void)
{
    bitmap_oracle();compositor();
    printf("WRITTEN-COVERAGE-HOST: %u checks PASS; exact production composition/resize/present, real pixels, OOM/row-fault rollback\n",checks);
    return 0;
}
