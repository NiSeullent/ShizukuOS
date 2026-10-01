/* SPDX-License-Identifier: GPL-2.0-only
 * Exact kernel diagnostic bodies; controlled live/hidden window state and
 * actual protected pixel pages. This is observation safety, not guest proof. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <unistd.h>
#include "../../kernel64/gfx_present_layout.h"
#define GFX_MAX_WINDOWS 256
typedef struct { uint32_t name_len; uint16_t atom,name[64]; } gclass_t;
typedef struct gwin gwin_t;
struct gwin {
    int used,destroying,msgonly; uint64_t handle;
    gwin_t *parent,*next; gclass_t *cls;
    uint32_t style,exstyle,pid,tid; int32_t x,y,w,h,sw,sh;
    uint32_t *surf;
};
typedef struct { int pid; } process_t;
static gwin_t windows[GFX_MAX_WINDOWS], *g_win = windows;
static struct { uint32_t *back,width,height; uint64_t stat_presents; } g_fb;
static int opt_in;
static unsigned tree_lines,present_lines,checks;
static char last_present[2048],last_tree[1024];
static int k64_cmdline_has(const char *s) { (void)s; return opt_in; }
static int wm_is_visible(gwin_t *w)
{
    for (;w && w!=g_win;w=w->parent)
        if (w->msgonly || !(w->style & SHZ_WS_VISIBLE)) return 0;
    return 1;
}
static void kprintf(const char *fmt,...)
{
    char line[2048]; va_list ap; int n;
    va_start(ap,fmt); n=vsnprintf(line,sizeof line,fmt,ap); va_end(ap);
    if (n<0 || (size_t)n>=sizeof line) abort();
    if (strstr(line,"raster: tree")) {
        if ((size_t)n>=sizeof last_tree) abort();
        ++tree_lines; memcpy(last_tree,line,(size_t)n+1);
    } else if (strstr(line,"raster: present")) {
        ++present_lines; memcpy(last_present,line,(size_t)n+1);
    } else abort();
}
#include "../../kernel64/gfx_render_trace.h"
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1;} } while(0)
int main(int argc,char **argv)
{
    uint32_t source[4]={0xff1e1f22,0xff1e1f22,0xff123456,0xff1e1f22};
    uint32_t retained[4]={0xff1e1f22,0xff1e1f22,0xff123456,0xff1e1f22};
    uint32_t screen[4]={0xc0c0c0,0xc0c0c0,0xc0c0c0,0xc0c0c0};
    uint32_t original[4]; gclass_t cls; process_t proc={336};
    shz_present_t p={0}; shz_present_layout_t layout; shz_rect_t damage={0,0,2,2};
    unsigned i; long page=sysconf(_SC_PAGESIZE); void *guard;
    opt_in=argc>1 && !strcmp(argv[1],"enabled");
    guard=mmap(0,(size_t)page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(guard!=MAP_FAILED); memset(&cls,0,sizeof cls);
    cls.name_len=64; cls.atom=0xc234; for(i=0;i<64;++i) cls.name[i]=i==2 ? 0x400 : 'C';
    for(i=1;i<GFX_MAX_WINDOWS;++i) {
        windows[i].used=1;windows[i].handle=0x1000+i;windows[i].parent=g_win;
        windows[i].style=SHZ_WS_VISIBLE;windows[i].cls=&cls;
        windows[i].surf=retained;windows[i].sw=windows[i].sh=2;
        windows[i].w=windows[i].h=2;
    }
    /* Invisible/dead/message-only backing pages must not be read by the tree. */
    windows[1].style=0;windows[1].surf=guard;
    windows[2].destroying=1;windows[2].surf=guard;
    windows[3].msgonly=1;windows[3].surf=guard;
    g_fb.back=screen;g_fb.width=g_fb.height=2;g_fb.stat_presents=10;
    p.hwnd=windows[4].handle;p.w=p.h=p.surf_w=p.surf_h=2;p.stride=8;p.bits=0x10000;
    CHECK(shz_present_layout(&p,2,2,4096,0x10000,0x100000,&layout)==SHZ_PRESENT_OK);
    memcpy(original,retained,sizeof original);
    gfx_render_trace_present(&proc,&p,&windows[4],0,source,&layout,&damage,9);
    CHECK(tree_lines==(opt_in ? 16u : 0u));CHECK(present_lines==(opt_in ? 1u : 0u));
    if (opt_in) {
        CHECK(strstr(last_present,"source_first=ff1e1f22")!=0);
        CHECK(strstr(last_present,"stored_first=ff1e1f22")!=0);
        CHECK(strstr(last_present,"screen_first=c0c0c0")!=0);
        CHECK(strstr(last_present,"fb_updates=1")!=0);
        CHECK(strstr(last_tree,"class=CC?CCCCCCCCCCCCCCCCCCCCCCCCCCCC")!=0);
        CHECK(strstr(last_tree,"row=16")!=0);
        CHECK(strstr(last_tree,"atom=c234")!=0);
    }
    CHECK(!memcmp(original,retained,sizeof original));CHECK(screen[0]==0xc0c0c0);
    for(i=0;i<3;++i) gfx_render_trace_present(&proc,&p,&windows[4],0,source,&layout,&damage,9);
    CHECK(tree_lines==(opt_in ? 64u : 0u));
    gfx_render_trace_present(&proc,&p,&windows[4],0,source,&layout,&damage,9);
    CHECK(tree_lines==(opt_in ? 64u : 0u));
    /* A failed staging request must not read either source or retained bytes. */
    windows[4].surf=guard;
    gfx_render_trace_present(&proc,&p,&windows[4],(int32_t)0xc0000005,0,&layout,0,10);
    CHECK(!opt_in || strstr(last_present,"stored_samples=0"));
    CHECK(!opt_in || strstr(last_present,"source_samples=0"));
    CHECK(munmap(guard,(size_t)page)==0);
    printf("RENDER-TREE-HOST: %u checks PASS (%s), bounded real retained/source/screen observations\n",checks,opt_in ? "enabled" : "disabled");
    return 0;
}
