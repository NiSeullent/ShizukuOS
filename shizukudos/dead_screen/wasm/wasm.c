/* SPDX-License-Identifier: GPL-2.0-only
 * Same held C core/renderer, browser design/game preview ONLY.
 * No guest framebuffer, OS hook, native crash, heap or imported service.
 */
#include "../dead_screen.h"
#include "../../supervisor/src/font8x8_basic.h"

static ds_state state;
static uint32_t pixels[800*600];
static char trace_text[2048];
static unsigned width=640,height=480,ready,text_mode;
static size_t trace_length;

/* Freestanding compiler struct-copy/clear support. Volatile loops prevent this
 * implementation being rewritten into a recursive libc call. No allocator. */
void *memcpy(void *dst,const void *src,size_t n)
{
    volatile unsigned char *d=dst;const volatile unsigned char *s=src;
    for(size_t i=0;i<n;++i)d[i]=s[i];return dst;
}
void *memset(void *dst,int value,size_t n)
{
    volatile unsigned char *d=dst;for(size_t i=0;i<n;++i)d[i]=(unsigned char)value;return dst;
}
static int trace_writer(void *context,const char *bytes,size_t n)
{
    (void)context;
    if(n>sizeof trace_text-1-trace_length)return -1;
    for(size_t i=0;i<n;++i)trace_text[trace_length++]=bytes[i];
    trace_text[trace_length]=0;return 0;
}
static void preview_text(unsigned x,unsigned y,const char *text,uint32_t color)
{
    const unsigned ox=(width-640)/2,oy=(height-480)/2;
    for(unsigned n=0;text[n] && x+n*8+8<=632;++n)
        for(unsigned yy=0;yy<8;++yy)for(unsigned xx=0;xx<8;++xx)
            if(font8x8_basic[(unsigned char)text[n]][yy]&(1u<<xx))
                pixels[(oy+y+yy)*width+ox+x+n*8+xx]=color;
}
static void preview_clear(unsigned x,unsigned y,unsigned end)
{
    const unsigned ox=(width-640)/2,oy=(height-480)/2;
    for(unsigned yy=y;yy<y+8;++yy)for(unsigned xx=x;xx<end;++xx)
        pixels[(oy+yy)*width+ox+xx]=0;
}
static void preview_labels(void)
{
    /* Preserve the held native renderer. Replace its native-only assertions
     * visibly in this adapter, for both trace/items panes and every game. */
    if(state.show_trace) {
        preview_clear(304,76,632);
        preview_text(304,76,"EXAMPLE TRACE - PREVIEW",0xffffff);
    } else {
        preview_clear(304,396,632);
        preview_text(304,396,"T shows example traceback",0xaaaaaa);
    }
    preview_clear(24,466,632);
    preview_text(24,466,"Esc menu  R restart  L KO/EN  T trace/items | design/game preview",0xaaaaaa);
}
int ds_preview_render(void)
{
    if(!ready)return -1;
    ds_surface f={pixels,width,height,width,800*600,1};
    int status=text_mode?ds_fallback_framebuffer(&state,&f):ds_render(&state,&f);
    if(status)return status;
    if(!text_mode)preview_labels();
    /* RGBX words from the same renderer become little-endian RGBA8. */
    for(unsigned i=0;i<width*height;++i)pixels[i]|=0xff000000u;
    return 0;
}
int ds_preview_init(void)
{
    ds_init(&state);text_mode=0;width=640;height=480;
    ds_fault example={0};
    const char reason[]="SYNTHETIC EXAMPLE TRACE - design/game preview, not an OS error";
    for(unsigned i=0;i<sizeof reason;++i)example.reason[i]=reason[i];
    /* Explicit examples, not guest addresses or observed crash evidence. */
    example.ip=0x11111111;example.sp=0x22222222;example.bp=0x33333333;
    example.flags=0x202;example.vector=14;example.error=2;
    example.cr2=0x44444444;example.cr3=0x55555555;example.registers_valid=1;
    for(unsigned i=0;i<DS_REGS;++i)example.reg[i]=0x1000+i;
    example.frames[0]=example.ip;example.frame_count=1;
    ready=ds_latch(&state,DS_KERNEL_FATAL,&example)==1;
    trace_length=0;
    if(!ready || ds_fallback(&state,trace_writer,0)) {ready=0;return -1;}
    return ds_preview_render();
}
void ds_preview_input(int key)
{if(ready && !text_mode && key>=DS_NONE && key<=DS_TRACE)ds_key_event(&state,(enum ds_key)key);}
void ds_preview_tick(void) {if(ready && !text_mode)ds_tick(&state);}
uintptr_t ds_preview_pixels(void) {return (uintptr_t)pixels;}
unsigned ds_preview_width(void) {return width;}
unsigned ds_preview_height(void) {return height;}
uintptr_t ds_preview_trace(void) {return (uintptr_t)trace_text;}
unsigned ds_preview_trace_len(void) {return (unsigned)trace_length;}
unsigned ds_preview_mode(void) {return state.mode;}
unsigned ds_preview_score(void)
{return state.mode==DS_TETRIS?state.tetris.score:state.mode==DS_SUIKA?state.suika.score:0;}
void ds_preview_fallback(int enable) {if(ready)text_mode=!!enable;}
/* Optional size control; preserves the example/game state and rejects all
 * other modes without mutation. The stable root ABI can simply use init(). */
int ds_preview_set_size(unsigned w,unsigned h)
{if(!ready || !((w==640 && h==480)||(w==800 && h==600)))return -1;width=w;height=h;return ds_preview_render();}
