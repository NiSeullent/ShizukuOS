/* SPDX-License-Identifier: GPL-2.0-only
 * Exact production diagnostic helper with controlled logging/environment,
 * plus actual guarded/padded/top-down/bottom-up pixel memory. No guest proof. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <limits.h>
typedef uint32_t DWORD;
typedef uint16_t WCHAR;
typedef void *HANDLE;
typedef void *HBITMAP;
typedef void *HWND;
typedef struct { int32_t left, top, right, bottom; } RECT;
typedef struct { int w,h; uint32_t *bits; int topdown; HANDLE section; DWORD section_offset; } bitmap_t;
typedef struct { HWND hwnd; int memdc; } dc_t;
typedef struct { int n; } rlist_t;
typedef struct { bitmap_t *bm; const rlist_t *clip; int has_dirty; RECT dirty; } gctx_t;
typedef struct { HWND hwnd; bitmap_t bmp; } backing_t;
static DWORD thread_error;
static int trace_environment, debug_calls, environment_calls;
static char debug_line[641];
static DWORD shz_last_error(void) { return thread_error; }
static void shz_set_last_error(DWORD value) { thread_error=value; }
static DWORD GetEnvironmentVariableW(const WCHAR *name, WCHAR *value, DWORD count)
{
    (void)name; ++environment_calls; thread_error=999;
    if (count != 2) abort();
    if (!trace_environment) return 0;
    value[0]='1'; value[1]=0; return 1;
}
static int32_t NtShzDebugPrint(const char *bytes, uint32_t count)
{
    if (count > 640) abort();
    memcpy(debug_line,bytes,count);debug_line[count]=0;
    ++debug_calls; thread_error=777; return 0;
}
#define SHZ_GDI_INTERNAL_H
#include "../dlls/gdi32/gdi_render_trace.c"
#include "../../abi/shz_pixel_sample.h"
static unsigned checks;
#define VERIFY(c) do { ++checks; if (!(c)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#c); abort(); } } while(0)
static void samplers(void)
{
    uint32_t pixels[128], copy[128];
    shz_pixel_samples_t sample, reverse, a, b;
    unsigned i;
    for(i=0;i<128;++i) pixels[i]=0xc0c0c0u;
    sample=shz_pixel_samples(pixels,8,8,16,1,0,0,8,8);
    VERIFY(sample.count==64 && sample.differing==0 && sample.nonface==0);
    VERIFY(!shz_pixel_samples(NULL,8,8,16,1,0,0,8,8).count);
    VERIFY(!shz_pixel_samples(pixels,8,8,7,1,0,0,8,8).count);
    VERIFY(!shz_pixel_samples(pixels,-1,8,16,1,0,0,8,8).count);
    VERIFY(!shz_pixel_samples(pixels,8,8,16,1,9,0,10,8).count);
    VERIFY(!shz_pixel_samples(pixels,8,8,16,1,0,0,0,8).count);
    for(i=0;i<128;++i) pixels[i]=i;
    memcpy(copy,pixels,sizeof pixels);
    sample=shz_pixel_samples(pixels,8,8,16,1,0,0,8,8);
    reverse=shz_pixel_samples(pixels,8,8,16,0,0,0,8,8);
    VERIFY(sample.count==64 && sample.first==0 && sample.last==119 && sample.differing==63);
    VERIFY(reverse.count==64 && reverse.first==112 && reverse.last==7 && reverse.hash!=sample.hash);
    VERIFY(!memcmp(copy,pixels,sizeof pixels));
    sample=shz_pixel_samples(pixels,8,8,16,1,INT_MIN,INT_MIN,INT_MAX,INT_MAX);
    VERIFY(sample.count==64 && sample.first==0 && sample.last==119);
    sample=shz_pixel_samples(pixels,8,8,16,1,2,3,3,4);
    VERIFY(sample.count==1 && sample.first==50 && sample.last==50 && !sample.differing);
    {
        long page=sysconf(_SC_PAGESIZE);
        unsigned char *memory=mmap(NULL,(size_t)page*3,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        uint32_t *guarded;
        VERIFY(memory!=MAP_FAILED);
        VERIFY(!mprotect(memory+page,(size_t)page,PROT_READ|PROT_WRITE));
        guarded=(uint32_t *)(memory+2*page-4);
        *guarded=0xff123456;
        sample=shz_pixel_samples(guarded,1,1,1,0,INT_MIN,INT_MIN,INT_MAX,INT_MAX);
        VERIFY(sample.count==1 && sample.first==0xff123456 && sample.alpha==1);
        VERIFY(!munmap(memory,(size_t)page*3));
    }
    {
        uint32_t *many=malloc(10001*4);VERIFY(many!=NULL);
        for(i=0;i<10001;++i) many[i]=i;
        a=shz_pixel_samples(many,10001,1,10001,1,0,0,10001,1);
        b=shz_pixel_samples(many,10001,1,10001,1,0,0,10001,1);
        VERIFY(a.count==64 && a.first==0 && a.last==10000 && a.hash==b.hash);
        free(many);
    }
}
int main(void)
{
    uint32_t pixels[64], original[64];
    bitmap_t bitmap={8,8,pixels,1,(HANDLE)0x4444,0};
    dc_t dc={(HWND)0xabc,0};rlist_t clip={1};
    gctx_t context={&bitmap,&clip,1,{0,0,8,8}};
    backing_t backing={(HWND)0xabc,{8,8,pixels,1,NULL,0}};
    RECT rect={0,0,8,8};unsigned i;
    samplers();
    for(i=0;i<64;++i)pixels[i]=i;
    memcpy(original,pixels,sizeof pixels);
    thread_error=123;trace_environment=0;
    gdi_render_trace_dib(&bitmap,(HBITMAP)0x1234);
    gdi_render_trace_blit(&dc,&bitmap,&context,0,0,8,8,0,0,8,8,0xcc0020);
    gdi_render_trace_present(&backing,&rect,0);
    VERIFY(!debug_calls && thread_error==123 && environment_calls==1);
    trace_environment=1;trace_state=0;
    gdi_render_trace_dib(&bitmap,(HBITMAP)0x1234);
    VERIFY(debug_calls==1 && thread_error==123 && strstr(debug_line,"section=4444"));
    gdi_render_trace_blit(&dc,&bitmap,&context,0,0,8,8,0,0,8,8,0xcc0020);
    VERIFY(debug_calls==2 && thread_error==123 && strstr(debug_line,"clips=1") && strstr(debug_line,"source_w=8"));
    gdi_render_trace_blit(&dc,&bitmap,&context,0,0,8,8,INT_MAX,INT_MAX,INT_MAX,INT_MAX,0xcc0020);
    VERIFY(debug_calls==3 && thread_error==123 && strstr(debug_line,"sx=7fffffff"));
    gdi_render_trace_present(&backing,&rect,(int32_t)0xc0000008u);
    VERIFY(debug_calls==4 && thread_error==123 && strstr(debug_line,"status=c0000008"));
    VERIFY(!memcmp(original,pixels,sizeof pixels));
    {
        long page=sysconf(_SC_PAGESIZE);
        unsigned char *guard=mmap(NULL,(size_t)page*2,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        bitmap_t source={1024,2,(uint32_t *)guard,1,(HANDLE)0x4444,0};
        backing_t protected_backing={(HWND)0xabc,{1024,2,(uint32_t *)(guard+page),1,NULL,0}};
        RECT protected_rect={0,0,1024,2};
        VERIFY(guard!=MAP_FAILED);
        VERIFY(!mprotect(guard,(size_t)page,PROT_READ|PROT_WRITE));
        *((uint32_t *)guard)=0x123456;
        context.dirty.right=context.dirty.bottom=1;
        /* A one-pixel destination clip consumes only source[0]. Diagnostic
         * source sampling must not add a read from the inaccessible last row. */
        gdi_render_trace_blit(&dc,&source,&context,0,0,1024,2,0,0,1024,2,0xcc0020);
        VERIFY(debug_calls==5 && thread_error==123 && strstr(debug_line,"source_w=400"));
        gdi_render_trace_present(&protected_backing,&protected_rect,(int32_t)0xc0000005u);
        VERIFY(debug_calls==6 && thread_error==123 && strstr(debug_line,"status=c0000005"));
        VERIFY(!munmap(guard,(size_t)page*2));
    }
    debug_calls=0;present_count=0;
    for(i=0;i<10000;++i)gdi_render_trace_present(&backing,&rect,0);
    VERIFY(debug_calls==80 && present_count==4096 && thread_error==123);
    VERIFY(!memcmp(original,pixels,sizeof pixels));
    printf("RENDER-TRACE-HOST: %u checks passed; bounded kernel samples, guards/padding/orientation, protected unused GDI source/backing, trace opt-in, LastError, unchanged pixels and 80-line cap\n",checks);
    return 0;
}
