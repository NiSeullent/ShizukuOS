/* SPDX-License-Identifier: GPL-2.0-only
 * Host tests for diagnostic pixel gates and resource ownership. Native font,
 * GDI transfer, Windows identity and visible output require the real trial.
 */
#ifndef COMPOSITION_HOST_TEST
#define COMPOSITION_HOST_TEST
#endif
#include "composition.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {int kind;DWORD *pixels;} object;
typedef struct {object *bitmap,*font;COLORREF text;} dc;
static object stock_bitmap={1,NULL},stock_font={2,NULL};
static unsigned checks,calls,fail_at,live_dc,live_bitmap,live_font,visible_blits;
static DWORD current_style;
static int empty_provider_text,partial_provider_text,empty_reference_text,bad_background,
    mismatch_screen,invalid_screen;static dc *visible;
#define CHECK(x) do {++checks;if (!(x)) {fprintf(stderr,"check %u line %u\n",checks,__LINE__);exit(1);}} while (0)
static int fault(void) {return ++calls==fail_at;}
static DWORD rgb(COLORREF c) {return ((c&255u)<<16)|(c&0xff00u)|((c>>16)&255u);}
static COLORREF cr(DWORD c) {return ((c&255u)<<16)|(c&0xff00u)|((c>>16)&255u);}
HDC CreateCompatibleDC(HDC source)
{
    dc *d;(void)source;if (fault()) return NULL;d=calloc(1,sizeof(*d));CHECK(d);
    d->bitmap=&stock_bitmap;d->font=&stock_font;++live_dc;return d;
}
HBITMAP CreateDIBSection(HDC d,const BITMAPINFO *i,unsigned usage,void **p,HANDLE section,DWORD offset)
{
    object *b;(void)d;CHECK(i->bmiHeader.biWidth==COMPOSE_WIDTH && i->bmiHeader.biHeight==-COMPOSE_HEIGHT);
    CHECK(i->bmiHeader.biBitCount==32 && !usage && !section && !offset);
    if (fault()) return NULL;b=calloc(1,sizeof(*b));CHECK(b);b->kind=1;
    b->pixels=calloc(COMPOSE_WIDTH*COMPOSE_HEIGHT,sizeof(DWORD));CHECK(b->pixels);*p=b->pixels;++live_bitmap;return b;
}
HGDIOBJ SelectObject(HDC h,HGDIOBJ value)
{
    dc *d=h;object *o=value,*old;if (fault()) return HGDI_ERROR;
    if (o->kind==1) {old=d->bitmap;d->bitmap=o;} else {old=d->font;d->font=o;}return old;
}
BOOL DeleteDC(HDC d) {int bad=fault();CHECK(live_dc);--live_dc;free(d);return !bad;}
BOOL DeleteObject(HGDIOBJ p)
{
    object *o=p;int bad=fault();CHECK(o!=&stock_bitmap && o!=&stock_font);
    if (o->kind==1) {CHECK(live_bitmap);--live_bitmap;free(o->pixels);} else {CHECK(live_font);--live_font;}free(o);return !bad;
}
BOOL SystemParametersInfoA(unsigned action,unsigned bytes,void *p,unsigned flags)
{CHECK(action==SPI_GETNONCLIENTMETRICS && bytes==sizeof(NONCLIENTMETRICSA)-sizeof(int) && !flags);(void)p;return !fault();}
HFONT CreateFontIndirectA(const LOGFONTA *f)
{object *o;(void)f;if (fault()) return NULL;o=calloc(1,sizeof(*o));CHECK(o);o->kind=2;++live_font;return o;}
int SetBkMode(HDC d,int mode) {(void)d;CHECK(mode==TRANSPARENT);return fault()?0:1;}
COLORREF SetTextColor(HDC h,COLORREF c) {dc *d=h;COLORREF prior=d->text;if (fault()) return CLR_INVALID;d->text=c;return prior;}
int FillRect(HDC h,const RECT *a,HBRUSH brush)
{dc *d=h;int x,y;(void)brush;if (fault()) return 0;for(y=a->top;y<a->bottom;++y)for(x=a->left;x<a->right;++x)d->bitmap->pixels[y*COMPOSE_WIDTH+x]=0xc0c0c0u;return 1;}
static void ink(dc *d,const char *s,int n,const RECT *a,int partial)
{
    int x0=(a->left+a->right-n*6)/2,y0=(a->top+a->bottom-7)/2,i,x,y;
    for(i=0;i<n-(partial?1:0);++i)for(y=0;y<7;++y)for(x=0;x<5;++x)
        if (((unsigned char)s[i]+x+y)%3) d->bitmap->pixels[(y0+y)*COMPOSE_WIDTH+x0+i*6+x]=rgb(d->text);
}
int DrawTextA(HDC h,const char *s,int n,RECT *a,unsigned flags)
{dc *d=h;CHECK(flags==(DT_CENTER|DT_VCENTER|DT_SINGLELINE));if (fault()) return 0;if (!empty_reference_text)ink(d,s,n,a,0);return 7;}
BOOL BitBlt(HDC dh,int x,int y,int w,int height,HDC sh,int sx,int sy,DWORD rop)
{
    dc *d=dh,*s=sh;int row;(void)rop;if (fault()) return 0;
    if (d==visible) {++visible_blits;CHECK(x==0 && y==0 && w==COMPOSE_WIDTH && height==COMPOSE_HEIGHT);}
    for(row=0;row<height;++row)memcpy(d->bitmap->pixels+(y+row)*COMPOSE_WIDTH+x,s->bitmap->pixels+(sy+row)*COMPOSE_WIDTH+sx,(unsigned)w*4u);return 1;
}
BOOL GdiFlush(void) {return !fault();}
COLORREF GetPixel(HDC h,int x,int y)
{
    dc *d=h;if (fault() || (d==visible && invalid_screen)) return CLR_INVALID;
    CHECK(x>=0 && y>=0 && x<COMPOSE_WIDTH && y<COMPOSE_HEIGHT);
    return cr(d->bitmap->pixels[y*COMPOSE_WIDTH+x]) ^ (d==visible && mismatch_screen?1u:0u);
}
int GetDeviceCaps(HDC d,int which) {(void)d;CHECK(which==BITSPIXEL);return fault()?0:32;}
static HRESULT background(HANDLE theme,HDC h,int part,int state,const RECT *a,const RECT *clip)
{
    dc *d=h;int x,y;DWORD fills[2][4]={{0xc0c0c0,0xd4d0c8,0xa0a0a0,0xc0c0c0},{0xf0f0f0,0xe5f1fb,0xcce4f7,0xf0f0f0}};
    DWORD borders[2][4]={{0x808080,0x000080,0,0x808080},{0x0078d7,0x0078d7,0x005a9e,0xc8c8c8}};
    CHECK(part==1 && !clip);if (fault()) return -1;
    for(y=a->top;y<a->bottom;++y)for(x=a->left;x<a->right;++x) {
        int edge=x==a->left || x==a->right-1 || y==a->top || y==a->bottom-1;DWORD c;
        if (theme==(HANDLE)1) {
            if (edge)c=current_style==1?0x000040:0x004578;
            else if (current_style==1)c=0x000080;
            else {int den=a->right-a->left-3,t=x-a->left-1;c=((DWORD)(120+(90-120)*t/den)<<8)|(DWORD)(215+(158-215)*t/den);}
        } else c=edge?borders[current_style-1][state-1]:fills[current_style-1][state-1];
        d->bitmap->pixels[y*COMPOSE_WIDTH+x]=bad_background?0xc0c0c0:c;
    }
    return S_OK;
}
static HRESULT provider_text(HANDLE theme,HDC h,int part,int state,LPCWSTR s,int n,DWORD flags,DWORD flags2,const RECT *a)
{
    dc *d=h;char label[150];unsigned i=0;(void)part;CHECK(n==-1 && !flags2);
    if (fault())return -1;if (flags&DT_WORDBREAK)return S_OK;
    while(s[i]) {label[i]=(char)s[i];++i;}label[i]=0;
    d->text=cr(theme==(HANDLE)1?0xffffff:state==4?(current_style==1?0x808080:0xa0a0a0):0);
    if (!empty_provider_text)ink(d,label,(int)i,a,partial_provider_text);return S_OK;
}
static int trial(DWORD style,compose_report *r)
{
    dc target;object bitmap={1,NULL};int ok;memset(&target,0,sizeof(target));
    bitmap.pixels=calloc(COMPOSE_WIDTH*COMPOSE_HEIGHT,4);CHECK(bitmap.pixels);target.bitmap=&bitmap;visible=&target;current_style=style;
    ok=compose_scene(&target,style,(HANDLE)1,(HANDLE)2,background,provider_text,r);free(bitmap.pixels);
    CHECK(!live_dc && !live_bitmap && !live_font);CHECK(visible_blits<=1);return ok;
}
static void reset(void)
{calls=fail_at=visible_blits=0;empty_provider_text=partial_provider_text=empty_reference_text=bad_background=mismatch_screen=invalid_screen=0;}
int main(void)
{
    compose_report r;unsigned style,n,i;
    for(style=1;style<=2;++style) {
        reset();CHECK(trial(style,&r));CHECK(r.memory_valid && r.transfer_succeeded && !r.api_stage);
        CHECK(r.background_samples==28 && !r.background_mismatches && !r.memory_reads_invalid);
        CHECK(r.screen_samples==21 && !r.screen_mismatches && !r.screen_reads_invalid);
        for(i=0;i<COMPOSE_REGIONS;++i)CHECK(r.reference_ink[i]>=12 && r.reference_ink[i]==r.actual_ink[i] && !r.text_pixel_mismatches[i]);
        n=calls;
        reset();empty_provider_text=1;CHECK(!trial(style,&r));CHECK(!r.memory_valid && r.transfer_succeeded);
        reset();partial_provider_text=1;CHECK(!trial(style,&r));CHECK(!r.memory_valid && r.text_pixel_mismatches[5]);
        reset();empty_reference_text=1;CHECK(!trial(style,&r));CHECK(!r.memory_valid && !r.reference_ink[0]);
        reset();bad_background=1;CHECK(!trial(style,&r));CHECK(r.background_mismatches);
        reset();mismatch_screen=1;CHECK(trial(style,&r));CHECK(r.memory_valid && r.screen_mismatches==21);
        reset();invalid_screen=1;CHECK(trial(style,&r));CHECK(r.memory_valid && r.screen_reads_invalid==21);
        /* Inject each API/cleanup failure in turn. The target remains owned
         * by the caller and every acquired private object is released. */
        for(i=1;i<=n;++i) {reset();fail_at=i;(void)trial(style,&r);CHECK(r.api_stage || r.cleanup_errors || r.memory_reads_invalid || r.screen_reads_invalid || !r.screen_bpp);}
    }
    reset();CHECK(!trial(0,&r));CHECK(r.api_stage==1 && !visible_blits);
    printf("PASS: %u composition pixel, text-mask, transfer and ownership assertions\n",checks);return 0;
}
