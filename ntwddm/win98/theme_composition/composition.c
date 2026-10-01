/* SPDX-License-Identifier: GPL-2.0-only
 * Diagnostic composition: provider output is tested in a native 32-bit DIB.
 * A separate native DrawTextA reference tests every label pixel, not its HRESULT.
 * Destination samples are observations, never proof of complete visible scanout.
 */
#include "composition.h"

static const RECT regions[COMPOSE_REGIONS] = {
    {12,12,444,48}, {12,64,108,116}, {120,64,216,116},
    {228,64,324,116}, {336,64,432,116}, {12,136,216,184}, {228,136,432,184}
};
static const char *const labels_a[COMPOSE_REGIONS] = {
    "", "Normal", "Hot", "Pressed", "Disabled", "Classic (C)", "Modern (M)"
};
static const WCHAR *const labels_w[COMPOSE_REGIONS] = {
    L"", L"Normal", L"Hot", L"Pressed", L"Disabled", L"Classic (C)", L"Modern (M)"
};
/* Independent constants from the frozen ntstyle.c contract. This diagnostic
 * does not query the provider to obtain the expected value it is testing. */
static const DWORD fill[2][4] = {
    {0xc0c0c0u,0xd4d0c8u,0xa0a0a0u,0xc0c0c0u},
    {0xf0f0f0u,0xe5f1fbu,0xcce4f7u,0xf0f0f0u}
};
static const DWORD border[2][4] = {
    {0x808080u,0x000080u,0x000000u,0x808080u},
    {0x0078d7u,0x0078d7u,0x005a9eu,0xc8c8c8u}
};
static COLORREF colorref(DWORD rgb)
{
    return ((rgb >> 16) & 255u) | (rgb & 0xff00u) | ((rgb & 255u) << 16);
}
static void clear_bytes(void *p, unsigned n)
{
    unsigned i; unsigned char *b = p;
    for (i=0;i<n;++i) b[i]=0;
}
static int restored(HDC dc,HGDIOBJ object)
{
    HGDIOBJ prior=SelectObject(dc,object);
    return prior && prior!=HGDI_ERROR;
}
static DWORD pixel_rgb(const DWORD *p, int x, int y)
{
    return p[y*COMPOSE_WIDTH+x] & 0x00ffffffu;
}
static void background_sample(HDC dc, const DWORD *pixels, int x, int y,
                              DWORD expected, compose_report *r)
{
    COLORREF actual=GetPixel(dc,x,y);
    ++r->background_samples;
    if (actual==CLR_INVALID) ++r->memory_reads_invalid;
    if (pixel_rgb(pixels,x,y)!=expected || actual!=colorref(expected))
        ++r->background_mismatches;
}
static int check_background(HDC dc,const DWORD *p,DWORD style,unsigned index,
                            int state,compose_report *r)
{
    const RECT *a=&regions[index]; DWORD f,b; unsigned before=r->background_mismatches;
    if (index==0) {
        b=style==1?0x000040u:0x004578u;
        background_sample(dc,p,a->left,a->top,b,r);
        background_sample(dc,p,a->right-1,a->bottom-1,b,r);
        /* The horizontal gradient endpoints are inside the one-pixel border. */
        background_sample(dc,p,a->left+1,a->top+2,style==1?0x000080u:0x0078d7u,r);
        background_sample(dc,p,a->right-2,a->top+2,style==1?0x000080u:0x005a9eu,r);
    } else {
        f=fill[style-1][state-1]; b=border[style-1][state-1];
        background_sample(dc,p,a->left,a->top,b,r);
        background_sample(dc,p,a->right-1,a->bottom-1,b,r);
        background_sample(dc,p,a->left+2,a->top+2,f,r);
        background_sample(dc,p,a->right-3,a->bottom-3,f,r);
    }
    return before==r->background_mismatches && !r->memory_reads_invalid;
}
int compose_scene(HDC target,DWORD style,HANDLE window_theme,HANDLE button_theme,
                  compose_background background,compose_text text,compose_report *r)
{
    BITMAPINFO info; NONCLIENTMETRICSA metrics;
    HDC memory=NULL,reference=NULL; HBITMAP bitmap=NULL,reference_bitmap=NULL;
    HGDIOBJ old_bitmap=NULL,old_reference=NULL,old_font=NULL; HFONT font=NULL;
    DWORD *pixels=NULL,*reference_pixels=NULL; unsigned i; int ok=0;
    int ink_x[COMPOSE_REGIONS],ink_y[COMPOSE_REGIONS];
    const DWORD centered=DT_CENTER|DT_VCENTER|DT_SINGLELINE;
    clear_bytes(r,sizeof(*r));
    if (!target || (style!=1u && style!=2u) || !window_theme || !button_theme || !background || !text) {
        r->api_stage=1;return 0;
    }
    clear_bytes(&info,sizeof(info)); info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth=COMPOSE_WIDTH;info.bmiHeader.biHeight=-COMPOSE_HEIGHT;
    info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;
    r->api_stage=2;memory=CreateCompatibleDC(target);if (!memory) goto done;
    r->api_stage=3;bitmap=CreateDIBSection(target,&info,DIB_RGB_COLORS,(void **)&pixels,NULL,0);
    if (!bitmap || !pixels) goto done;
    r->api_stage=4;old_bitmap=SelectObject(memory,bitmap);
    if (!old_bitmap || old_bitmap==HGDI_ERROR) goto done;
    r->api_stage=5;reference=CreateCompatibleDC(target);if (!reference) goto done;
    r->api_stage=6;reference_bitmap=CreateDIBSection(target,&info,DIB_RGB_COLORS,(void **)&reference_pixels,NULL,0);
    if (!reference_bitmap || !reference_pixels) goto done;
    r->api_stage=7;old_reference=SelectObject(reference,reference_bitmap);
    if (!old_reference || old_reference==HGDI_ERROR) goto done;
    clear_bytes(&metrics,sizeof(metrics));metrics.cbSize=sizeof(metrics)-sizeof(metrics.iPaddedBorderWidth);
    r->api_stage=8;if (!SystemParametersInfoA(SPI_GETNONCLIENTMETRICS,metrics.cbSize,&metrics,0)) goto done;
    r->api_stage=9;font=CreateFontIndirectA(&metrics.lfMessageFont);if (!font) goto done;
    r->api_stage=10;old_font=SelectObject(reference,font);if (!old_font || old_font==HGDI_ERROR) goto done;
    r->api_stage=11;if (!SetBkMode(reference,TRANSPARENT) || !GdiFlush()) goto done;
    {
        RECT client={0,0,COMPOSE_WIDTH,COMPOSE_HEIGHT};
        r->api_stage=12;if (!FillRect(memory,&client,(HBRUSH)(COLOR_BTNFACE+1))) goto done;
    }
    for (i=0;i<COMPOSE_REGIONS;++i) {
        const RECT *a=&regions[i]; RECT reference_rect=*a; HANDLE theme=i==0?window_theme:button_theme;
        int state=i==0?1:(i<5?(int)i:(i==5?(style==1?3:1):(style==2?3:1)));
        const char *label=i?labels_a[i]:(style==1?"Classic theme":"Modern theme");
        LPCWSTR wide=i?labels_w[i]:(style==1?L"Classic theme":L"Modern theme");
        DWORD tc=i==0?0xffffffu:(i==4?(style==1?0x808080u:0xa0a0a0u):0u);
        int x,y,length=0;DWORD expected_count=0,actual_count=0,mismatch=0;
        r->api_stage=20+i;if (background(theme,memory,1,state,a,NULL)!=S_OK || !GdiFlush()) goto done;
        check_background(memory,pixels,style,i,state,r);
        r->api_stage=30+i;
        if (!BitBlt(reference,a->left,a->top,a->right-a->left,a->bottom-a->top,memory,a->left,a->top,SRCCOPY) || !GdiFlush()) goto done;
        /* Snapshot only this region's pre-text background to distinguish
         * transparent native text ink from gradient/border pixels. */
        while (label[length]) ++length;
        r->api_stage=40+i;if (SetTextColor(reference,colorref(tc))==CLR_INVALID ||
            !DrawTextA(reference,label,length,&reference_rect,centered) || !GdiFlush()) goto done;
        r->api_stage=50+i;if (text(theme,memory,1,state,wide,-1,centered,0,a)!=S_OK || !GdiFlush()) goto done;
        ink_x[i]=ink_y[i]=-1;
        for (y=a->top+1;y<a->bottom-1;++y) for (x=a->left+1;x<a->right-1;++x) {
            DWORD actual=pixel_rgb(pixels,x,y),expected=pixel_rgb(reference_pixels,x,y);
            /* All text colors differ from the fixed palette background in
             * their region; disabled gray also differs from its fill. */
            if (expected==tc) {++expected_count;if (ink_x[i]<0) {ink_x[i]=x;ink_y[i]=y;}}
            if (actual==tc) ++actual_count;
            if (actual!=expected) ++mismatch;
        }
        r->reference_ink[i]=expected_count;r->actual_ink[i]=actual_count;r->text_pixel_mismatches[i]=mismatch;
        if (expected_count<12u || actual_count<12u || mismatch) continue;
        /* Native GetPixel must independently agree with the actual DIB at
         * a real text-ink point, including its COLORREF byte order. */
        if (GetPixel(memory,ink_x[i],ink_y[i])!=colorref(tc)) ++r->memory_reads_invalid;
    }
    {
        RECT footer={12,200,444,252};
        r->api_stage=60;if (text(button_theme,memory,1,1,
            L"Offscreen composition / native text reference diagnostic.\nAutomatic switches at 10 and 20 seconds; closes at 30 seconds.",
            -1,DT_CENTER|DT_WORDBREAK,0,&footer)!=S_OK || !GdiFlush()) goto done;
    }
    r->memory_valid=!r->background_mismatches && !r->memory_reads_invalid;
    for (i=0;i<COMPOSE_REGIONS;++i) if (r->reference_ink[i]<12u || r->actual_ink[i]<12u || r->text_pixel_mismatches[i]) r->memory_valid=0;
    /* Exactly one transfer of the completed full scene to the visible DC. */
    r->api_stage=70;if (!BitBlt(target,0,0,COMPOSE_WIDTH,COMPOSE_HEIGHT,memory,0,0,SRCCOPY) || !GdiFlush()) goto done;
    r->transfer_succeeded=1;r->screen_bpp=(DWORD)GetDeviceCaps(target,BITSPIXEL);
    for (i=0;i<COMPOSE_REGIONS;++i) {
        const RECT *a=&regions[i];int xs[3]={a->left,a->left+2,ink_x[i]};int ys[3]={a->top,a->top+2,ink_y[i]};unsigned j;
        for (j=0;j<3;++j) {
            COLORREF observed; if (xs[j]<0 || ys[j]<0) continue;
            observed=GetPixel(target,xs[j],ys[j]);++r->screen_samples;
            if (observed==CLR_INVALID) ++r->screen_reads_invalid;
            else if (observed!=colorref(pixel_rgb(pixels,xs[j],ys[j]))) ++r->screen_mismatches;
        }
    }
    r->api_stage=0;ok=r->memory_valid;
done:
    /* Destroying each private DC releases any selected bitmap/font even if
     * restoring a selection fails. Never delete caller-owned stock objects. */
    if (old_font && old_font!=HGDI_ERROR && !restored(reference,old_font)) ++r->cleanup_errors;
    if (old_reference && old_reference!=HGDI_ERROR && !restored(reference,old_reference)) ++r->cleanup_errors;
    if (old_bitmap && old_bitmap!=HGDI_ERROR && !restored(memory,old_bitmap)) ++r->cleanup_errors;
    if (reference && !DeleteDC(reference)) ++r->cleanup_errors;
    if (memory && !DeleteDC(memory)) ++r->cleanup_errors;
    if (font && !DeleteObject(font)) ++r->cleanup_errors;
    if (reference_bitmap && !DeleteObject(reference_bitmap)) ++r->cleanup_errors;
    if (bitmap && !DeleteObject(bitmap)) ++r->cleanup_errors;
    return ok && !r->cleanup_errors;
}
