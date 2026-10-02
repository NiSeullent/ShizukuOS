/* SPDX-License-Identifier: GPL-2.0-only
 * Original Windows AMD64 DirectWrite acceptance. The private CJK face is
 * supplied on the private FAT volume, never installed or globally registered.
 * Expected cmap/hmtx values come from separately parsed immutable font bytes.
 */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#define INITGUID
#define CONST_VTABLE
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <dwrite.h>
#include "trial_font.h"

#define WIDTH 384
#define ROW_HEIGHT 64
#define HEIGHT 128
typedef HRESULT (WINAPI *factory_fn)(DWRITE_FACTORY_TYPE,REFIID,IUnknown**);
static unsigned checks, failures, paints, callback_runs, callback_glyphs, missing_glyphs, wrong_faces;
static HANDLE output;
static int output_ok=1;
static char buffer[1024];
static unsigned used;
static void * volatile anchor=&checks;
static HDC read_dc;
static HBITMAP read_bitmap;
static HGDIOBJ original_bitmap;
static unsigned *pixels;
static unsigned char face_key[1024];
static UINT32 face_key_size;
static void zero(void *p,SIZE_T n) { unsigned char *q=p;while(n--)*q++=0; }
static int equal(const void *a,const void *b,SIZE_T n) { const unsigned char *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1; }
static int wide_equal(const WCHAR *a,const WCHAR *b) { while(*a&&*a==*b){++a;++b;}return *a==*b; }
static void text(const char *s) { while(*s){DWORD n=0;char c=*s++;if(used==sizeof buffer){output_ok=0;used=0;}buffer[used++]=c;if(c=='\n'){if(!WriteFile(output,buffer,used,&n,0)||n!=used)output_ok=0;used=0;}} }
static void number(unsigned n) { char b[12];unsigned i=0,j;do{b[i++]=(char)('0'+n%10);n/=10;}while(n);for(j=0;j<i/2;++j){char c=b[j];b[j]=b[i-1-j];b[i-1-j]=c;}b[i]=0;text(b); }
static void hex(unsigned n) { char b[9];unsigned i;for(i=0;i<8;++i)b[i]="0123456789abcdef"[(n>>((7-i)*4))&15];b[8]=0;text(b); }
static void check(int ok,const char *name) { ++checks;if(!ok)++failures;text(ok?"DW64 PASS ":"DW64 FAIL ");text(name);text("\r\n"); }
static int result(HRESULT hr,const char *name) { text("DW64 HR ");text(name);text(" ");hex((unsigned)hr);text("\r\n");check(SUCCEEDED(hr),name);return SUCCEEDED(hr); }
static ULONG increment(volatile LONG *p) { return (ULONG)__atomic_add_fetch(p,1,__ATOMIC_SEQ_CST); }
static ULONG decrement(volatile LONG *p) { return (ULONG)__atomic_sub_fetch(p,1,__ATOMIC_SEQ_CST); }

typedef struct Enumerator { IDWriteFontFileEnumerator iface;volatile LONG refs;IDWriteFontFile *file;unsigned step; } Enumerator;
typedef struct Loader { IDWriteFontCollectionLoader iface;volatile LONG refs;IDWriteFontFile *file;IDWriteFactory *factory;unsigned enumerators,released,live; } Loader;
static Loader loader;
static ULONG STDMETHODCALLTYPE enum_add(IDWriteFontFileEnumerator *p) { return increment(&((Enumerator*)p)->refs); }
static ULONG STDMETHODCALLTYPE enum_release(IDWriteFontFileEnumerator *p) { Enumerator *e=(Enumerator*)p;ULONG n=decrement(&e->refs);if(!n){IDWriteFontFile_Release(e->file);--loader.live;++loader.released;check(HeapFree(GetProcessHeap(),0,e),"release_actual_enumerator_allocation");}return n; }
static HRESULT STDMETHODCALLTYPE enum_query(IDWriteFontFileEnumerator *p,REFIID id,void **out) { if(!out)return E_POINTER;*out=0;if(equal(id,&IID_IUnknown,sizeof *id)||equal(id,&IID_IDWriteFontFileEnumerator,sizeof *id)){*out=p;enum_add(p);return S_OK;}return E_NOINTERFACE; }
static HRESULT STDMETHODCALLTYPE enum_move(IDWriteFontFileEnumerator *p,BOOL *has) { Enumerator *e=(Enumerator*)p;if(!has)return E_POINTER;*has=e->step++==0;return S_OK; }
static HRESULT STDMETHODCALLTYPE enum_file(IDWriteFontFileEnumerator *p,IDWriteFontFile **out) { Enumerator *e=(Enumerator*)p;if(!out)return E_POINTER;*out=0;if(e->step!=1)return E_FAIL;IDWriteFontFile_AddRef(e->file);*out=e->file;return S_OK; }
static const IDWriteFontFileEnumeratorVtbl enum_vtable={enum_query,enum_add,enum_release,enum_move,enum_file};
static ULONG STDMETHODCALLTYPE loader_add(IDWriteFontCollectionLoader *p) { return increment(&((Loader*)p)->refs); }
static ULONG STDMETHODCALLTYPE loader_release(IDWriteFontCollectionLoader *p) { return decrement(&((Loader*)p)->refs); }
static HRESULT STDMETHODCALLTYPE loader_query(IDWriteFontCollectionLoader *p,REFIID id,void **out) { if(!out)return E_POINTER;*out=0;if(equal(id,&IID_IUnknown,sizeof *id)||equal(id,&IID_IDWriteFontCollectionLoader,sizeof *id)){*out=p;loader_add(p);return S_OK;}return E_NOINTERFACE; }
static HRESULT STDMETHODCALLTYPE loader_enum(IDWriteFontCollectionLoader *p,IDWriteFactory *factory,const void *key,UINT32 n,IDWriteFontFileEnumerator **out) {
    Enumerator *e;Loader *l=(Loader*)p;if(!out)return E_POINTER;*out=0;
    check(factory==l->factory&&n==4&&key&&equal(key,"CJK1",4),"private_loader_factory_and_key_binding");
    if(factory!=l->factory||n!=4||!key||!equal(key,"CJK1",4))return E_INVALIDARG;
    e=HeapAlloc(GetProcessHeap(),0,sizeof *e);if(!e)return E_OUTOFMEMORY;
    zero(e,sizeof *e);e->iface.lpVtbl=&enum_vtable;e->refs=1;e->file=l->file;IDWriteFontFile_AddRef(e->file);++l->enumerators;++l->live;*out=&e->iface;return S_OK;
}
static const IDWriteFontCollectionLoaderVtbl loader_vtable={loader_query,loader_add,loader_release,loader_enum};

static int same_face_file(IDWriteFontFace *face) {
    IDWriteFontFile *file=0;UINT32 n=1,size=0;const void *key=0;int ok=0;
    if(SUCCEEDED(IDWriteFontFace_GetFiles(face,&n,&file))&&n==1&&file){
        if(SUCCEEDED(IDWriteFontFile_GetReferenceKey(file,&key,&size))&&size==face_key_size&&key)ok=equal(key,face_key,size);
        IDWriteFontFile_Release(file);
    }
    return ok;
}
typedef struct Renderer { IDWriteTextRenderer iface;volatile LONG refs;IDWriteBitmapRenderTarget *target;IDWriteRenderingParams *params;const WCHAR *chars;const UINT16 *expected;UINT32 count,seen,shape_errors,row; } Renderer;
static ULONG STDMETHODCALLTYPE render_add(IDWriteTextRenderer *p) { return increment(&((Renderer*)p)->refs); }
static ULONG STDMETHODCALLTYPE render_release(IDWriteTextRenderer *p) { return decrement(&((Renderer*)p)->refs); }
static HRESULT STDMETHODCALLTYPE render_query(IDWriteTextRenderer *p,REFIID id,void **out) { if(!out)return E_POINTER;*out=0;if(equal(id,&IID_IUnknown,sizeof *id)||equal(id,&IID_IDWriteTextRenderer,sizeof *id)||equal(id,&IID_IDWritePixelSnapping,sizeof *id)){*out=p;render_add(p);return S_OK;}return E_NOINTERFACE; }
static HRESULT STDMETHODCALLTYPE render_snapping(IDWriteTextRenderer *p,void *ctx,BOOL *disabled) { (void)p;(void)ctx;if(!disabled)return E_POINTER;*disabled=FALSE;return S_OK; }
static HRESULT STDMETHODCALLTYPE render_transform(IDWriteTextRenderer *p,void *ctx,DWRITE_MATRIX *m) { (void)p;(void)ctx;if(!m)return E_POINTER;zero(m,sizeof *m);m->m11=m->m22=1.0f;return S_OK; }
static HRESULT STDMETHODCALLTYPE render_dip(IDWriteTextRenderer *p,void *ctx,FLOAT *dip) { (void)p;(void)ctx;if(!dip)return E_POINTER;*dip=1.0f;return S_OK; }
static void render_skipped(Renderer *r,const char *reason) {
    text("DW64 DRAW SKIPPED row=");number(r->row);text(" reason=");text(reason);
    text(" errors=");number(r->shape_errors);text("\r\n");
}
static HRESULT STDMETHODCALLTYPE render_glyphs(IDWriteTextRenderer *p,void *ctx,FLOAT x,FLOAT y,DWRITE_MEASURING_MODE mode,const DWRITE_GLYPH_RUN *run,const DWRITE_GLYPH_RUN_DESCRIPTION *desc,IUnknown *effect) {
    Renderer *r=(Renderer*)p;UINT32 i;RECT bounds;HRESULT hr;(void)ctx;(void)effect;
    if(!run||!run->fontFace||!run->glyphIndices||!run->glyphCount||run->glyphCount>64){render_skipped(r,"invalid-run");return E_INVALIDARG;}
    ++callback_runs;callback_glyphs+=run->glyphCount;if(!same_face_file(run->fontFace))++wrong_faces;
    for(i=0;i<run->glyphCount;++i)if(!run->glyphIndices[i])++missing_glyphs;
    if(!desc||!desc->string||!desc->clusterMap||desc->stringLength!=run->glyphCount||desc->textPosition>r->count||desc->stringLength>r->count-desc->textPosition||run->isSideways||(run->bidiLevel&1)){
        ++r->shape_errors;render_skipped(r,"invalid-description");return E_FAIL;
    }
    for(i=0;i<run->glyphCount;++i){
        UINT32 position=desc->textPosition+i,bit=1u<<position,mask=0;
        /* Diagnostic bits preserve the existing one-error-per-position rule. */
        if(r->seen&bit)mask|=1u;
        if(desc->clusterMap[i]!=i)mask|=2u;
        if(desc->string[i]!=r->chars[position])mask|=4u;
        if(run->glyphIndices[i]!=r->expected[position])mask|=8u;
        if(mask){
            ++r->shape_errors;
            text("DW64 MISMATCH row=");number(r->row);text(" position=");number(position);
            text(" local=");number(i);text(" text_position=");number(desc->textPosition);
            text(" mask=");hex(mask);text(" expected_utf16=");hex(r->chars[position]);
            text(" actual_utf16=");hex(desc->string[i]);text(" expected_glyph=");number(r->expected[position]);
            text(" actual_glyph=");number(run->glyphIndices[i]);text(" expected_cluster=");number(i);
            text(" actual_cluster=");number(desc->clusterMap[i]);text(" seen=");hex(r->seen);
            text(" bit=");hex(bit);text("\r\n");
        }
        r->seen|=bit;
    }
    check(!r->shape_errors,"layout_callback_exact_private_cmap_utf16_and_cluster_order");
    if(r->shape_errors){render_skipped(r,"shape-errors");return E_FAIL;}
    text("DW64 DRAW CALL row=");number(r->row);text(" text_position=");number(desc->textPosition);
    text(" string_length=");number(desc->stringLength);text(" glyphs=");number(run->glyphCount);text("\r\n");
    hr=IDWriteBitmapRenderTarget_DrawGlyphRun(r->target,x,y,mode,run,r->params,RGB(15,35,65),&bounds);
    text("DW64 DRAW RETURN row=");number(r->row);text(" hr=");hex((unsigned)hr);text("\r\n");
    return hr;
}
static HRESULT STDMETHODCALLTYPE render_underline(IDWriteTextRenderer *p,void *ctx,FLOAT x,FLOAT y,const DWRITE_UNDERLINE *u,IUnknown *effect) { (void)p;(void)ctx;(void)x;(void)y;(void)u;(void)effect;return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE render_strike(IDWriteTextRenderer *p,void *ctx,FLOAT x,FLOAT y,const DWRITE_STRIKETHROUGH *u,IUnknown *effect) { (void)p;(void)ctx;(void)x;(void)y;(void)u;(void)effect;return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE render_inline(IDWriteTextRenderer *p,void *ctx,FLOAT x,FLOAT y,IDWriteInlineObject *obj,BOOL side,BOOL rtl,IUnknown *effect) { (void)p;(void)ctx;(void)x;(void)y;(void)obj;(void)side;(void)rtl;(void)effect;return E_NOTIMPL; }
static const IDWriteTextRendererVtbl renderer_vtable={render_query,render_add,render_release,render_snapping,render_transform,render_dip,render_glyphs,render_underline,render_strike,render_inline};

static IDWriteFontFace *open_face(IDWriteFactory *factory,const WCHAR *path,IDWriteFontFile **owner,const char *name) {
    IDWriteFontFile *file=0;IDWriteFontFace *face=0;BOOL supported=FALSE;DWRITE_FONT_FILE_TYPE file_type;DWRITE_FONT_FACE_TYPE face_type;UINT32 count=0;
    if(!result(IDWriteFactory_CreateFontFileReference(factory,path,0,&file),name)||!file)return 0;
    if(result(IDWriteFontFile_Analyze(file,&supported,&file_type,&face_type,&count),"analyze_actual_font")&&supported&&count==1){
        check(1,"single_supported_real_font_face");result(IDWriteFactory_CreateFontFace(factory,face_type,1,&file,0,DWRITE_FONT_SIMULATIONS_NONE,&face),"create_actual_font_face");
    }else check(0,"single_supported_real_font_face");
    if(owner&&face)*owner=file;else IDWriteFontFile_Release(file);
    return face;
}
static void baseline_trial(IDWriteFactory *factory) {
    unsigned i,j;IDWriteFontCollection *collection=0;
    if(result(IDWriteFactory_GetSystemFontCollection(factory,&collection,FALSE),"system_font_collection")&&collection){
        UINT32 index=0;BOOL found=FALSE;check(IDWriteFontCollection_GetFontFamilyCount(collection)>0,"system_collection_has_families");
        check(SUCCEEDED(IDWriteFontCollection_FindFamilyName(collection,L"Noto Sans",&index,&found))&&found,"system_noto_sans_family");
        IDWriteFontCollection_Release(collection);
    }
    for(i=0;i<BASELINE_COUNT;++i){
        IDWriteFontFace *face=open_face(factory,baseline_paths[i],0,"baseline_font_file_reference");UINT16 glyphs[9];DWRITE_GLYPH_METRICS metrics[2];DWRITE_FONT_METRICS font_metrics;
        if(!face)continue;
        zero(glyphs,sizeof glyphs);zero(metrics,sizeof metrics);zero(&font_metrics,sizeof font_metrics);
        check(SUCCEEDED(IDWriteFontFace_GetGlyphIndices(face,expected_codepoints,9,glyphs)),"baseline_glyph_indices");
        check(glyphs[0]==baseline_latin_glyphs[i][0]&&glyphs[1]==baseline_latin_glyphs[i][1],"baseline_latin_cmap_identity");
        for(j=2;j<9;++j)if(glyphs[j])break;
        check(j==9,"baseline_hangul_absent_as_independently_parsed");
        IDWriteFontFace_GetMetrics(face,&font_metrics);check(font_metrics.designUnitsPerEm==baseline_units[i],"baseline_design_units_identity");
        check(SUCCEEDED(IDWriteFontFace_GetDesignGlyphMetrics(face,glyphs,2,metrics,FALSE))&&metrics[0].advanceWidth==baseline_advances[i][0]&&metrics[1].advanceWidth==baseline_advances[i][1],"baseline_latin_design_advances");
        check(IDWriteFontFace_GetGlyphCount(face)==baseline_glyph_counts[i],"baseline_real_face_outlives_file_reference");
        IDWriteFontFace_Release(face);
    }
}
static void alpha_trial(IDWriteFactory *factory,IDWriteFontFace *face,const UINT16 *glyphs,const DWRITE_GLYPH_METRICS *metrics) {
    DWRITE_GLYPH_RUN run;DWRITE_GLYPH_OFFSET offsets[2];FLOAT advances[2];IDWriteGlyphRunAnalysis *analysis=0;RECT bounds;unsigned char *alpha=0,*allocation=0;unsigned n=0,i,ink=0;
    zero(&run,sizeof run);zero(offsets,sizeof offsets);run.fontFace=face;run.fontEmSize=32.0f;run.glyphCount=2;run.glyphIndices=glyphs+3;run.glyphAdvances=advances;run.glyphOffsets=offsets;
    advances[0]=metrics[3].advanceWidth*32.0f/EXPECTED_UNITS;advances[1]=metrics[4].advanceWidth*32.0f/EXPECTED_UNITS;
    if(!result(IDWriteFactory_CreateGlyphRunAnalysis(factory,&run,1.0f,0,DWRITE_RENDERING_MODE_NATURAL,DWRITE_MEASURING_MODE_NATURAL,8.0f,40.0f,&analysis),"actual_korean_glyph_run_analysis")||!analysis)goto done;
    zero(&bounds,sizeof bounds);if(!result(IDWriteGlyphRunAnalysis_GetAlphaTextureBounds(analysis,DWRITE_TEXTURE_CLEARTYPE_3x1,&bounds),"korean_alpha_texture_bounds"))goto done;
    check(bounds.right>bounds.left&&bounds.bottom>bounds.top&&bounds.left>=0&&bounds.top>=0&&bounds.right<=WIDTH&&bounds.bottom<=ROW_HEIGHT,"bounded_korean_ink_bounds");
    if(bounds.right<=bounds.left||bounds.bottom<=bounds.top||bounds.right-bounds.left>WIDTH||bounds.bottom-bounds.top>ROW_HEIGHT)goto done;
    n=(unsigned)(bounds.right-bounds.left)*(unsigned)(bounds.bottom-bounds.top)*3;allocation=HeapAlloc(GetProcessHeap(),0,n+32);check(allocation!=0,"owned_bounded_alpha_buffer");if(!allocation)goto done;alpha=allocation+16;zero(alpha,n);for(i=0;i<16;++i)allocation[i]=allocation[n+16+i]=0xa5;
    if(result(IDWriteGlyphRunAnalysis_CreateAlphaTexture(analysis,DWRITE_TEXTURE_CLEARTYPE_3x1,&bounds,alpha,n),"actual_korean_alpha_texture")){for(i=0;i<n;++i)if(alpha[i])++ink;check(ink>100,"actual_korean_alpha_coverage");text("DW64 ALPHA nonzero=");number(ink);text(" bytes=");number(n);text("\r\n");}
    for(i=0;i<16;++i)if(allocation[i]!=0xa5||allocation[n+16+i]!=0xa5)break;
    check(i==16,"korean_alpha_buffer_guards_unchanged");
done:
    if(allocation)check(HeapFree(GetProcessHeap(),0,allocation),"release_owned_alpha_buffer");
    if(analysis)IDWriteGlyphRunAnalysis_Release(analysis);
}
static unsigned pixel_hash(void) { unsigned h=2166136261u,i;for(i=0;i<WIDTH*HEIGHT;++i){unsigned p=pixels[i];h=(h^((p>>16)&255))*16777619u;h=(h^((p>>8)&255))*16777619u;h=(h^(p&255))*16777619u;}return h; }
static int readback_setup(void) {
    BITMAPINFO bi;zero(&bi,sizeof bi);bi.bmiHeader.biSize=sizeof bi.bmiHeader;bi.bmiHeader.biWidth=WIDTH;bi.bmiHeader.biHeight=-HEIGHT;bi.bmiHeader.biPlanes=1;bi.bmiHeader.biBitCount=32;bi.bmiHeader.biCompression=BI_RGB;
    read_dc=CreateCompatibleDC(0);check(read_dc!=0,"create_real_readback_dc");if(!read_dc)return 0;
    read_bitmap=CreateDIBSection(read_dc,&bi,DIB_RGB_COLORS,(void**)&pixels,0,0);check(read_bitmap&&pixels,"create_owned_readback_dib");if(!read_bitmap||!pixels)return 0;
    original_bitmap=SelectObject(read_dc,read_bitmap);check(original_bitmap&&original_bitmap!=HGDI_ERROR,"select_readback_dib");return original_bitmap&&original_bitmap!=HGDI_ERROR;
}
static void layout_trial(IDWriteFactory *factory,IDWriteFontCollection *collection) {
    IDWriteTextFormat *format=0;IDWriteGdiInterop *interop=0;IDWriteRenderingParams *params=0;IDWriteBitmapRenderTarget *target=0;Renderer renderer;unsigned row,i,before,ink[2]={0,0};int renderer_live=0;
    static const WCHAR latin[]={65,66};static const WCHAR korean[]={0xd55c,0xae00,32,0xd604,0xb300,32,0xbaa8,0xb358};
    if(!readback_setup())goto done;
    if(!result(IDWriteFactory_CreateTextFormat(factory,L"Noto Sans CJK KR",collection,DWRITE_FONT_WEIGHT_NORMAL,DWRITE_FONT_STYLE_NORMAL,DWRITE_FONT_STRETCH_NORMAL,32.0f,L"ko-kr",&format),"private_collection_text_format")||!format)goto done;
    if(!result(IDWriteFactory_GetGdiInterop(factory,&interop),"actual_gdi_interop")||!interop)goto done;
    if(!result(IDWriteFactory_CreateRenderingParams(factory,&params),"actual_rendering_params")||!params)goto done;
    if(!result(IDWriteGdiInterop_CreateBitmapRenderTarget(interop,0,WIDTH,ROW_HEIGHT,&target),"actual_bitmap_render_target")||!target)goto done;
    zero(&renderer,sizeof renderer);renderer.iface.lpVtbl=&renderer_vtable;renderer.refs=1;renderer.target=target;renderer.params=params;renderer_live=1;
    for(row=0;row<2;++row){
        IDWriteTextLayout *layout=0;DWRITE_TEXT_METRICS metrics;HDC dc=IDWriteBitmapRenderTarget_GetMemoryDC(target);const WCHAR *chars=row?korean:latin;unsigned count=row?8:2;before=callback_glyphs;
        renderer.chars=chars;renderer.expected=row?expected_korean_layout:expected_latin_layout;renderer.count=count;renderer.seen=renderer.shape_errors=0;renderer.row=row;
        check(dc!=0,"actual_dwrite_memory_dc");if(!dc)break;
        check(PatBlt(dc,0,0,WIDTH,ROW_HEIGHT,WHITENESS)&&GdiFlush(),"clear_real_dwrite_target");
        if(!result(IDWriteFactory_CreateTextLayout(factory,chars,count,format,WIDTH-16.0f,ROW_HEIGHT,&layout),row?"create_korean_text_layout":"create_latin_text_layout")||!layout)continue;
        /* Layout owns its format/collection while drawing; keep the original
         * format until both lines finish, then release every owned reference. */
        zero(&metrics,sizeof metrics);check(SUCCEEDED(IDWriteTextLayout_GetMetrics(layout,&metrics))&&metrics.lineCount==1&&metrics.width>10.0f&&metrics.width<WIDTH-16.0f&&metrics.height>20.0f&&metrics.height<=ROW_HEIGHT,"bounded_real_text_layout_metrics");
        result(IDWriteTextLayout_Draw(layout,0,&renderer.iface,8.0f,0.0f),row?"actual_korean_layout_draw":"actual_latin_layout_draw");
        check(callback_glyphs>before,row?"korean_renderer_received_real_glyphs":"latin_renderer_received_real_glyphs");
        check(renderer.seen==((1u<<count)-1)&&!renderer.shape_errors,row?"all_korean_layout_positions_match_independent_cmap":"all_latin_layout_positions_match_independent_cmap");
        text("DW64 SHAPE row=");number(row);text(" covered=");number(renderer.seen);text(" expected=");number((1u<<count)-1);text(" errors=");number(renderer.shape_errors);text("\r\n");
        check(BitBlt(read_dc,0,row*ROW_HEIGHT,WIDTH,ROW_HEIGHT,dc,0,0,SRCCOPY)&&GdiFlush(),"copy_real_dwrite_pixels_to_owned_dib");
        check(IDWriteTextLayout_Release(layout)==0,"release_final_layout_reference");
        for(i=row*WIDTH*ROW_HEIGHT;i<(row+1)*WIDTH*ROW_HEIGHT;++i)if((pixels[i]&0xffffff)!=0xffffff)++ink[row];
        check(ink[row]>(row?150u:50u),row?"actual_korean_dib_ink_coverage":"actual_latin_dib_ink_coverage");
    }
    check(callback_runs>=2&&callback_glyphs>=10&&!missing_glyphs&&!wrong_faces,"all_layout_glyphs_use_exact_private_face_without_missing_glyphs");
    check(renderer.refs==1,"renderer_balanced_com_references");
    { unsigned mismatch=0,x,y;for(y=0;y<HEIGHT;y+=8)for(x=0;x<WIDTH;x+=8){unsigned p=pixels[y*WIDTH+x];if(GetPixel(read_dc,x,y)!=RGB((p>>16)&255,(p>>8)&255,p&255))++mismatch;}check(!mismatch,"independent_getpixel_matches_all_readback_samples"); }
    text("DW64 RASTER latin_ink=");number(ink[0]);text(" korean_ink=");number(ink[1]);text(" runs=");number(callback_runs);text(" glyphs=");number(callback_glyphs);text(" missing=");number(missing_glyphs);text(" wrong_faces=");number(wrong_faces);text(" hash=");hex(pixel_hash());text("\r\n");
done:
    if(renderer_live)check(render_release(&renderer.iface)==0,"release_renderer_owner_reference");
    if(target)check(IDWriteBitmapRenderTarget_Release(target)==0,"release_final_bitmap_target_reference");
    if(params)check(IDWriteRenderingParams_Release(params)==0,"release_final_rendering_params_reference");
    if(interop)IDWriteGdiInterop_Release(interop);
    if(format)check(IDWriteTextFormat_Release(format)==0,"release_final_text_format_reference");
}
static LRESULT CALLBACK window_proc(HWND window,UINT message,WPARAM wp,LPARAM lp) {
    if(message==WM_PAINT){PAINTSTRUCT ps;HDC dc;BOOL end,blit;zero(&ps,sizeof ps);dc=BeginPaint(window,&ps);if(!dc){check(0,"paint_actual_directwrite_readback");return 0;}blit=BitBlt(dc,20,35,WIDTH,HEIGHT,read_dc,0,0,SRCCOPY);check(blit&&GdiFlush(),"paint_actual_directwrite_readback");end=EndPaint(window,&ps);check(end,"end_visible_paint");++paints;return 0;}
    return DefWindowProcW(window,message,wp,lp);
}
static void visible_trial(void) {
    WNDCLASSEXW wc;HINSTANCE instance=GetModuleHandleW(0);HWND window=0;POINT point={20,35};unsigned x,y,mismatch=0;HDC dc;
    if(!pixels||!read_dc)return;
    zero(&wc,sizeof wc);wc.cbSize=sizeof wc;wc.lpfnWndProc=window_proc;wc.hInstance=instance;wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);wc.lpszClassName=L"DWriteProbe64";
    check(RegisterClassExW(&wc)!=0,"register_visible_class");
    window=CreateWindowExW(0,wc.lpszClassName,L"DirectWrite: Latin / Korean private face",WS_OVERLAPPEDWINDOW|WS_VISIBLE,90,70,440,230,0,0,instance,0);check(window!=0,"create_visible_window");if(!window)goto done;
    check(UpdateWindow(window)&&paints>0,"dispatch_real_visible_paint");
    check(ClientToScreen(window,&point)&&point.x>=0&&point.y>=0&&point.x+WIDTH<=GetSystemMetrics(SM_CXSCREEN)&&point.y+HEIGHT<=GetSystemMetrics(SM_CYSCREEN),"bounded_real_client_screen_origin");
    dc=GetDC(window);check(dc!=0,"read_actual_visible_window_dc");if(dc){for(y=0;y<HEIGHT;++y)for(x=0;x<WIDTH;++x){unsigned p=pixels[y*WIDTH+x];if(GetPixel(dc,x+20,y+35)!=RGB((p>>16)&255,(p>>8)&255,p&255))++mismatch;}check(!mismatch,"all_49152_visible_pixels_match_real_directwrite_dib");check(ReleaseDC(window,dc)!=0,"release_visible_window_dc");}
    text("DW64 GUI READY ");text(TRIAL_NONCE);text(" left=");number((unsigned)point.x);text(" top=");number((unsigned)point.y);text(" width=");number(WIDTH);text(" height=");number(HEIGHT);text(" hash=");hex(pixel_hash());text("\r\n");Sleep(4000);
    check(DestroyWindow(window)&&!IsWindow(window),"destroy_visible_window");
done:
    check(UnregisterClassW(wc.lpszClassName,instance)!=0,"unregister_visible_class");
}
void WINAPI DWriteProbeEntry(void) {
    HMODULE module=0;factory_fn create_factory=0;IDWriteFactory *factory=0;IUnknown *identity=0;IDWriteFontFace *face=0;IDWriteFontFile *file=0;IDWriteFontCollection *collection=0;IDWriteFontFamily *family=0;IDWriteLocalizedStrings *names=0;UINT16 glyphs[9];DWRITE_GLYPH_METRICS metrics[9];DWRITE_FONT_METRICS fm;unsigned i;int registered=0;
    output=GetStdHandle(STD_OUTPUT_HANDLE);text("DW64 BEGIN ");text(TRIAL_NONCE);text("\r\n");check(anchor==&checks,"relocated_probe_anchor");
    module=LoadLibraryW(L"C:\\SHZ\\SYS64\\dwrite.dll");check(module!=0,"load_actual_archive_dwrite");if(!module)goto done;
    { union {FARPROC raw;factory_fn typed;} fn;fn.raw=GetProcAddress(module,"DWriteCreateFactory");create_factory=fn.typed;check(create_factory!=0,"actual_dwrite_create_factory_export"); }if(!create_factory)goto done;
    if(!result(create_factory(DWRITE_FACTORY_TYPE_ISOLATED,&IID_IDWriteFactory,(IUnknown**)&factory),"real_isolated_dwrite_factory")||!factory)goto done;
    check(SUCCEEDED(IDWriteFactory_QueryInterface(factory,&IID_IUnknown,(void**)&identity))&&identity==(IUnknown*)factory,"factory_iunknown_identity");if(identity){IUnknown_Release(identity);identity=0;}
    { ULONG a=IDWriteFactory_AddRef(factory),b=IDWriteFactory_Release(factory);check(a==b+1&&b>=1,"factory_balanced_addref_release"); }
    baseline_trial(factory);
    face=open_face(factory,L"D:\\dwriteprobe\\CJK.otf",&file,"private_cjk_font_file_reference");if(!face||!file)goto done;
    { const void *key=0;UINT32 n=0;if(SUCCEEDED(IDWriteFontFile_GetReferenceKey(file,&key,&n))&&key&&n<=sizeof face_key){face_key_size=n;for(i=0;i<n;++i)face_key[i]=((const unsigned char*)key)[i];}check(face_key_size>0,"bound_actual_private_font_reference_key"); }
    zero(glyphs,sizeof glyphs);zero(metrics,sizeof metrics);zero(&fm,sizeof fm);
    check(SUCCEEDED(IDWriteFontFace_GetGlyphIndices(face,expected_codepoints,9,glyphs)),"private_korean_latin_glyph_indices");
    check(equal(glyphs,expected_glyphs,sizeof glyphs),"all_nine_glyph_ids_match_independent_publisher_cmap");
    IDWriteFontFace_GetMetrics(face,&fm);check(fm.designUnitsPerEm==EXPECTED_UNITS&&IDWriteFontFace_GetGlyphCount(face)==EXPECTED_GLYPHS,"private_face_units_and_glyph_count_identity");
    check(SUCCEEDED(IDWriteFontFace_GetDesignGlyphMetrics(face,glyphs,9,metrics,FALSE)),"private_real_design_glyph_metrics");
    for(i=0;i<9;++i)if(metrics[i].advanceWidth!=expected_advances[i]||metrics[i].leftSideBearing!=expected_bearings[i])break;
    check(i==9,"all_nine_advance_and_bearing_metrics_match_independent_hmtx");
    alpha_trial(factory,face,glyphs,metrics);
    zero(&loader,sizeof loader);loader.iface.lpVtbl=&loader_vtable;loader.refs=1;loader.file=file;loader.factory=factory;IDWriteFontFile_AddRef(file);
    if(!result(IDWriteFactory_RegisterFontCollectionLoader(factory,&loader.iface),"register_private_collection_loader"))goto loader_done;
    registered=1;
    if(!result(IDWriteFactory_CreateCustomFontCollection(factory,&loader.iface,"CJK1",4,&collection),"actual_private_custom_font_collection")||!collection)goto loader_done;
    check(IDWriteFontCollection_GetFontFamilyCount(collection)==1&&loader.enumerators>=1&&loader.live==0,"private_collection_enumeration_ownership");
    { UINT32 index=0;BOOL found=FALSE;WCHAR name[128];
      if(SUCCEEDED(IDWriteFontCollection_FindFamilyName(collection,L"Noto Sans CJK KR",&index,&found))&&found&&SUCCEEDED(IDWriteFontCollection_GetFontFamily(collection,index,&family))&&family&&SUCCEEDED(IDWriteFontFamily_GetFamilyNames(family,&names))&&names){zero(name,sizeof name);found=FALSE;index=0;check(SUCCEEDED(IDWriteLocalizedStrings_FindLocaleName(names,L"en-us",&index,&found))&&found&&SUCCEEDED(IDWriteLocalizedStrings_GetString(names,index,name,128))&&wide_equal(name,L"Noto Sans CJK KR"),"actual_private_family_name_identity");}else check(0,"actual_private_family_name_identity"); }
    IDWriteFontFile_Release(file);file=0;check(same_face_file(face),"real_private_face_outlives_original_file_reference");
    layout_trial(factory,collection);visible_trial();
loader_done:
    if(names){IDWriteLocalizedStrings_Release(names);names=0;}if(family){IDWriteFontFamily_Release(family);family=0;}if(collection){IDWriteFontCollection_Release(collection);collection=0;}
    if(registered)check(SUCCEEDED(IDWriteFactory_UnregisterFontCollectionLoader(factory,&loader.iface)),"unregister_private_collection_loader");
    if(loader.file){IDWriteFontFile_Release(loader.file);loader.file=0;}check(loader.live==0&&loader.enumerators==loader.released&&loader.refs==1,"all_private_loader_and_enumerator_refs_released");
    check(loader_release(&loader.iface)==0,"release_final_private_loader_reference");
done:
    if(original_bitmap&&original_bitmap!=HGDI_ERROR)check(SelectObject(read_dc,original_bitmap)==read_bitmap,"restore_original_readback_bitmap");
    if(read_bitmap)check(DeleteObject(read_bitmap)!=0,"delete_owned_readback_dib");
    if(read_dc)check(DeleteDC(read_dc)!=0,"delete_owned_readback_dc");
    if(names)IDWriteLocalizedStrings_Release(names);
    if(family)IDWriteFontFamily_Release(family);
    if(collection)IDWriteFontCollection_Release(collection);
    if(file)IDWriteFontFile_Release(file);
    if(face)IDWriteFontFace_Release(face);
    if(identity)IUnknown_Release(identity);
    if(factory)check(IDWriteFactory_Release(factory)==0,"release_final_isolated_factory_reference");
    if(module)check(FreeLibrary(module)!=0,"unload_actual_dwrite");
    check(anchor==&checks,"final_relocated_probe_anchor");check(output_ok,"complete_console_writes");
    text("DW64 COUNTS checks=");number(checks);text(" failures=");number(failures);text(" paints=");number(paints);text("\r\n");text(failures?"DW64 FINAL FAIL ":"DW64 FINAL PASS ");text(TRIAL_NONCE);text("\r\n");ExitProcess(failures||!output_ok?1:0);
}
