/* SPDX-License-Identifier: GPL-2.0-only
 * gdi32: enhanced metafiles, recorded as raster pictures.
 *
 * Recording. CreateEnhMetaFile returns a metafile DC (GetObjectType: OBJ_ENHMETADC) that draws, like a memory DC, into a
 * white canvas the size of the reference device (grown to the picture frame, at most 8192x8192 pixels). Everything drawn
 * between two GdiComment calls (and before CloseEnhMetaFile) becomes ONE EMR_STRETCHDIBITS record holding the bounding box of
 * the pixels that changed, so the order of pictures and comments is kept. Undrawn pixels inside such a box are recorded
 * as they are on the canvas (white unless drawn earlier): the records are opaque rectangles, not vector drawing. The file
 * is a standard EMF (EMR_HEADER with the description, the records, EMR_EOF) that other readers can play; with a file name
 * it is also written to that file by CloseEnhMetaFile.
 *
 * Playback. PlayEnhMetaFile/EnumEnhMetaFile map the picture frame onto the given rectangle (scale and offset computed as
 * Windows does from rclFrame, szlDevice and szlMillimeters), saving and restoring the target DC around it.
 * PlayEnhMetaFileRecord plays EMR_HEADER, EMR_EOF, EMR_GDICOMMENT, EMR_STRETCHDIBITS, EMR_SETDIBITSTODEVICE and the simple
 * state records (SAVEDC, RESTOREDC, SETBKMODE, SETBKCOLOR, SETTEXTCOLOR, SETPOLYFILLMODE, SETROP2, SETSTRETCHBLTMODE,
 * SETTEXTALIGN); any other record (vector drawing, objects, clipping, transforms from metafiles made elsewhere) is not
 * played and makes it return FALSE with ERROR_NOT_SUPPORTED. PlayEnhMetaFile skips such records, as Windows skips records it
 * cannot play.
 */
#include "gdi_internal.h"

#define EMF_MAX_CANVAS 8192

typedef struct emfrec {
    uint8_t *buf; uint32_t size, cap;                               /* the records after the header */
    uint32_t nrec;
    RECT bounds; int has_bounds;                                     /* device pixels the records cover */
    RECT dirty; int has_dirty;                                       /* drawn since the last record */
    RECTL frame; int has_frame;                                      /* .01 mm, as the caller gave it */
    SIZEL dev_px, dev_mm;                                            /* reference device */
    WCHAR *desc; uint32_t desc_chars;                                /* both strings and their NULs */
    WCHAR *file;
    HBITMAP canvas;
} emfrec_t;

typedef struct { uint8_t *data; uint32_t size; } emf_t;

static void *emf_alloc(uint32_t n)
{
    if (n >= 0x10000) return VirtualAlloc(0, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return gdi_alloc(n);
}
static void emf_free(void *p, uint32_t n)
{
    if (!p) return;
    if (n >= 0x10000) VirtualFree(p, 0, MEM_RELEASE); else gdi_free(p);
}

static void *rec_append(emfrec_t *r, uint32_t n)
{
    uint8_t *p;
    if (r->size + n > r->cap) {
        uint32_t nc = r->cap ? r->cap : 4096;
        uint8_t *nb;
        while (nc < r->size + n) nc *= 2;
        nb = emf_alloc(nc);
        if (!nb) return 0;
        if (r->size) memcpy(nb, r->buf, r->size);
        emf_free(r->buf, r->cap);
        r->buf = nb;
        r->cap = nc;
    }
    p = r->buf + r->size;
    memset(p, 0, n);
    r->size += n;
    ++r->nrec;
    return p;
}

static void rect_union(RECT *d, int *has, const RECT *s)
{
    if (!*has) { *d = *s; *has = 1; return; }
    if (s->left < d->left) d->left = s->left;
    if (s->top < d->top) d->top = s->top;
    if (s->right > d->right) d->right = s->right;
    if (s->bottom > d->bottom) d->bottom = s->bottom;
}

void gdi_emf_touch(dc_t *dc, const RECT *dev)
{
    if (!rc_is_empty(dev)) rect_union(&dc->emf->dirty, &dc->emf->has_dirty, dev);
}

/* what was drawn since the last record, as one EMR_STRETCHDIBITS of its bounding box */
static int flush_raster(dc_t *dc)
{
    emfrec_t *r = dc->emf;
    bitmap_t *b = gdi_obj_get((HGDIOBJ)r->canvas, OBJ_BITMAP, 0);
    RECT d, all;
    EMRSTRETCHDIBITS *e;
    BITMAPINFOHEADER *bih;
    uint32_t *px;
    int w, h, y, x;
    if (!r->has_dirty || !b) return 1;
    r->has_dirty = 0;
    all.left = all.top = 0; all.right = b->w; all.bottom = b->h;
    if (!rc_intersect(&d, &r->dirty, &all)) return 1;
    w = d.right - d.left;
    h = d.bottom - d.top;
    e = rec_append(r, (uint32_t)(sizeof *e + sizeof *bih + (size_t)w * h * 4));
    if (!e) return 0;
    e->emr.iType = EMR_STRETCHDIBITS;
    e->emr.nSize = (DWORD)(sizeof *e + sizeof *bih + (size_t)w * h * 4);
    e->rclBounds.left = d.left; e->rclBounds.top = d.top; e->rclBounds.right = d.right - 1; e->rclBounds.bottom = d.bottom - 1;
    e->xDest = d.left; e->yDest = d.top; e->cxDest = w; e->cyDest = h;
    e->xSrc = 0; e->ySrc = 0; e->cxSrc = w; e->cySrc = h;
    e->offBmiSrc = sizeof *e; e->cbBmiSrc = sizeof *bih;
    e->offBitsSrc = (DWORD)(sizeof *e + sizeof *bih); e->cbBitsSrc = (DWORD)((size_t)w * h * 4);
    e->iUsageSrc = DIB_RGB_COLORS;
    e->dwRop = SRCCOPY;
    bih = (BITMAPINFOHEADER *)(e + 1);
    bih->biSize = sizeof *bih;
    bih->biWidth = w;
    bih->biHeight = h;                                               /* bottom-up, the form every EMF reader takes */
    bih->biPlanes = 1;
    bih->biBitCount = 32;
    bih->biCompression = BI_RGB;
    bih->biSizeImage = (DWORD)((size_t)w * h * 4);
    px = (uint32_t *)(bih + 1);
    for (y = 0; y < h; ++y) {
        const uint32_t *src = bm_px(b, d.left, d.bottom - 1 - y);
        for (x = 0; x < w; ++x) px[(size_t)y * w + x] = src[x] & 0xffffff;
    }
    rect_union(&r->bounds, &r->has_bounds, &d);
    return 1;
}

static void rec_free(emfrec_t *r)
{
    emf_free(r->buf, r->cap);
    gdi_free(r->desc);
    gdi_free(r->file);
    gdi_free(r);
}

void gdi_emf_dc_free(dc_t *dc)
{
    emfrec_t *r = dc->emf;                                           /* DeleteDC has already dropped the canvas selection */
    dc->emf = 0;
    if (!r) return;
    DeleteObject(r->canvas);
    rec_free(r);
}

DLLAPI HDC WINAPI CreateEnhMetaFileW(HDC ref, LPCWSTR file, const RECT *frame, LPCWSTR desc)
{
    emfrec_t *r;
    dc_t *dc;
    bitmap_t *b;
    HGDIOBJ h;
    int w, hh;
    size_t i, n;
    if (ref && !gdi_dc_get(ref)) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
    r = gdi_alloc(sizeof *r);
    if (!r) return 0;
    r->dev_px.cx = ref ? GetDeviceCaps(ref, HORZRES) : 1024;
    r->dev_px.cy = ref ? GetDeviceCaps(ref, VERTRES) : 768;
    if (r->dev_px.cx <= 0) r->dev_px.cx = 1;
    if (r->dev_px.cy <= 0) r->dev_px.cy = 1;
    r->dev_mm.cx = r->dev_px.cx * 254 / 960;                          /* 96 dpi */
    r->dev_mm.cy = r->dev_px.cy * 254 / 960;
    if (r->dev_mm.cx <= 0) r->dev_mm.cx = 1;
    if (r->dev_mm.cy <= 0) r->dev_mm.cy = 1;
    w = r->dev_px.cx;
    hh = r->dev_px.cy;
    if (frame) {
        const int fr = (int)((int64_t)frame->right * r->dev_px.cx / ((int64_t)r->dev_mm.cx * 100)) + 1;
        const int fb = (int)((int64_t)frame->bottom * r->dev_px.cy / ((int64_t)r->dev_mm.cy * 100)) + 1;
        r->frame.left = frame->left; r->frame.top = frame->top; r->frame.right = frame->right; r->frame.bottom = frame->bottom;
        r->has_frame = 1;
        if (fr > w) w = fr;
        if (fb > hh) hh = fb;
    }
    if (w > EMF_MAX_CANVAS) w = EMF_MAX_CANVAS;
    if (hh > EMF_MAX_CANVAS) hh = EMF_MAX_CANVAS;
    if (desc) {                                                       /* "application\0title\0\0" */
        for (n = 0; desc[n] || desc[n + 1]; ++n) {}
        n += 2;
        r->desc = gdi_alloc(n * sizeof(WCHAR));
        if (!r->desc) { rec_free(r); return 0; }
        memcpy(r->desc, desc, n * sizeof(WCHAR));
        r->desc_chars = (uint32_t)n;
    }
    if (file) {
        for (n = 0; file[n]; ++n) {}
        r->file = gdi_alloc((n + 1) * sizeof(WCHAR));
        if (!r->file) { rec_free(r); return 0; }
        for (i = 0; i <= n; ++i) r->file[i] = file[i];
    }
    r->canvas = CreateBitmap(w, hh, 1, 32, 0);
    if (!r->canvas) { rec_free(r); return 0; }
    GDI_ENTER();
    b = gdi_obj_get((HGDIOBJ)r->canvas, OBJ_BITMAP, 0);
    if (b && b->bits) memset(b->bits, 0xff, (size_t)b->w * b->h * 4);    /* white paper */
    dc = gdi_alloc(sizeof *dc);
    if (!dc || !b) { GDI_LEAVE(); gdi_free(dc); DeleteObject(r->canvas); rec_free(r); return 0; }
    dc->memdc = 1;
    gdi_dc_defaults(dc);
    dc->hbmp = r->canvas;
    ++b->sel;
    dc->emf = r;
    h = gdi_obj_new(OBJ_ENHMETADC, dc, 0);
    if (!h) { --b->sel; GDI_LEAVE(); gdi_free(dc); DeleteObject(r->canvas); rec_free(r); return 0; }
    GDI_LEAVE();
    return (HDC)h;
}

DLLAPI HDC WINAPI CreateEnhMetaFileA(HDC ref, LPCSTR file, const RECT *frame, LPCSTR desc)
{
    WCHAR fw[MAX_PATH], dw[512];
    size_t i, n = 0;
    if (file) { for (i = 0; file[i] && i + 1 < MAX_PATH; ++i) fw[i] = (unsigned char)file[i]; fw[i] = 0; }
    if (desc) {
        while ((desc[n] || desc[n + 1]) && n + 2 < 512) ++n;
        for (i = 0; i < n; ++i) dw[i] = (unsigned char)desc[i];
        dw[n] = 0; dw[n + 1] = 0;
    }
    return CreateEnhMetaFileW(ref, file ? fw : 0, frame, desc ? dw : 0);
}

DLLAPI BOOL WINAPI GdiComment(HDC hdc, UINT n, const BYTE *data)
{
    dc_t *dc;
    EMRGDICOMMENT *c;
    uint32_t sz;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    if (!dc->emf) RET(TRUE);                                          /* only metafiles keep comments */
    if (n && !data) { SetLastError(ERROR_INVALID_PARAMETER); RET(FALSE); }
    if (!flush_raster(dc)) RET(FALSE);
    sz = (uint32_t)((offsetof(EMRGDICOMMENT, Data) + n + 3) & ~3u);
    c = rec_append(dc->emf, sz);
    if (!c) RET(FALSE);
    c->emr.iType = EMR_GDICOMMENT;
    c->emr.nSize = sz;
    c->cbData = n;
    if (n) memcpy(c->Data, data, n);
    RET(TRUE);
}

static HENHMETAFILE emf_handle(uint8_t *data, uint32_t size)
{
    emf_t *e = gdi_alloc(sizeof *e);
    HGDIOBJ h;
    if (!e) return 0;
    e->data = data;
    e->size = size;
    h = gdi_obj_new(OBJ_ENHMETAFILE, e, 0);
    if (!h) gdi_free(e);
    return (HENHMETAFILE)h;
}

DLLAPI HENHMETAFILE WINAPI CloseEnhMetaFile(HDC hdc)
{
    dc_t *dc;
    emfrec_t *r;
    EMREOF *eof;
    ENHMETAHEADER *hd;
    uint32_t hsize, total;
    uint8_t *data;
    HENHMETAFILE hm;
    GDI_ENTER();
    dc = gdi_dc_get(hdc);
    if (!dc || !dc->emf) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    r = dc->emf;
    if (!flush_raster(dc)) RET(0);
    eof = rec_append(r, sizeof *eof);
    if (!eof) RET(0);
    eof->emr.iType = EMR_EOF;
    eof->emr.nSize = sizeof *eof;
    eof->offPalEntries = sizeof *eof - sizeof(DWORD);
    eof->nSizeLast = sizeof *eof;
    hsize = (uint32_t)((sizeof(ENHMETAHEADER) + r->desc_chars * sizeof(WCHAR) + 3) & ~(size_t)3);
    total = hsize + r->size;
    data = emf_alloc(total);
    if (!data) RET(0);
    memset(data, 0, hsize);
    hd = (ENHMETAHEADER *)data;
    hd->iType = EMR_HEADER;
    hd->nSize = hsize;
    if (r->has_bounds) {
        hd->rclBounds.left = r->bounds.left; hd->rclBounds.top = r->bounds.top;
        hd->rclBounds.right = r->bounds.right - 1; hd->rclBounds.bottom = r->bounds.bottom - 1;
    } else {
        hd->rclBounds.left = hd->rclBounds.top = 0;
        hd->rclBounds.right = hd->rclBounds.bottom = -1;
    }
    if (r->has_frame) hd->rclFrame = r->frame;
    else {                                                            /* the bounds in .01 mm */
        hd->rclFrame.left = (LONG)((int64_t)hd->rclBounds.left * r->dev_mm.cx * 100 / r->dev_px.cx);
        hd->rclFrame.top = (LONG)((int64_t)hd->rclBounds.top * r->dev_mm.cy * 100 / r->dev_px.cy);
        hd->rclFrame.right = (LONG)((int64_t)(hd->rclBounds.right + 1) * r->dev_mm.cx * 100 / r->dev_px.cx);
        hd->rclFrame.bottom = (LONG)((int64_t)(hd->rclBounds.bottom + 1) * r->dev_mm.cy * 100 / r->dev_px.cy);
    }
    hd->dSignature = ENHMETA_SIGNATURE;
    hd->nVersion = 0x10000;
    hd->nBytes = total;
    hd->nRecords = r->nrec + 1;
    hd->nHandles = 1;
    hd->nDescription = r->desc_chars;
    hd->offDescription = r->desc_chars ? sizeof(ENHMETAHEADER) : 0;
    hd->szlDevice = r->dev_px;
    hd->szlMillimeters = r->dev_mm;
    hd->szlMicrometers.cx = r->dev_mm.cx * 1000;
    hd->szlMicrometers.cy = r->dev_mm.cy * 1000;
    if (r->desc_chars) memcpy(data + sizeof(ENHMETAHEADER), r->desc, r->desc_chars * sizeof(WCHAR));
    memcpy(data + hsize, r->buf, r->size);
    if (r->file) {
        HANDLE f = CreateFileW(r->file, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
        DWORD wr = 0;
        const BOOL ok = f != INVALID_HANDLE_VALUE && WriteFile(f, data, total, &wr, 0) && wr == total;
        if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
        if (!ok) { emf_free(data, total); RET(0); }
    }
    hm = emf_handle(data, total);
    if (!hm) { emf_free(data, total); RET(0); }
    GDI_LEAVE();
    DeleteDC(hdc);                                                    /* frees the recording and the canvas */
    return hm;
}

DLLAPI BOOL WINAPI DeleteEnhMetaFile(HENHMETAFILE h)
{
    emf_t *e;
    GDI_ENTER();
    e = gdi_obj_get((HGDIOBJ)h, OBJ_ENHMETAFILE, 0);
    if (!e) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    gdi_obj_free((HGDIOBJ)h);
    emf_free(e->data, e->size);
    gdi_free(e);
    RET(TRUE);
}

/* a well-formed EMF: header first, every record inside the data, sizes multiples of 4, EOF last */
static int emf_valid(const uint8_t *d, uint32_t size)
{
    const ENHMETAHEADER *hd = (const ENHMETAHEADER *)d;
    uint32_t off = 0;
    if (size < 88 || hd->iType != EMR_HEADER || hd->dSignature != ENHMETA_SIGNATURE || hd->nBytes > size || hd->nSize < 88) return 0;
    while (off < hd->nBytes) {
        const EMR *e = (const EMR *)(d + off);
        if (off + 8 > hd->nBytes || e->nSize < 8 || (e->nSize & 3) || e->nSize > hd->nBytes - off) return 0;
        if (e->iType == EMR_EOF) return 1;
        off += e->nSize;
    }
    return 0;
}

DLLAPI HENHMETAFILE WINAPI SetEnhMetaFileBits(UINT size, const BYTE *bits)
{
    uint8_t *data;
    HENHMETAFILE h;
    if (!bits || !emf_valid(bits, size)) { SetLastError(ERROR_INVALID_DATA); return 0; }
    size = ((const ENHMETAHEADER *)bits)->nBytes;
    data = emf_alloc(size);
    if (!data) return 0;
    memcpy(data, bits, size);
    GDI_ENTER();
    h = emf_handle(data, size);
    GDI_LEAVE();
    if (!h) emf_free(data, size);
    return h;
}

DLLAPI UINT WINAPI GetEnhMetaFileBits(HENHMETAFILE h, UINT size, LPBYTE buf)
{
    emf_t *e;
    GDI_ENTER();
    e = gdi_obj_get((HGDIOBJ)h, OBJ_ENHMETAFILE, 0);
    if (!e) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    if (!buf) RET(e->size);
    if (size < e->size) { SetLastError(ERROR_INSUFFICIENT_BUFFER); RET(0); }
    memcpy(buf, e->data, e->size);
    RET(e->size);
}

DLLAPI UINT WINAPI GetEnhMetaFileHeader(HENHMETAFILE h, UINT size, LPENHMETAHEADER out)
{
    emf_t *e;
    UINT n;
    GDI_ENTER();
    e = gdi_obj_get((HGDIOBJ)h, OBJ_ENHMETAFILE, 0);
    if (!e) { SetLastError(ERROR_INVALID_HANDLE); RET(0); }
    n = ((const ENHMETAHEADER *)e->data)->nSize;
    if (!out) RET(n);
    if (size < n) n = size;
    memcpy(out, e->data, n);
    RET(n);
}

/* ---------------------------------------------------------------- playback */
typedef struct { HDC hdc; double sx, sy, ox, oy; } play_t;
#define PLAY_MAX 16
static play_t g_play[PLAY_MAX];
static int g_nplay;

static const play_t *play_find(HDC hdc)
{
    int i;
    for (i = g_nplay - 1; i >= 0; --i) if (g_play[i].hdc == hdc) return &g_play[i];
    return 0;
}

static int iround(double v) { return v < 0 ? -(int)(-v + 0.5) : (int)(v + 0.5); }

static int dib_ok(const EMR *rec, DWORD offbmi, DWORD cbbmi, DWORD offbits, DWORD cbbits)
{
    return cbbmi >= sizeof(BITMAPINFOHEADER) && offbmi >= 8 && offbmi <= rec->nSize && cbbmi <= rec->nSize - offbmi &&
           offbits <= rec->nSize && cbbits <= rec->nSize - offbits;
}

DLLAPI BOOL WINAPI PlayEnhMetaFileRecord(HDC hdc, LPHANDLETABLE ht, const ENHMETARECORD *rec, UINT n)
{
    play_t id = { 0, 1.0, 1.0, 0.0, 0.0 };
    const play_t *m;
    const EMR *e = (const EMR *)rec;
    DWORD arg;
    (void)ht; (void)n;
    if (!rec || e->nSize < 8) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    GDI_ENTER();
    m = play_find(hdc);
    id = m ? *m : id;
    GDI_LEAVE();
    m = &id;
    arg = e->nSize >= 12 ? rec->dParm[0] : 0;
    switch (e->iType) {
    case EMR_HEADER: case EMR_EOF: case EMR_GDICOMMENT: return TRUE;
    case EMR_STRETCHDIBITS: {
        const EMRSTRETCHDIBITS *s = (const EMRSTRETCHDIBITS *)rec;
        int x0, y0, x1, y1;
        if (e->nSize < sizeof *s || !dib_ok(e, s->offBmiSrc, s->cbBmiSrc, s->offBitsSrc, s->cbBitsSrc)) break;
        x0 = iround(m->ox + s->xDest * m->sx); x1 = iround(m->ox + (s->xDest + s->cxDest) * m->sx);
        y0 = iround(m->oy + s->yDest * m->sy); y1 = iround(m->oy + (s->yDest + s->cyDest) * m->sy);
        return StretchDIBits(hdc, x0, y0, x1 - x0, y1 - y0, s->xSrc, s->ySrc, s->cxSrc, s->cySrc, (const BYTE *)rec + s->offBitsSrc,
                             (const BITMAPINFO *)((const BYTE *)rec + s->offBmiSrc), s->iUsageSrc, s->dwRop) > 0;
    }
    case EMR_SETDIBITSTODEVICE: {
        const EMRSETDIBITSTODEVICE *s = (const EMRSETDIBITSTODEVICE *)rec;
        const BITMAPINFO *bi;
        int x0, y0, x1, y1, bh;
        if (e->nSize < sizeof *s || !dib_ok(e, s->offBmiSrc, s->cbBmiSrc, s->offBitsSrc, s->cbBitsSrc)) break;
        bi = (const BITMAPINFO *)((const BYTE *)rec + s->offBmiSrc);
        if (m->sx == 1.0 && m->sy == 1.0)
            return SetDIBitsToDevice(hdc, iround(m->ox + s->xDest), iround(m->oy + s->yDest), s->cxSrc, s->cySrc, s->xSrc, s->ySrc,
                                     s->iStartScan, s->cScans, (const BYTE *)rec + s->offBitsSrc, bi, s->iUsageSrc) > 0;
        bh = bi->bmiHeader.biHeight < 0 ? -bi->bmiHeader.biHeight : bi->bmiHeader.biHeight;
        if (s->iStartScan != 0 || (int)s->cScans != bh) break;         /* banded records are played 1:1 only */
        x0 = iround(m->ox + s->xDest * m->sx); x1 = iround(m->ox + (s->xDest + (LONG)s->cxSrc) * m->sx);
        y0 = iround(m->oy + s->yDest * m->sy); y1 = iround(m->oy + (s->yDest + (LONG)s->cySrc) * m->sy);
        return StretchDIBits(hdc, x0, y0, x1 - x0, y1 - y0, s->xSrc, s->ySrc, s->cxSrc, s->cySrc, (const BYTE *)rec + s->offBitsSrc,
                             bi, s->iUsageSrc, SRCCOPY) > 0;
    }
    case EMR_SAVEDC: return SaveDC(hdc) != 0;
    case EMR_RESTOREDC: return RestoreDC(hdc, (int)arg);
    case EMR_SETBKMODE: return SetBkMode(hdc, (int)arg) != 0;
    case EMR_SETBKCOLOR: return SetBkColor(hdc, arg) != CLR_INVALID;
    case EMR_SETTEXTCOLOR: return SetTextColor(hdc, arg) != CLR_INVALID;
    case EMR_SETPOLYFILLMODE: return SetPolyFillMode(hdc, (int)arg) != 0;
    case EMR_SETROP2: return SetROP2(hdc, (int)arg) != 0;
    case EMR_SETSTRETCHBLTMODE: return SetStretchBltMode(hdc, (int)arg) != 0;
    case EMR_SETTEXTALIGN: return SetTextAlign(hdc, arg) != GDI_ERROR;
    default: break;
    }
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

DLLAPI BOOL WINAPI EnumEnhMetaFile(HDC hdc, HENHMETAFILE h, ENHMFENUMPROC proc, LPVOID param, const RECT *rc)
{
    emf_t *e;
    const uint8_t *data;
    uint32_t size, off = 0;
    const ENHMETAHEADER *hd;
    HANDLETABLE *ht;
    int nh, pushed = 0, saved = 0;
    BOOL ret = TRUE;
    if (!proc) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    GDI_ENTER();
    e = gdi_obj_get((HGDIOBJ)h, OBJ_ENHMETAFILE, 0);
    if (!e) { SetLastError(ERROR_INVALID_HANDLE); RET(FALSE); }
    data = e->data;
    size = e->size;
    GDI_LEAVE();
    hd = (const ENHMETAHEADER *)data;
    nh = hd->nHandles ? hd->nHandles : 1;
    ht = gdi_alloc(sizeof(HGDIOBJ) * (size_t)nh);
    if (!ht) return FALSE;
    ht->objectHandle[0] = (HGDIOBJ)h;
    if (hdc) {
        play_t p;
        double fl, ft, fr, fb;
        if (!rc) { gdi_free(ht); SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        fl = hd->rclFrame.left * (double)hd->szlDevice.cx / (hd->szlMillimeters.cx * 100.0);   /* frame in reference pixels */
        ft = hd->rclFrame.top * (double)hd->szlDevice.cy / (hd->szlMillimeters.cy * 100.0);
        fr = hd->rclFrame.right * (double)hd->szlDevice.cx / (hd->szlMillimeters.cx * 100.0);
        fb = hd->rclFrame.bottom * (double)hd->szlDevice.cy / (hd->szlMillimeters.cy * 100.0);
        if (fr - fl <= 0 || fb - ft <= 0) {                             /* no frame: the bounds */
            fl = hd->rclBounds.left; ft = hd->rclBounds.top; fr = hd->rclBounds.right + 1; fb = hd->rclBounds.bottom + 1;
        }
        p.hdc = hdc;
        p.sx = fr - fl > 0 ? (rc->right - rc->left) / (fr - fl) : 1.0;
        p.sy = fb - ft > 0 ? (rc->bottom - rc->top) / (fb - ft) : 1.0;
        p.ox = rc->left - fl * p.sx;
        p.oy = rc->top - ft * p.sy;
        saved = SaveDC(hdc);
        GDI_ENTER();
        if (g_nplay < PLAY_MAX) { g_play[g_nplay++] = p; pushed = 1; }
        GDI_LEAVE();
        if (!pushed) { if (saved) RestoreDC(hdc, saved); gdi_free(ht); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    }
    while (off + 8 <= size) {
        const ENHMETARECORD *rec = (const ENHMETARECORD *)(data + off);
        if (rec->nSize < 8 || rec->nSize > size - off) break;
        if (!proc(hdc, ht, rec, nh, (LPARAM)param)) { ret = FALSE; break; }
        if (rec->iType == EMR_EOF) break;
        off += rec->nSize;
    }
    if (pushed) {
        int i;
        GDI_ENTER();
        for (i = g_nplay - 1; i >= 0; --i)
            if (g_play[i].hdc == hdc) { memmove(&g_play[i], &g_play[i + 1], (size_t)(g_nplay - 1 - i) * sizeof g_play[0]); --g_nplay; break; }
        GDI_LEAVE();
        if (saved) RestoreDC(hdc, saved);
    }
    gdi_free(ht);
    return ret;
}

static int CALLBACK play_one(HDC hdc, HANDLETABLE *ht, const ENHMETARECORD *rec, int n, LPARAM param)
{
    (void)param;
    PlayEnhMetaFileRecord(hdc, ht, rec, (UINT)n);                     /* a record that cannot be played is skipped */
    return 1;
}

DLLAPI BOOL WINAPI PlayEnhMetaFile(HDC hdc, HENHMETAFILE h, const RECT *rc)
{
    if (!hdc || !rc) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return EnumEnhMetaFile(hdc, h, play_one, 0, rc);
}
