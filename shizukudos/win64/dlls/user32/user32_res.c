/* SPDX-License-Identifier: GPL-2.0-only
 * user32: resources. The resource directory of a module is read the way the PE format defines it (IMAGE_DIRECTORY_ENTRY_RESOURCE
 * -> type -> name -> language), either in a loaded image (HINSTANCE = image base, NULL = the executable) or in an image
 * file read from disk (PrivateExtractIcons). On top of it: LoadString, icons and cursors from RT_GROUP_ICON/RT_ICON and
 * RT_GROUP_CURSOR/RT_CURSOR (DIB images of 1/4/8/24/32 bpp with AND mask or alpha; PNG-compressed entries are not decoded
 * and are skipped when choosing a size), CreateIconFromResource(Ex), LookupIconIdFromDirectory(Ex), .ico/.cur files for
 * LoadImage(LR_LOADFROMFILE), bitmaps (RT_BITMAP, .bmp files). Language choice: neutral, then en-US, then the first. */
#include "user32_int.h"

HICON u32_icon_create_argb(uint32_t *argb, int w, int h, int cursor, int hx, int hy);   /* user32_icon.c, takes argb */

/* ---------------------------------------------------------------- the resource tree */
typedef struct {
    const uint8_t *base;                        /* loaded image: the image base; file: the file bytes */
    size_t size;                                /* file: its length (0 for a loaded image: RVAs are addresses) */
    const IMAGE_SECTION_HEADER *sec;            /* file: the section table for RVA -> offset */
    int nsec;
    const uint8_t *rsrc;                        /* the resource directory */
    uint32_t rsrc_rva, rsrc_size;
} img_t;

static const void *rva_ptr(const img_t *im, uint32_t rva, uint32_t len)
{
    int i;
    if (!im->size) return im->base + rva;
    for (i = 0; i < im->nsec; ++i) {
        const IMAGE_SECTION_HEADER *s = &im->sec[i];
        const uint32_t vs = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
        if (rva >= s->VirtualAddress && rva - s->VirtualAddress + len <= vs && rva - s->VirtualAddress + len <= s->SizeOfRawData) {
            const size_t off = (size_t)s->PointerToRawData + (rva - s->VirtualAddress);
            return off + len <= im->size ? im->base + off : 0;
        }
    }
    return 0;
}

static int img_open(img_t *im, const uint8_t *base, size_t size)
{
    const IMAGE_DOS_HEADER *d = (const IMAGE_DOS_HEADER *)base;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_DATA_DIRECTORY *dd;
    memset(im, 0, sizeof *im);
    im->base = base;
    im->size = size;
    if (size && size < sizeof *d) return 0;
    if (d->e_magic != IMAGE_DOS_SIGNATURE || (size && (size_t)d->e_lfanew + sizeof *nt > size)) return 0;
    nt = (const IMAGE_NT_HEADERS64 *)(base + d->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        dd = &((const IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    else return 0;
    im->sec = (const IMAGE_SECTION_HEADER *)((const uint8_t *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    im->nsec = nt->FileHeader.NumberOfSections;
    if (size && (size_t)((const uint8_t *)(im->sec + im->nsec) - base) > size) return 0;
    if (!dd->VirtualAddress || !dd->Size) return 0;
    im->rsrc_rva = dd->VirtualAddress;
    im->rsrc_size = dd->Size;
    im->rsrc = rva_ptr(im, dd->VirtualAddress, dd->Size);
    return im->rsrc != 0;
}

static int wname_eq(const img_t *im, uint32_t name_off, LPCWSTR want)
{
    const uint16_t *n;
    unsigned len, i;
    if (name_off + 2 > im->rsrc_size) return 0;
    n = (const uint16_t *)(im->rsrc + name_off);
    len = n[0];
    if (name_off + 2 + len * 2 > im->rsrc_size) return 0;
    for (i = 0; i < len; ++i) {
        WCHAR a = n[1 + i], b = want[i];
        if (!b) return 0;
        if (a >= 'a' && a <= 'z') a = (WCHAR)(a - 32);
        if (b >= 'a' && b <= 'z') b = (WCHAR)(b - 32);
        if (a != b) return 0;
    }
    return want[len] == 0;
}

/* One level: the entry matching `key` (integer id or string; "#123" is id 123); returns its OffsetToData or 0. */
static uint32_t dir_find(const img_t *im, uint32_t dir_off, LPCWSTR key, int any)
{
    const IMAGE_RESOURCE_DIRECTORY *d;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *e;
    unsigned i, n;
    uintptr_t id = (uintptr_t)key;
    int is_id = IS_INTRESOURCE(key);
    if (dir_off + sizeof *d > im->rsrc_size) return 0;
    d = (const IMAGE_RESOURCE_DIRECTORY *)(im->rsrc + dir_off);
    n = (unsigned)d->NumberOfNamedEntries + d->NumberOfIdEntries;
    if (dir_off + sizeof *d + n * sizeof *e > im->rsrc_size) return 0;
    e = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(d + 1);
    if (!is_id && key[0] == '#') {
        uintptr_t v = 0;
        const WCHAR *p = key + 1;
        while (*p >= '0' && *p <= '9') v = v * 10 + (uintptr_t)(*p++ - '0');
        id = v;
        is_id = 1;
    }
    for (i = 0; i < n; ++i) {
        if (any) return e[i].OffsetToData;
        if (is_id && !e[i].NameIsString && e[i].Id == id) return e[i].OffsetToData;
        if (!is_id && e[i].NameIsString && wname_eq(im, e[i].NameOffset, key)) return e[i].OffsetToData;
    }
    return 0;
}

static const void *img_resource(const img_t *im, LPCWSTR type, LPCWSTR name, DWORD *size)
{
    static const WORD langs[3] = { 0, 0x409, 0x800 };
    uint32_t t, nm, l = 0;
    const IMAGE_RESOURCE_DATA_ENTRY *de;
    int i;
    t = dir_find(im, 0, type, 0);
    if (!(t & 0x80000000u)) return 0;
    nm = dir_find(im, t & 0x7fffffffu, name, 0);
    if (!(nm & 0x80000000u)) return 0;
    for (i = 0; i < 3 && !l; ++i) l = dir_find(im, nm & 0x7fffffffu, MAKEINTRESOURCEW(langs[i]), 0);
    if (!l) l = dir_find(im, nm & 0x7fffffffu, 0, 1);
    if (!l || (l & 0x80000000u) || l + sizeof *de > im->rsrc_size) return 0;
    de = (const IMAGE_RESOURCE_DATA_ENTRY *)(im->rsrc + l);
    if (size) *size = de->Size;
    return rva_ptr(im, de->OffsetToData, de->Size);
}

const void *u32_find_resource(HINSTANCE inst, LPCWSTR type, LPCWSTR name, DWORD *size)
{
    img_t im;
    if (!inst) inst = GetModuleHandleW(0);
    if (!inst || !img_open(&im, (const uint8_t *)inst, 0)) return 0;
    return img_resource(&im, type, name, size);
}

/* ---------------------------------------------------------------- strings */
DLLAPI int WINAPI LoadStringW(HINSTANCE inst, UINT id, LPWSTR buf, int cap)
{
    DWORD size = 0;
    const WCHAR *p = u32_find_resource(inst, (LPCWSTR)RT_STRING, MAKEINTRESOURCEW((id >> 4) + 1), &size);
    const WCHAR *end;
    unsigned i;
    int n;
    if (!buf) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!p) { if (cap > 0) buf[0] = 0; SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return 0; }
    end = (const WCHAR *)((const uint8_t *)p + size);
    for (i = 0; i < (id & 15) && p < end; ++i) p += 1 + *p;           /* skip the preceding counted strings */
    if (p >= end || !*p) { if (cap > 0) buf[0] = 0; SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return 0; }
    n = *p;
    if (cap == 0) { *(const WCHAR **)buf = p + 1; return n; }          /* a read-only pointer to the string itself */
    if (n > cap - 1) n = cap - 1;
    memcpy(buf, p + 1, (size_t)n * 2);
    buf[n] = 0;
    return n;
}

DLLAPI int WINAPI LoadStringA(HINSTANCE inst, UINT id, LPSTR buf, int cap)
{
    WCHAR w[1024];
    int n;
    if (!buf || cap <= 0) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    n = LoadStringW(inst, id, w, 1024);
    if (n <= 0) { buf[0] = 0; return 0; }
    n = WideCharToMultiByte(CP_ACP, 0, w, n, buf, cap - 1, 0, 0);
    buf[n] = 0;
    return n;
}

/* ---------------------------------------------------------------- icon and cursor images */
static uint32_t pal_px(const RGBQUAD *pal, int npal, int i) { return i < npal ? 0xff000000u | (uint32_t)pal[i].rgbRed << 16 | (uint32_t)pal[i].rgbGreen << 8 | pal[i].rgbBlue : 0xff000000u; }

/* A DIB icon image (BITMAPINFOHEADER, height = 2 x image height: XOR image then 1 bpp AND mask) -> straight ARGB. */
static uint32_t *dib_icon_argb(const uint8_t *p, DWORD size, int *w, int *h)
{
    const BITMAPINFOHEADER *bh = (const BITMAPINFOHEADER *)p;
    int bpp, npal = 0, x, y, any_alpha = 0;
    size_t xstride, astride, off;
    const uint8_t *xor_bits, *and_bits;
    const RGBQUAD *pal;
    uint32_t *a;
    if (size < sizeof *bh || bh->biSize < sizeof *bh || bh->biWidth <= 0 || bh->biWidth > 1024 || bh->biHeight <= 0) return 0;
    if (bh->biCompression != BI_RGB) return 0;
    bpp = bh->biBitCount;
    if (bpp != 1 && bpp != 4 && bpp != 8 && bpp != 24 && bpp != 32) return 0;
    *w = bh->biWidth;
    *h = bh->biHeight / 2;
    if (*h <= 0 || *h > 1024) return 0;
    if (bpp <= 8) npal = bh->biClrUsed ? (int)bh->biClrUsed : 1 << bpp;
    pal = (const RGBQUAD *)(p + bh->biSize);
    xstride = (((size_t)*w * (size_t)bpp + 31) / 32) * 4;
    astride = (((size_t)*w + 31) / 32) * 4;
    off = bh->biSize + (size_t)npal * 4;
    if (off + xstride * (size_t)*h > size) return 0;
    xor_bits = p + off;
    and_bits = off + xstride * (size_t)*h + astride * (size_t)*h <= size ? xor_bits + xstride * (size_t)*h : 0;
    a = HeapAlloc(GetProcessHeap(), 0, (size_t)*w * (size_t)*h * 4);
    if (!a) return 0;
    for (y = 0; y < *h; ++y) {
        const uint8_t *r = xor_bits + xstride * (size_t)(*h - 1 - y);    /* bottom-up */
        for (x = 0; x < *w; ++x) {
            uint32_t v;
            switch (bpp) {
            case 32: v = ((const uint32_t *)r)[x]; any_alpha |= (int)(v >> 24); break;
            case 24: v = 0xff000000u | (uint32_t)r[x * 3 + 2] << 16 | (uint32_t)r[x * 3 + 1] << 8 | r[x * 3]; break;
            case 8: v = pal_px(pal, npal, r[x]); break;
            case 4: v = pal_px(pal, npal, (r[x >> 1] >> ((x & 1) ? 0 : 4)) & 15); break;
            default: v = pal_px(pal, npal, (r[x >> 3] >> (7 - (x & 7))) & 1); break;
            }
            a[(size_t)y * (size_t)*w + (size_t)x] = v;
        }
    }
    if (bpp == 32 && any_alpha) return a;                               /* per-pixel alpha: the AND mask is ignored */
    for (y = 0; y < *h; ++y)
        for (x = 0; x < *w; ++x) {
            uint32_t *v = &a[(size_t)y * (size_t)*w + (size_t)x];
            const int transparent = and_bits && ((and_bits[astride * (size_t)(*h - 1 - y) + (size_t)(x >> 3)] >> (7 - (x & 7))) & 1);
            *v = transparent ? 0 : (*v | 0xff000000u);
        }
    return a;
}

static uint32_t *scale_argb(uint32_t *src, int w, int h, int nw, int nh)
{
    uint32_t *d;
    int x, y;
    if (nw == w && nh == h) return src;
    d = HeapAlloc(GetProcessHeap(), 0, (size_t)nw * (size_t)nh * 4);
    if (!d) return src;
    for (y = 0; y < nh; ++y)
        for (x = 0; x < nw; ++x) d[(size_t)y * (size_t)nw + (size_t)x] = src[(size_t)(y * h / nh) * (size_t)w + (size_t)(x * w / nw)];
    HeapFree(GetProcessHeap(), 0, src);
    return d;
}

DLLAPI HICON WINAPI CreateIconFromResourceEx(PBYTE bits, DWORD size, BOOL icon, DWORD ver, int cx, int cy, UINT flags)
{
    int w, h, hx = 0, hy = 0;
    uint32_t *a;
    (void)ver;
    if (!bits || size < 8) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!icon) { hx = ((const WORD *)bits)[0]; hy = ((const WORD *)bits)[1]; bits += 4; size -= 4; }
    if (size >= 8 && bits[0] == 0x89 && bits[1] == 'P' && bits[2] == 'N' && bits[3] == 'G') { SetLastError(ERROR_NOT_SUPPORTED); return 0; }   /* PNG: no decoder */
    a = dib_icon_argb(bits, size, &w, &h);
    if (!a) { SetLastError(ERROR_INVALID_DATA); return 0; }
    if (!cx && (flags & LR_DEFAULTSIZE)) cx = u32_metric(icon ? SM_CXICON : SM_CXCURSOR);
    if (!cy && (flags & LR_DEFAULTSIZE)) cy = u32_metric(icon ? SM_CYICON : SM_CYCURSOR);
    if (cx > 0 && cy > 0 && (cx != w || cy != h)) {
        hx = hx * cx / w; hy = hy * cy / h;
        a = scale_argb(a, w, h, cx, cy);
        w = cx; h = cy;
    }
    if (icon) { hx = w / 2; hy = h / 2; }
    return u32_icon_create_argb(a, w, h, !icon, hx, hy);
}

DLLAPI HICON WINAPI CreateIconFromResource(PBYTE bits, DWORD size, BOOL icon, DWORD ver) { return CreateIconFromResourceEx(bits, size, icon, ver, 0, 0, LR_DEFAULTSIZE); }

#pragma pack(push, 2)
typedef struct { WORD reserved, type, count; } grpdir_t;
typedef struct { BYTE w, h, colors, reserved; WORD planes, bpp; DWORD bytes; WORD id; } grpicon_t;       /* RT_GROUP_ICON */
typedef struct { WORD w, h2, planes, bpp; DWORD bytes; WORD id; } grpcur_t;                            /* RT_GROUP_CURSOR */
typedef struct { BYTE w, h, colors, reserved; WORD planes, bpp; DWORD bytes, offset; } icofile_t;       /* .ico/.cur files */
#pragma pack(pop)

/* the entry whose size is closest to cx x cy (larger preferred over smaller), then the deepest colour */
static int best_entry(const uint8_t *dir, int icon, int cx, int cy, int file)
{
    const grpdir_t *d = (const grpdir_t *)dir;
    int i, best = -1;
    long best_score = 0;
    for (i = 0; i < d->count; ++i) {
        int w, h, bpp;
        long score;
        if (file) { const icofile_t *e = (const icofile_t *)(d + 1) + i; w = e->w ? e->w : 256; h = e->h ? e->h : 256; bpp = icon ? e->bpp : 32; }
        else if (icon) { const grpicon_t *e = (const grpicon_t *)(d + 1) + i; w = e->w ? e->w : 256; h = e->h ? e->h : 256; bpp = e->bpp; }
        else { const grpcur_t *e = (const grpcur_t *)(d + 1) + i; w = e->w; h = e->h2 / 2; bpp = e->bpp; }
        if (w >= 256 && icon) continue;                                 /* 256 px entries are PNG compressed in practice */
        score = (long)(w >= cx ? w - cx : (cx - w) * 4) + (long)(h >= cy ? h - cy : (cy - h) * 4);
        score = score * 64 - bpp;
        if (best < 0 || score < best_score) { best = i; best_score = score; }
    }
    return best;
}

DLLAPI int WINAPI LookupIconIdFromDirectoryEx(PBYTE dir, BOOL icon, int cx, int cy, UINT flags)
{
    const grpdir_t *d = (const grpdir_t *)dir;
    int i;
    if (!dir || d->type != (icon ? 1 : 2)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!cx) cx = (flags & LR_DEFAULTSIZE) || !cx ? u32_metric(icon ? SM_CXICON : SM_CXCURSOR) : cx;
    if (!cy) cy = (flags & LR_DEFAULTSIZE) || !cy ? u32_metric(icon ? SM_CYICON : SM_CYCURSOR) : cy;
    i = best_entry(dir, icon, cx, cy, 0);
    if (i < 0) return 0;
    return icon ? ((const grpicon_t *)(d + 1))[i].id : ((const grpcur_t *)(d + 1))[i].id;
}

DLLAPI int WINAPI LookupIconIdFromDirectory(PBYTE dir, BOOL icon) { return LookupIconIdFromDirectoryEx(dir, icon, 0, 0, LR_DEFAULTSIZE); }

static HICON icon_from_img(const img_t *im, LPCWSTR name, int cursor, int cx, int cy)
{
    DWORD size = 0;
    const uint8_t *dir = img_resource(im, cursor ? (LPCWSTR)RT_GROUP_CURSOR : (LPCWSTR)RT_GROUP_ICON, name, &size);
    const uint8_t *img;
    int id;
    if (!dir || size < sizeof(grpdir_t)) { SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return 0; }
    if (!cx) cx = u32_metric(cursor ? SM_CXCURSOR : SM_CXICON);
    if (!cy) cy = u32_metric(cursor ? SM_CYCURSOR : SM_CYICON);
    id = LookupIconIdFromDirectoryEx((PBYTE)dir, !cursor, cx, cy, 0);
    if (!id) { SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return 0; }
    img = img_resource(im, cursor ? (LPCWSTR)RT_CURSOR : (LPCWSTR)RT_ICON, MAKEINTRESOURCEW(id), &size);
    if (!img) { SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return 0; }
    return CreateIconFromResourceEx((PBYTE)img, size, !cursor, 0x00030000, cx, cy, 0);
}

HICON u32_icon_from_resource(HINSTANCE inst, LPCWSTR name, int cursor, int cx, int cy)
{
    img_t im;
    if (!inst) inst = GetModuleHandleW(0);
    if (!inst || !img_open(&im, (const uint8_t *)inst, 0)) { SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND); return 0; }
    return icon_from_img(&im, name, cursor, cx, cy);
}

/* ---------------------------------------------------------------- files */
static uint8_t *read_file(LPCWSTR path, size_t *n)
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    LARGE_INTEGER sz;
    uint8_t *p;
    DWORD got = 0;
    if (f == INVALID_HANDLE_VALUE) return 0;
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (256 << 20)) { CloseHandle(f); SetLastError(ERROR_INVALID_DATA); return 0; }
    p = HeapAlloc(GetProcessHeap(), 0, (size_t)sz.QuadPart);
    if (!p) { CloseHandle(f); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    if (!ReadFile(f, p, (DWORD)sz.QuadPart, &got, 0) || got != (DWORD)sz.QuadPart) { CloseHandle(f); HeapFree(GetProcessHeap(), 0, p); return 0; }
    CloseHandle(f);
    *n = (size_t)sz.QuadPart;
    return p;
}

/* an .ico or .cur file */
static HICON icon_from_icofile(const uint8_t *p, size_t n, int cursor, int cx, int cy)
{
    const grpdir_t *d = (const grpdir_t *)p;
    const icofile_t *e;
    int i;
    if (n < sizeof *d || d->reserved || (d->type != 1 && d->type != 2) || n < sizeof *d + d->count * sizeof *e) { SetLastError(ERROR_INVALID_DATA); return 0; }
    cursor = d->type == 2;
    if (!cx) cx = u32_metric(cursor ? SM_CXCURSOR : SM_CXICON);
    if (!cy) cy = u32_metric(cursor ? SM_CYCURSOR : SM_CYICON);
    i = best_entry(p, !cursor, cx, cy, 1);
    if (i < 0) { SetLastError(ERROR_INVALID_DATA); return 0; }
    e = (const icofile_t *)(d + 1) + i;
    if ((size_t)e->offset + e->bytes > n) { SetLastError(ERROR_INVALID_DATA); return 0; }
    if (cursor) {                                                       /* hot spot lives in the directory entry of a .cur */
        uint8_t *tmp = HeapAlloc(GetProcessHeap(), 0, (size_t)e->bytes + 4);
        HICON h;
        if (!tmp) return 0;
        ((WORD *)tmp)[0] = e->planes;
        ((WORD *)tmp)[1] = e->bpp;
        memcpy(tmp + 4, p + e->offset, e->bytes);
        h = CreateIconFromResourceEx(tmp, e->bytes + 4, FALSE, 0x00030000, cx, cy, 0);
        HeapFree(GetProcessHeap(), 0, tmp);
        return h;
    }
    return CreateIconFromResourceEx((PBYTE)(p + e->offset), e->bytes, TRUE, 0x00030000, cx, cy, 0);
}

HICON u32_icon_from_file(LPCWSTR path, int cursor, int cx, int cy)
{
    size_t n = 0;
    uint8_t *p = read_file(path, &n);
    HICON h;
    if (!p) return 0;
    h = icon_from_icofile(p, n, cursor, cx, cy);
    HeapFree(GetProcessHeap(), 0, p);
    return h;
}

/* A packed DIB (BITMAPINFO + bits) -> a bitmap object. */
HBITMAP u32_bitmap_from_dib(const uint8_t *p, size_t n)
{
    const BITMAPINFOHEADER *h = (const BITMAPINFOHEADER *)p;
    size_t pal = 0;
    HBITMAP hb;
    HDC dc;
    int ah;
    if (n < sizeof *h || h->biSize < sizeof *h || h->biWidth <= 0) return 0;
    if (h->biBitCount <= 8) pal = (h->biClrUsed ? h->biClrUsed : (1u << h->biBitCount)) * 4;
    else if (h->biCompression == BI_BITFIELDS) pal = 12;
    if (h->biSize + pal > n) return 0;
    ah = h->biHeight < 0 ? -h->biHeight : h->biHeight;
    dc = GetDC(0);
    hb = CreateCompatibleBitmap(dc, h->biWidth, ah);
    if (hb && SetDIBits(dc, hb, 0, (UINT)ah, p + h->biSize + pal, (const BITMAPINFO *)p, DIB_RGB_COLORS) <= 0) { DeleteObject(hb); hb = 0; }
    ReleaseDC(0, dc);
    return hb;
}

DLLAPI HBITMAP WINAPI LoadBitmapW(HINSTANCE inst, LPCWSTR name)
{
    DWORD size = 0;
    const uint8_t *p;
    if (!inst) { SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return 0; }   /* OBM_* system bitmaps do not exist */
    p = u32_find_resource(inst, (LPCWSTR)RT_BITMAP, name, &size);
    if (!p) { SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return 0; }
    return u32_bitmap_from_dib(p, size);
}

HBITMAP u32_bitmap_from_file(LPCWSTR path)
{
    size_t n = 0;
    uint8_t *p = read_file(path, &n);
    HBITMAP hb = 0;
    if (!p) return 0;
    if (n > sizeof(BITMAPFILEHEADER) && p[0] == 'B' && p[1] == 'M') {
        const BITMAPFILEHEADER *fh = (const BITMAPFILEHEADER *)p;
        const BITMAPINFOHEADER *ih = (const BITMAPINFOHEADER *)(p + sizeof *fh);
        size_t pal = 0;
        if (ih->biBitCount <= 8) pal = (ih->biClrUsed ? ih->biClrUsed : (1u << ih->biBitCount)) * 4;
        else if (ih->biCompression == BI_BITFIELDS) pal = 12;
        if (fh->bfOffBits >= sizeof *fh + ih->biSize + pal && fh->bfOffBits < n) {
            /* repack as a DIB whose bits follow the colour table directly */
            const size_t head = ih->biSize + pal, bits = n - fh->bfOffBits;
            uint8_t *dib = HeapAlloc(GetProcessHeap(), 0, head + bits);
            if (dib) {
                memcpy(dib, ih, head);
                memcpy(dib + head, p + fh->bfOffBits, bits);
                hb = u32_bitmap_from_dib(dib, head + bits);
                HeapFree(GetProcessHeap(), 0, dib);
            }
        }
    }
    if (!hb) SetLastError(ERROR_INVALID_DATA);
    HeapFree(GetProcessHeap(), 0, p);
    return hb;
}

/* ---------------------------------------------------------------- PrivateExtractIconsW */
/* the RT_GROUP_ICON entries of an image in directory order (named entries first, as the format stores them) */
static int group_icon_names(const img_t *im, LPCWSTR *names, WCHAR (*buf)[64], int max)
{
    const IMAGE_RESOURCE_DIRECTORY *d;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *e;
    uint32_t t = dir_find(im, 0, (LPCWSTR)RT_GROUP_ICON, 0);
    unsigned i, n;
    int k = 0;
    if (!(t & 0x80000000u)) return 0;
    t &= 0x7fffffffu;
    if (t + sizeof *d > im->rsrc_size) return 0;
    d = (const IMAGE_RESOURCE_DIRECTORY *)(im->rsrc + t);
    n = (unsigned)d->NumberOfNamedEntries + d->NumberOfIdEntries;
    e = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(d + 1);
    for (i = 0; i < n && k < max; ++i, ++k) {
        if (e[i].NameIsString) {
            const uint16_t *s = (const uint16_t *)(im->rsrc + e[i].NameOffset);
            const unsigned len = s[0] < 63 ? s[0] : 63;
            memcpy(buf[k], s + 1, len * 2);
            buf[k][len] = 0;
            names[k] = buf[k];
        } else {
            names[k] = MAKEINTRESOURCEW(e[i].Id);
        }
    }
    return k;
}

DLLAPI UINT WINAPI PrivateExtractIconsW(LPCWSTR file, int index, int cx, int cy, HICON *icons, UINT *ids, UINT n, UINT flags)
{
    size_t size = 0;
    uint8_t *p;
    img_t im;
    UINT got = 0;
    (void)flags;
    if (!file) { SetLastError(ERROR_INVALID_PARAMETER); return (UINT)-1; }
    p = read_file(file, &size);
    if (!p) return (UINT)-1;
    if (size >= 6 && p[0] == 0 && p[1] == 0 && (p[2] == 1 || p[2] == 2) && p[3] == 0) {       /* .ico / .cur */
        if (!icons) got = 1;
        else if (n && index == 0) { icons[0] = icon_from_icofile(p, size, 0, LOWORD(cx), LOWORD(cy)); if (ids) ids[0] = 0; got = icons[0] ? 1 : 0; }
    } else if (img_open(&im, p, size)) {
        static LPCWSTR names[256];
        static WCHAR nbuf[256][64];
        const int total = group_icon_names(&im, names, nbuf, 256);
        if (!icons) got = (UINT)total;
        else if (index < 0) {                                           /* a resource id */
            if (n) { icons[0] = icon_from_img(&im, MAKEINTRESOURCEW(-index), 0, LOWORD(cx), LOWORD(cy)); if (ids) ids[0] = (UINT)-index; got = icons[0] ? 1 : 0; }
        } else {
            int i;
            for (i = index; i < total && got < n; ++i) {
                icons[got] = icon_from_img(&im, names[i], 0, LOWORD(cx), LOWORD(cy));
                if (!icons[got]) break;
                if (ids) ids[got] = IS_INTRESOURCE(names[i]) ? (UINT)(uintptr_t)names[i] : 0;
                ++got;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, p);
    return got;
}
