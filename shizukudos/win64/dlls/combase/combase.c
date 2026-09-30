/* SPDX-License-Identifier: GPL-2.0-only
 * combase.dll - the Windows Runtime string type (HSTRING) and the apartment entry points RoInitialize / RoUninitialize.
 *
 * HSTRING is an immutable, reference-counted UTF-16 string; NULL is the empty string. Heap strings keep their reference
 * count in a small header in front of the characters. "Fast-pass" strings made by WindowsCreateStringReference live in the
 * caller's HSTRING_HEADER (24 bytes on x64, as documented), are never freed and must not outlive the buffer they point at
 * (which the caller must keep NUL-terminated); duplicating one makes a real copy.
 *
 * RoInitialize maps RO_INIT_SINGLETHREADED / RO_INIT_MULTITHREADED to CoInitializeEx STA / MTA (ole32.dll) with its
 * S_OK / S_FALSE / RPC_E_CHANGED_MODE results. There is no class registry, so RoGetActivationFactory and
 * RoActivateInstance are not provided.
 */
#include "nt.h"
#include <string.h>
#include <roapi.h>
#include <winstring.h>

#define E_BOUNDS_ ((HRESULT)0x8000000B)

#define COINIT_MULTITHREADED_ 0
#define COINIT_APARTMENTTHREADED_ 2

enum { HS_REFERENCE = 1, HS_PREALLOC = 2 };
typedef struct { UINT32 flags; UINT32 length; LONG refs; UINT32 pad; const WCHAR *ptr; } hstr_rep;     /* 24 bytes on x64 */
static const WCHAR g_empty[1] = { 0 };

static hstr_rep *heap_string(UINT32 length, int zero)
{
    hstr_rep *r;
    if (length > 0x3ffffff0u) return 0;
    r = HeapAlloc(GetProcessHeap(), zero ? HEAP_ZERO_MEMORY : 0, sizeof(hstr_rep) + ((SIZE_T)length + 1) * sizeof(WCHAR));
    if (!r) return 0;
    r->flags = 0;
    r->length = length;
    r->refs = 1;
    r->pad = 0;
    r->ptr = (const WCHAR *)(r + 1);
    ((WCHAR *)(r + 1))[length] = 0;
    return r;
}

DLLAPI HRESULT WINAPI WindowsCreateString(LPCWSTR src, UINT32 length, HSTRING *out)
{
    hstr_rep *r;
    if (!out) return E_INVALIDARG;
    *out = 0;
    if (!length) return S_OK;
    if (!src) return E_POINTER;
    r = heap_string(length, 0);
    if (!r) return E_OUTOFMEMORY;
    memcpy((WCHAR *)r->ptr, src, (SIZE_T)length * sizeof(WCHAR));
    *out = (HSTRING)r;
    return S_OK;
}

DLLAPI HRESULT WINAPI WindowsCreateStringReference(PCWSTR src, UINT32 length, HSTRING_HEADER *header, HSTRING *out)
{
    hstr_rep *r = (hstr_rep *)header;
    if (!out || !header) return E_INVALIDARG;
    *out = 0;
    if (!length) return S_OK;
    if (!src) return E_POINTER;
    r->flags = HS_REFERENCE;
    r->length = length;
    r->refs = 0;
    r->pad = 0;
    r->ptr = src;
    *out = (HSTRING)r;
    return S_OK;
}

DLLAPI HRESULT WINAPI WindowsDeleteString(HSTRING s)
{
    hstr_rep *r = (hstr_rep *)s;
    if (!r) return S_OK;
    if (r->flags & HS_REFERENCE) return S_OK;                       /* the header belongs to the caller */
    if (InterlockedDecrement(&r->refs) == 0) HeapFree(GetProcessHeap(), 0, r);
    return S_OK;
}

DLLAPI HRESULT WINAPI WindowsDuplicateString(HSTRING s, HSTRING *out)
{
    hstr_rep *r = (hstr_rep *)s;
    if (!out) return E_INVALIDARG;
    if (!r) { *out = 0; return S_OK; }
    if (r->flags & HS_REFERENCE) return WindowsCreateString(r->ptr, r->length, out);
    InterlockedIncrement(&r->refs);
    *out = s;
    return S_OK;
}

DLLAPI PCWSTR WINAPI WindowsGetStringRawBuffer(HSTRING s, UINT32 *length)
{
    hstr_rep *r = (hstr_rep *)s;
    if (!r) {
        if (length) *length = 0;
        return g_empty;
    }
    if (length) *length = r->length;
    return r->ptr;
}

DLLAPI UINT32 WINAPI WindowsGetStringLen(HSTRING s) { return s ? ((hstr_rep *)s)->length : 0; }
DLLAPI BOOL WINAPI WindowsIsStringEmpty(HSTRING s) { return !s || ((hstr_rep *)s)->length == 0; }

DLLAPI HRESULT WINAPI WindowsStringHasEmbeddedNull(HSTRING s, BOOL *has)
{
    const hstr_rep *r = (const hstr_rep *)s;
    UINT32 i;
    if (!has) return E_INVALIDARG;
    *has = FALSE;
    if (r)
        for (i = 0; i < r->length; ++i)
            if (!r->ptr[i]) { *has = TRUE; break; }
    return S_OK;
}

DLLAPI HRESULT WINAPI WindowsCompareStringOrdinal(HSTRING a, HSTRING b, INT32 *result)
{
    const WCHAR *pa, *pb;
    UINT32 la, lb, i;
    if (!result) return E_INVALIDARG;
    if (a == b) { *result = 0; return S_OK; }
    pa = WindowsGetStringRawBuffer(a, &la);
    pb = WindowsGetStringRawBuffer(b, &lb);
    for (i = 0; i < la && i < lb; ++i)
        if (pa[i] != pb[i]) { *result = pa[i] < pb[i] ? -1 : 1; return S_OK; }
    *result = la == lb ? 0 : la < lb ? -1 : 1;
    return S_OK;
}

DLLAPI HRESULT WINAPI WindowsConcatString(HSTRING a, HSTRING b, HSTRING *out)
{
    UINT32 la = WindowsGetStringLen(a), lb = WindowsGetStringLen(b);
    hstr_rep *r;
    if (!out) return E_INVALIDARG;
    if (!la) return WindowsDuplicateString(b, out);
    if (!lb) return WindowsDuplicateString(a, out);
    if ((UINT64)la + lb > 0x3ffffff0u) { *out = 0; return E_OUTOFMEMORY; }
    r = heap_string(la + lb, 0);
    if (!r) { *out = 0; return E_OUTOFMEMORY; }
    memcpy((WCHAR *)r->ptr, ((hstr_rep *)a)->ptr, (SIZE_T)la * sizeof(WCHAR));
    memcpy((WCHAR *)r->ptr + la, ((hstr_rep *)b)->ptr, (SIZE_T)lb * sizeof(WCHAR));
    *out = (HSTRING)r;
    return S_OK;
}

DLLAPI HRESULT WINAPI WindowsSubstringWithSpecifiedLength(HSTRING s, UINT32 start, UINT32 length, HSTRING *out)
{
    UINT32 sl = WindowsGetStringLen(s);
    if (!out) return E_INVALIDARG;
    *out = 0;
    if (start > sl || length > sl - start) return E_BOUNDS_;
    if (!length) return S_OK;
    if (start == 0 && length == sl) return WindowsDuplicateString(s, out);
    return WindowsCreateString(((hstr_rep *)s)->ptr + start, length, out);
}

DLLAPI HRESULT WINAPI WindowsSubstring(HSTRING s, UINT32 start, HSTRING *out)
{
    UINT32 sl = WindowsGetStringLen(s);
    if (!out) return E_INVALIDARG;
    *out = 0;
    if (start > sl) return E_BOUNDS_;
    return WindowsSubstringWithSpecifiedLength(s, start, sl - start, out);
}

/* ---- mutable buffers: fill, then promote to an immutable HSTRING ---- */
DLLAPI HRESULT WindowsPreallocateStringBuffer(UINT32 length, WCHAR **buffer, HSTRING_BUFFER *handle)
{
    hstr_rep *r;
    if (!buffer || !handle) return E_POINTER;
    *buffer = 0;
    *handle = 0;
    if (!length) return S_OK;                                      /* an empty string needs no buffer */
    r = heap_string(length, 1);
    if (!r) return E_OUTOFMEMORY;
    r->flags = HS_PREALLOC;
    *buffer = (WCHAR *)r->ptr;
    *handle = (HSTRING_BUFFER)r;
    return S_OK;
}

DLLAPI HRESULT WindowsPromoteStringBuffer(HSTRING_BUFFER handle, HSTRING *out)
{
    hstr_rep *r = (hstr_rep *)handle;
    if (!out) return E_POINTER;
    *out = 0;
    if (!r) return S_OK;
    if (!(r->flags & HS_PREALLOC)) return E_INVALIDARG;
    ((WCHAR *)r->ptr)[r->length] = 0;
    r->flags = 0;
    *out = (HSTRING)r;
    return S_OK;
}

DLLAPI HRESULT WindowsDeleteStringBuffer(HSTRING_BUFFER handle)
{
    hstr_rep *r = (hstr_rep *)handle;
    if (!r) return S_OK;
    if (!(r->flags & HS_PREALLOC)) return E_INVALIDARG;
    HeapFree(GetProcessHeap(), 0, r);
    return S_OK;
}

/* ---- apartments ---- */
DLLAPI HRESULT WINAPI RoInitialize(RO_INIT_TYPE type)
{
    if (type != RO_INIT_SINGLETHREADED && type != RO_INIT_MULTITHREADED) return E_INVALIDARG;
    return CoInitializeEx(0, type == RO_INIT_MULTITHREADED ? COINIT_MULTITHREADED_ : COINIT_APARTMENTTHREADED_);
}

DLLAPI void WINAPI RoUninitialize(void) { CoUninitialize(); }

/* ---------------------------------------------------------------- activation (api-ms-win-core-winrt-l1-1-0), error origination
 * No Windows Runtime class is registered on this system (there is no activation store and no in-box runtime class),
 * so RoGetActivationFactory / RoActivateInstance answer REGDB_E_CLASSNOTREG for every class id - the documented code
 * for an unregistered class, which callers (Chromium's connectivity and notification code) treat as "unavailable".
 * They require RoInitialize on the thread (CO_E_NOTINITIALIZED). RoOriginateError/W: there is no error-info store to
 * record the origination in, so they report FALSE ("not originated"), never a success they did not deliver. */
#define REGDB_E_CLASSNOTREG_ ((HRESULT)0x80040154)
#define CO_E_NOTINITIALIZED_ ((HRESULT)0x800401F0)
#define E_INVALIDARG_ ((HRESULT)0x80070057)
#define E_POINTER_ ((HRESULT)0x80004003)

static int ro_active(void)
{
    APTTYPE t;
    APTTYPEQUALIFIER q;
    return CoGetApartmentType(&t, &q) == S_OK;
}

DLLAPI HRESULT WINAPI RoGetActivationFactory(HSTRING classid, REFIID iid, void **out)
{
    if (!out) return E_POINTER_;
    *out = 0;
    if (!classid || !iid) return E_INVALIDARG_;
    if (!ro_active()) return CO_E_NOTINITIALIZED_;
    return REGDB_E_CLASSNOTREG_;
}

DLLAPI HRESULT WINAPI RoActivateInstance(HSTRING classid, IInspectable **out)
{
    if (!out) return E_POINTER_;
    *out = 0;
    if (!classid) return E_INVALIDARG_;
    if (!ro_active()) return CO_E_NOTINITIALIZED_;
    return REGDB_E_CLASSNOTREG_;
}

DLLAPI BOOL WINAPI RoOriginateError(HRESULT error, HSTRING message)
{
    (void)error; (void)message;
    return FALSE;
}

DLLAPI BOOL WINAPI RoOriginateErrorW(HRESULT error, UINT length, PCWSTR message)
{
    (void)error; (void)length; (void)message;
    return FALSE;
}
