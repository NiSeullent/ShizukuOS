/* SPDX-License-Identifier: GPL-2.0-only
 * user32: menus and accelerator tables.
 *
 * Menus are objects of this process (a handle table like the icons'); every item keeps the MENUITEMINFO state (type,
 * state, id, submenu, check bitmaps, data, text). TrackPopupMenu(Ex) shows a real popup: a top-most, non-activating
 * window of the private class "#32768" drawn with the system colours (check marks, default item in bold, disabled
 * text, separators, submenu arrows, the accelerator text after '\t' right-aligned), and runs the menu loop with the mouse
 * captured: hover highlights (WM_MENUSELECT), a click or Enter chooses, Escape / a click outside cancels, arrow keys move
 * through the enabled items and in/out of submenus, a mnemonic (&x) chooses directly. The owner gets WM_ENTERMENULOOP,
 * WM_INITMENUPOPUP, WM_MENUSELECT, WM_UNINITMENUPOPUP, WM_EXITMENULOOP and, unless TPM_NONOTIFY / TPM_RETURNCMD,
 * WM_COMMAND (WM_SYSCOMMAND for the window menu). GetSystemMenu builds the classic window menu.
 *
 * Gap: menu BARS are not drawn by the non-client painter (SetMenu/GetMenu keep the association and DrawMenuBar succeeds,
 * but the client area is not reduced and no bar appears).
 */
#include "user32_int.h"

HMENU WINAPI CreatePopupMenu(void);

typedef struct {
    UINT type, state, id;
    HMENU sub;
    HBITMAP bmp_checked, bmp_unchecked, bmp_item;
    ULONG_PTR data;
    WCHAR *text;
} mitem_t;

typedef struct {
    int used, popup;
    unsigned gen;
    mitem_t *items;
    int n, cap;
    DWORD style, help, max_height;
    HBRUSH back;
    ULONG_PTR data;
    HWND sys_owner;                             /* GetSystemMenu: the window it belongs to */
} menu_t;

#define NMENUS 512
static menu_t g_menus[NMENUS];
static unsigned g_menu_gen;
static CRITICAL_SECTION g_mlock;
static volatile LONG g_mlock_init;

static void mlock(void)
{
    if (InterlockedCompareExchange(&g_mlock_init, 1, 0) == 0) { InitializeCriticalSection(&g_mlock); g_mlock_init = 2; }
    while (g_mlock_init != 2) Sleep(0);
    EnterCriticalSection(&g_mlock);
}
static void munlock(void) { LeaveCriticalSection(&g_mlock); }

static HMENU mhandle(int i) { return (HMENU)(uintptr_t)(((uintptr_t)g_menus[i].gen << 12) | 0x3000000u | (unsigned)i); }
static menu_t *mget(HMENU h)
{
    const uintptr_t v = (uintptr_t)h;
    const int i = (int)(v & 0xfff);
    if ((v & 0x3000000u) != 0x3000000u || i >= NMENUS || !g_menus[i].used || mhandle(i) != h) return 0;
    return &g_menus[i];
}

int u32_menu_count(void)
{
    int i, n = 0;
    for (i = 0; i < NMENUS; ++i) n += g_menus[i].used;
    return n;
}

static HMENU menu_new(int popup)
{
    int i;
    HMENU h = 0;
    mlock();
    for (i = 0; i < NMENUS; ++i)
        if (!g_menus[i].used) {
            memset(&g_menus[i], 0, sizeof g_menus[i]);
            g_menus[i].used = 1;
            g_menus[i].popup = popup;
            g_menus[i].gen = (++g_menu_gen) & 0xfff;
            h = mhandle(i);
            break;
        }
    munlock();
    if (!h) SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return h;
}

DLLAPI HMENU WINAPI CreateMenu(void) { return menu_new(0); }
DLLAPI HMENU WINAPI CreatePopupMenu(void) { return menu_new(1); }
DLLAPI BOOL WINAPI IsMenu(HMENU h) { BOOL r; mlock(); r = mget(h) != 0; munlock(); return r; }

static WCHAR *wdup(LPCWSTR s)
{
    size_t n;
    WCHAR *d;
    if (!s) return 0;
    n = wcslen(s);
    d = HeapAlloc(GetProcessHeap(), 0, (n + 1) * 2);
    if (d) memcpy(d, s, (n + 1) * 2);
    return d;
}

static void item_free(mitem_t *it) { if (it->text) HeapFree(GetProcessHeap(), 0, it->text); it->text = 0; }

DLLAPI BOOL WINAPI DestroyMenu(HMENU h)
{
    menu_t *m;
    int i;
    HMENU subs[256];
    int ns = 0;
    mlock();
    m = mget(h);
    if (!m) { munlock(); SetLastError(ERROR_INVALID_MENU_HANDLE); return FALSE; }
    for (i = 0; i < m->n; ++i) {
        if (m->items[i].sub && ns < 256) subs[ns++] = m->items[i].sub;
        item_free(&m->items[i]);
    }
    if (m->items) HeapFree(GetProcessHeap(), 0, m->items);
    memset(m, 0, sizeof *m);
    munlock();
    for (i = 0; i < ns; ++i) DestroyMenu(subs[i]);                      /* submenus go with their parent */
    return TRUE;
}

/* position of an item: by command id (searching submenus: *owner gets the menu that holds it) or by position */
static int find_item(HMENU h, UINT item, BOOL bypos, menu_t **owner)
{
    menu_t *m = mget(h);
    int i;
    if (!m) return -1;
    if (bypos) { *owner = m; return item < (UINT)m->n ? (int)item : -1; }
    for (i = 0; i < m->n; ++i)
        if (!m->items[i].sub && m->items[i].id == item) { *owner = m; return i; }
    for (i = 0; i < m->n; ++i)
        if (m->items[i].sub) {
            const int r = find_item(m->items[i].sub, item, FALSE, owner);
            if (r >= 0) return r;
        }
    for (i = 0; i < m->n; ++i)                                          /* a submenu item addressed by its id */
        if (m->items[i].sub && m->items[i].id == item) { *owner = m; return i; }
    return -1;
}

static int insert_at(menu_t *m, int pos)
{
    if (m->n == m->cap) {
        const int nc = m->cap ? m->cap * 2 : 8;
        mitem_t *ni = m->items ? HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, m->items, (size_t)nc * sizeof *ni)
                               : HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size_t)nc * sizeof *ni);
        if (!ni) return -1;
        m->items = ni;
        m->cap = nc;
    }
    if (pos < 0 || pos > m->n) pos = m->n;
    memmove(&m->items[pos + 1], &m->items[pos], (size_t)(m->n - pos) * sizeof *m->items);
    memset(&m->items[pos], 0, sizeof *m->items);
    ++m->n;
    return pos;
}

static void apply_info(mitem_t *it, const MENUITEMINFOW *mi)
{
    if (mi->fMask & MIIM_FTYPE) it->type = mi->fType & ~(MFT_STRING);
    if (mi->fMask & MIIM_TYPE) {                                        /* the old combined form */
        it->type = mi->fType & ~(MFT_STRING);
        if (!(mi->fType & (MFT_BITMAP | MFT_SEPARATOR | MFT_OWNERDRAW))) { item_free(it); it->text = wdup(mi->dwTypeData); }
    }
    if (mi->fMask & MIIM_STRING) { item_free(it); it->text = wdup(mi->dwTypeData); }
    if (mi->fMask & MIIM_STATE) it->state = mi->fState;
    if (mi->fMask & MIIM_ID) it->id = mi->wID;
    if (mi->fMask & MIIM_SUBMENU) it->sub = mi->hSubMenu;
    if (mi->fMask & MIIM_CHECKMARKS) { it->bmp_checked = mi->hbmpChecked; it->bmp_unchecked = mi->hbmpUnchecked; }
    if (mi->fMask & MIIM_DATA) it->data = mi->dwItemData;
    if (mi->fMask & MIIM_BITMAP) it->bmp_item = mi->hbmpItem;
}

DLLAPI BOOL WINAPI InsertMenuItemW(HMENU h, UINT item, BOOL bypos, LPCMENUITEMINFOW mi)
{
    menu_t *m, *owner = 0;
    int pos;
    if (!mi || (mi->cbSize != sizeof *mi && mi->cbSize != offsetof(MENUITEMINFOW, hbmpItem))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    mlock();
    m = mget(h);
    if (!m) { munlock(); SetLastError(ERROR_INVALID_MENU_HANDLE); return FALSE; }
    if (bypos) pos = item == (UINT)-1 ? m->n : (int)item;
    else { pos = find_item(h, item, FALSE, &owner); if (pos < 0 || owner != m) pos = m->n; }
    pos = insert_at(m, pos);
    if (pos < 0) { munlock(); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    apply_info(&m->items[pos], mi);
    munlock();
    return TRUE;
}

DLLAPI BOOL WINAPI SetMenuItemInfoW(HMENU h, UINT item, BOOL bypos, LPCMENUITEMINFOW mi)
{
    menu_t *owner = 0;
    int pos;
    if (!mi || (mi->cbSize != sizeof *mi && mi->cbSize != offsetof(MENUITEMINFOW, hbmpItem))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    mlock();
    pos = find_item(h, item, bypos, &owner);
    if (pos < 0) { munlock(); SetLastError(ERROR_MENU_ITEM_NOT_FOUND); return FALSE; }
    apply_info(&owner->items[pos], mi);
    munlock();
    return TRUE;
}

DLLAPI BOOL WINAPI GetMenuItemInfoW(HMENU h, UINT item, BOOL bypos, LPMENUITEMINFOW mi)
{
    menu_t *owner = 0;
    mitem_t *it;
    int pos;
    if (!mi || (mi->cbSize != sizeof *mi && mi->cbSize != offsetof(MENUITEMINFOW, hbmpItem))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    mlock();
    pos = find_item(h, item, bypos, &owner);
    if (pos < 0) { munlock(); SetLastError(ERROR_MENU_ITEM_NOT_FOUND); return FALSE; }
    it = &owner->items[pos];
    if (mi->fMask & (MIIM_FTYPE | MIIM_TYPE)) mi->fType = it->type | (it->text && !(it->type & (MFT_BITMAP | MFT_SEPARATOR)) ? MFT_STRING : 0);
    if (mi->fMask & (MIIM_STRING | MIIM_TYPE)) {
        const UINT len = it->text ? (UINT)wcslen(it->text) : 0;
        if (mi->dwTypeData && mi->cch) {
            const UINT n = len < mi->cch - 1 ? len : mi->cch - 1;
            if (n) memcpy(mi->dwTypeData, it->text, n * 2);
            mi->dwTypeData[n] = 0;
            mi->cch = n;
        } else {
            mi->cch = len;
        }
    }
    if (mi->fMask & MIIM_STATE) mi->fState = it->state;
    if (mi->fMask & MIIM_ID) mi->wID = it->id;
    if (mi->fMask & MIIM_SUBMENU) mi->hSubMenu = it->sub;
    if (mi->fMask & MIIM_CHECKMARKS) { mi->hbmpChecked = it->bmp_checked; mi->hbmpUnchecked = it->bmp_unchecked; }
    if (mi->fMask & MIIM_DATA) mi->dwItemData = it->data;
    if ((mi->fMask & MIIM_BITMAP) && mi->cbSize == sizeof *mi) mi->hbmpItem = it->bmp_item;
    munlock();
    return TRUE;
}

/* MF_* flags of the classic calls -> MENUITEMINFO */
static void flags_to_info(MENUITEMINFOW *mi, UINT flags, UINT_PTR id, LPCWSTR data)
{
    memset(mi, 0, sizeof *mi);
    mi->cbSize = sizeof *mi;
    mi->fMask = MIIM_FTYPE | MIIM_STATE | MIIM_ID;
    mi->fType = flags & (MFT_SEPARATOR | MFT_MENUBARBREAK | MFT_MENUBREAK | MFT_RADIOCHECK | MFT_RIGHTJUSTIFY | MFT_RIGHTORDER | MFT_OWNERDRAW);
    mi->fState = flags & (MFS_GRAYED | MFS_DISABLED | MFS_CHECKED | MFS_HILITE | MFS_DEFAULT);
    if (flags & MF_POPUP) { mi->fMask |= MIIM_SUBMENU; mi->hSubMenu = (HMENU)id; mi->wID = (UINT)id; }
    else mi->wID = (UINT)id;
    if (flags & MF_BITMAP) { mi->fMask |= MIIM_BITMAP; mi->hbmpItem = (HBITMAP)data; }
    else if (flags & MF_OWNERDRAW) { mi->fMask |= MIIM_DATA; mi->dwItemData = (ULONG_PTR)data; }
    else if (!(flags & MF_SEPARATOR)) { mi->fMask |= MIIM_STRING; mi->dwTypeData = (LPWSTR)data; }
}

DLLAPI BOOL WINAPI InsertMenuW(HMENU h, UINT pos, UINT flags, UINT_PTR id, LPCWSTR text)
{
    MENUITEMINFOW mi;
    flags_to_info(&mi, flags, id, text);
    return InsertMenuItemW(h, pos, (flags & MF_BYPOSITION) != 0, &mi);
}

DLLAPI BOOL WINAPI AppendMenuW(HMENU h, UINT flags, UINT_PTR id, LPCWSTR text) { return InsertMenuW(h, (UINT)-1, flags | MF_BYPOSITION, id, text); }

DLLAPI BOOL WINAPI ModifyMenuW(HMENU h, UINT pos, UINT flags, UINT_PTR id, LPCWSTR text)
{
    MENUITEMINFOW mi;
    flags_to_info(&mi, flags, id, text);
    if (!(flags & (MF_BITMAP | MF_OWNERDRAW | MF_SEPARATOR))) mi.fMask |= MIIM_STRING;
    return SetMenuItemInfoW(h, pos, (flags & MF_BYPOSITION) != 0, &mi);
}

static BOOL remove_item(HMENU h, UINT pos, UINT flags, int destroy_sub)
{
    menu_t *owner = 0;
    HMENU sub = 0;
    int i;
    mlock();
    i = find_item(h, pos, (flags & MF_BYPOSITION) != 0, &owner);
    if (i < 0) { munlock(); SetLastError(ERROR_MENU_ITEM_NOT_FOUND); return FALSE; }
    sub = owner->items[i].sub;
    item_free(&owner->items[i]);
    memmove(&owner->items[i], &owner->items[i + 1], (size_t)(owner->n - i - 1) * sizeof *owner->items);
    --owner->n;
    munlock();
    if (destroy_sub && sub) DestroyMenu(sub);
    return TRUE;
}

DLLAPI BOOL WINAPI RemoveMenu(HMENU h, UINT pos, UINT flags) { return remove_item(h, pos, flags, 0); }
DLLAPI BOOL WINAPI DeleteMenu(HMENU h, UINT pos, UINT flags) { return remove_item(h, pos, flags, 1); }

DLLAPI int WINAPI GetMenuItemCount(HMENU h)
{
    menu_t *m;
    int n;
    mlock();
    m = mget(h);
    n = m ? m->n : -1;
    munlock();
    if (n < 0) SetLastError(ERROR_INVALID_MENU_HANDLE);
    return n;
}

DLLAPI UINT WINAPI GetMenuItemID(HMENU h, int pos)
{
    menu_t *m;
    UINT id = (UINT)-1;
    mlock();
    m = mget(h);
    if (m && pos >= 0 && pos < m->n && !m->items[pos].sub) id = m->items[pos].id;
    munlock();
    return id;
}

DLLAPI HMENU WINAPI GetSubMenu(HMENU h, int pos)
{
    menu_t *m;
    HMENU s = 0;
    mlock();
    m = mget(h);
    if (m && pos >= 0 && pos < m->n) s = m->items[pos].sub;
    munlock();
    return s;
}

DLLAPI UINT WINAPI GetMenuState(HMENU h, UINT item, UINT flags)
{
    menu_t *owner = 0;
    int i;
    UINT r;
    mlock();
    i = find_item(h, item, (flags & MF_BYPOSITION) != 0, &owner);
    if (i < 0) { munlock(); return (UINT)-1; }
    r = owner->items[i].state | owner->items[i].type;
    if (owner->items[i].sub) { menu_t *s = mget(owner->items[i].sub); r = (r & 0xff) | MF_POPUP | ((UINT)(s ? s->n : 0) << 8); }
    munlock();
    return r;
}

DLLAPI int WINAPI GetMenuStringW(HMENU h, UINT item, LPWSTR buf, int cap, UINT flags)
{
    MENUITEMINFOW mi;
    memset(&mi, 0, sizeof mi);
    mi.cbSize = sizeof mi;
    mi.fMask = MIIM_STRING;
    mi.dwTypeData = buf;
    mi.cch = buf ? (UINT)cap : 0;
    if (!GetMenuItemInfoW(h, item, (flags & MF_BYPOSITION) != 0, &mi)) return 0;
    return (int)mi.cch;
}

static UINT change_state(HMENU h, UINT item, UINT flags, UINT clear, UINT set)
{
    menu_t *owner = 0;
    int i;
    UINT old;
    mlock();
    i = find_item(h, item, (flags & MF_BYPOSITION) != 0, &owner);
    if (i < 0) { munlock(); return (UINT)-1; }
    old = owner->items[i].state;
    owner->items[i].state = (old & ~clear) | set;
    munlock();
    return old;
}

DLLAPI BOOL WINAPI EnableMenuItem(HMENU h, UINT item, UINT flags)
{
    const UINT old = change_state(h, item, flags, MFS_GRAYED | MFS_DISABLED, flags & (MF_GRAYED | MF_DISABLED));
    return old == (UINT)-1 ? -1 : (BOOL)(old & (MF_GRAYED | MF_DISABLED));
}

DLLAPI DWORD WINAPI CheckMenuItem(HMENU h, UINT item, UINT flags)
{
    const UINT old = change_state(h, item, flags, MFS_CHECKED, flags & MF_CHECKED);
    return old == (UINT)-1 ? (DWORD)-1 : (old & MF_CHECKED);
}

DLLAPI BOOL WINAPI HiliteMenuItem(HWND hwnd, HMENU h, UINT item, UINT flags)
{
    (void)hwnd;
    return change_state(h, item, flags, MFS_HILITE, flags & MF_HILITE) != (UINT)-1;
}

DLLAPI BOOL WINAPI CheckMenuRadioItem(HMENU h, UINT first, UINT last, UINT check, UINT flags)
{
    menu_t *m;
    int i, lo, hi, found = 0;
    mlock();
    m = mget(h);
    if (!m) { munlock(); return FALSE; }
    if (flags & MF_BYPOSITION) { lo = (int)first; hi = (int)last; }
    else {
        lo = hi = -1;
        for (i = 0; i < m->n; ++i) { if (m->items[i].id == first) lo = i; if (m->items[i].id == last) hi = i; }
    }
    if (lo < 0 || hi < lo || hi >= m->n) { munlock(); return FALSE; }
    for (i = lo; i <= hi; ++i) {
        const int on = (flags & MF_BYPOSITION) ? (UINT)i == check : m->items[i].id == check;
        if (on) { m->items[i].state |= MFS_CHECKED; m->items[i].type |= MFT_RADIOCHECK; found = 1; }
        else m->items[i].state &= ~MFS_CHECKED;
    }
    munlock();
    return found;
}

DLLAPI BOOL WINAPI SetMenuDefaultItem(HMENU h, UINT item, UINT bypos)
{
    menu_t *m;
    int i, k = -1;
    mlock();
    m = mget(h);
    if (!m) { munlock(); SetLastError(ERROR_INVALID_MENU_HANDLE); return FALSE; }
    if (item != (UINT)-1) {
        if (bypos) k = item < (UINT)m->n ? (int)item : -1;
        else for (i = 0; i < m->n; ++i) if (m->items[i].id == item) k = i;
        if (k < 0) { munlock(); SetLastError(ERROR_MENU_ITEM_NOT_FOUND); return FALSE; }
    }
    for (i = 0; i < m->n; ++i) { if (i == k) m->items[i].state |= MFS_DEFAULT; else m->items[i].state &= ~MFS_DEFAULT; }
    munlock();
    return TRUE;
}

DLLAPI UINT WINAPI GetMenuDefaultItem(HMENU h, UINT bypos, UINT flags)
{
    menu_t *m;
    int i;
    UINT r = (UINT)-1;
    mlock();
    m = mget(h);
    if (m)
        for (i = 0; i < m->n; ++i)
            if (m->items[i].state & MFS_DEFAULT) {
                if (!(flags & GMDI_USEDISABLED) && (m->items[i].state & (MFS_GRAYED | MFS_DISABLED))) break;
                r = bypos ? (UINT)i : m->items[i].id;
                break;
            }
    munlock();
    return r;
}

DLLAPI BOOL WINAPI GetMenuInfo(HMENU h, LPMENUINFO mi)
{
    menu_t *m;
    if (!mi || mi->cbSize != sizeof *mi) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    mlock();
    m = mget(h);
    if (!m) { munlock(); SetLastError(ERROR_INVALID_MENU_HANDLE); return FALSE; }
    if (mi->fMask & MIM_STYLE) mi->dwStyle = m->style;
    if (mi->fMask & MIM_MAXHEIGHT) mi->cyMax = m->max_height;
    if (mi->fMask & MIM_BACKGROUND) mi->hbrBack = m->back;
    if (mi->fMask & MIM_HELPID) mi->dwContextHelpID = m->help;
    if (mi->fMask & MIM_MENUDATA) mi->dwMenuData = m->data;
    munlock();
    return TRUE;
}

DLLAPI BOOL WINAPI SetMenuInfo(HMENU h, LPCMENUINFO mi)
{
    menu_t *m;
    int i;
    HMENU subs[256];
    int ns = 0;
    if (!mi || mi->cbSize != sizeof *mi) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    mlock();
    m = mget(h);
    if (!m) { munlock(); SetLastError(ERROR_INVALID_MENU_HANDLE); return FALSE; }
    if (mi->fMask & MIM_STYLE) m->style = mi->dwStyle;
    if (mi->fMask & MIM_MAXHEIGHT) m->max_height = mi->cyMax;
    if (mi->fMask & MIM_BACKGROUND) m->back = mi->hbrBack;
    if (mi->fMask & MIM_HELPID) m->help = mi->dwContextHelpID;
    if (mi->fMask & MIM_MENUDATA) m->data = mi->dwMenuData;
    if (mi->fMask & MIM_APPLYTOSUBMENUS) for (i = 0; i < m->n; ++i) if (m->items[i].sub && ns < 256) subs[ns++] = m->items[i].sub;
    munlock();
    for (i = 0; i < ns; ++i) SetMenuInfo(subs[i], mi);
    return TRUE;
}

DLLAPI BOOL WINAPI SetMenuItemBitmaps(HMENU h, UINT item, UINT flags, HBITMAP unchecked, HBITMAP checked)
{
    MENUITEMINFOW mi;
    memset(&mi, 0, sizeof mi);
    mi.cbSize = sizeof mi;
    mi.fMask = MIIM_CHECKMARKS;
    mi.hbmpChecked = checked;
    mi.hbmpUnchecked = unchecked;
    return SetMenuItemInfoW(h, item, (flags & MF_BYPOSITION) != 0, &mi);
}

DLLAPI LONG WINAPI GetMenuCheckMarkDimensions(void) { return MAKELONG(u32_metric(SM_CXMENUCHECK), u32_metric(SM_CYMENUCHECK)); }
DLLAPI DWORD WINAPI GetMenuContextHelpId(HMENU h) { MENUINFO mi; mi.cbSize = sizeof mi; mi.fMask = MIM_HELPID; return GetMenuInfo(h, &mi) ? mi.dwContextHelpID : 0; }
DLLAPI BOOL WINAPI SetMenuContextHelpId(HMENU h, DWORD id) { MENUINFO mi; mi.cbSize = sizeof mi; mi.fMask = MIM_HELPID; mi.dwContextHelpID = id; return SetMenuInfo(h, &mi); }

/* ---- A variants ---- */
static WCHAR *a2w(LPCSTR s)
{
    int n;
    WCHAR *w;
    if (!s) return 0;
    n = MultiByteToWideChar(CP_ACP, 0, s, -1, 0, 0);
    w = HeapAlloc(GetProcessHeap(), 0, (size_t)(n > 0 ? n : 1) * 2);
    if (w) MultiByteToWideChar(CP_ACP, 0, s, -1, w, n);
    return w;
}

DLLAPI BOOL WINAPI AppendMenuA(HMENU h, UINT flags, UINT_PTR id, LPCSTR text)
{
    WCHAR *w = (flags & (MF_BITMAP | MF_OWNERDRAW | MF_SEPARATOR)) ? 0 : a2w(text);
    const BOOL r = AppendMenuW(h, flags, id, w ? w : (LPCWSTR)text);
    if (w) HeapFree(GetProcessHeap(), 0, w);
    return r;
}
DLLAPI BOOL WINAPI InsertMenuA(HMENU h, UINT pos, UINT flags, UINT_PTR id, LPCSTR text)
{
    WCHAR *w = (flags & (MF_BITMAP | MF_OWNERDRAW | MF_SEPARATOR)) ? 0 : a2w(text);
    const BOOL r = InsertMenuW(h, pos, flags, id, w ? w : (LPCWSTR)text);
    if (w) HeapFree(GetProcessHeap(), 0, w);
    return r;
}
DLLAPI BOOL WINAPI InsertMenuItemA(HMENU h, UINT item, BOOL bypos, LPCMENUITEMINFOA mi)
{
    MENUITEMINFOW w;
    WCHAR *t = 0;
    BOOL r;
    if (!mi) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memcpy(&w, mi, sizeof w < mi->cbSize ? sizeof w : mi->cbSize);
    w.cbSize = mi->cbSize == sizeof *mi ? sizeof w : offsetof(MENUITEMINFOW, hbmpItem);
    if ((mi->fMask & MIIM_STRING) || ((mi->fMask & MIIM_TYPE) && !(mi->fType & (MFT_BITMAP | MFT_SEPARATOR | MFT_OWNERDRAW)))) {
        t = a2w(mi->dwTypeData);
        w.dwTypeData = t;
    }
    r = InsertMenuItemW(h, item, bypos, &w);
    if (t) HeapFree(GetProcessHeap(), 0, t);
    return r;
}
DLLAPI BOOL WINAPI SetMenuItemInfoA(HMENU h, UINT item, BOOL bypos, LPCMENUITEMINFOA mi)
{
    MENUITEMINFOW w;
    WCHAR *t = 0;
    BOOL r;
    if (!mi) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memcpy(&w, mi, sizeof w < mi->cbSize ? sizeof w : mi->cbSize);
    w.cbSize = mi->cbSize == sizeof *mi ? sizeof w : offsetof(MENUITEMINFOW, hbmpItem);
    if ((mi->fMask & MIIM_STRING) || ((mi->fMask & MIIM_TYPE) && !(mi->fType & (MFT_BITMAP | MFT_SEPARATOR | MFT_OWNERDRAW)))) {
        t = a2w(mi->dwTypeData);
        w.dwTypeData = t;
    }
    r = SetMenuItemInfoW(h, item, bypos, &w);
    if (t) HeapFree(GetProcessHeap(), 0, t);
    return r;
}

/* ---------------------------------------------------------------- window menus */
#define PROP_MENU L"ShzMenu"
#define PROP_SYSMENU L"ShzSysMenu"

DLLAPI BOOL WINAPI SetMenu(HWND hwnd, HMENU h)
{
    if (!IsWindow(hwnd) || (GetWindowLongW(hwnd, GWL_STYLE) & WS_CHILD)) { SetLastError(ERROR_INVALID_WINDOW_HANDLE); return FALSE; }
    if (h && !IsMenu(h)) { SetLastError(ERROR_INVALID_MENU_HANDLE); return FALSE; }
    if (h) return SetPropW(hwnd, PROP_MENU, (HANDLE)h);
    RemovePropW(hwnd, PROP_MENU);
    return TRUE;
}
DLLAPI HMENU WINAPI GetMenu(HWND hwnd)
{
    if (GetWindowLongW(hwnd, GWL_STYLE) & WS_CHILD) return 0;
    return (HMENU)GetPropW(hwnd, PROP_MENU);
}
DLLAPI BOOL WINAPI DrawMenuBar(HWND hwnd) { return IsWindow(hwnd); }   /* menu bars are not drawn (see the top of this file) */

DLLAPI HMENU WINAPI GetSystemMenu(HWND hwnd, BOOL revert)
{
    HMENU m = (HMENU)GetPropW(hwnd, PROP_SYSMENU);
    DWORD style;
    if (!IsWindow(hwnd)) return 0;
    if (revert) {                                                       /* back to the default: drop the copy */
        if (m) { RemovePropW(hwnd, PROP_SYSMENU); DestroyMenu(m); }
        return 0;
    }
    if (m && IsMenu(m)) return m;
    style = (DWORD)GetWindowLongW(hwnd, GWL_STYLE);
    m = CreatePopupMenu();
    if (!m) return 0;
    AppendMenuW(m, MF_STRING | ((style & (WS_MAXIMIZE | WS_MINIMIZE)) ? 0 : MF_GRAYED), SC_RESTORE, L"&Restore");
    AppendMenuW(m, MF_STRING | ((style & WS_MAXIMIZE) ? MF_GRAYED : 0), SC_MOVE, L"&Move");
    AppendMenuW(m, MF_STRING | ((style & WS_THICKFRAME) && !(style & WS_MAXIMIZE) ? 0 : MF_GRAYED), SC_SIZE, L"&Size");
    AppendMenuW(m, MF_STRING | ((style & WS_MINIMIZEBOX) ? 0 : MF_GRAYED), SC_MINIMIZE, L"Mi&nimize");
    AppendMenuW(m, MF_STRING | ((style & WS_MAXIMIZEBOX) && !(style & WS_MAXIMIZE) ? 0 : MF_GRAYED), SC_MAXIMIZE, L"Ma&ximize");
    AppendMenuW(m, MF_SEPARATOR, 0, 0);
    AppendMenuW(m, MF_STRING, SC_CLOSE, L"&Close\tAlt+F4");
    SetMenuDefaultItem(m, SC_CLOSE, FALSE);
    mlock();
    { menu_t *mm = mget(m); if (mm) mm->sys_owner = hwnd; }
    munlock();
    SetPropW(hwnd, PROP_SYSMENU, (HANDLE)m);
    return m;
}

/* ---------------------------------------------------------------- the popup */
#define ITEM_H 20
#define SEP_H 8
#define MARGIN 22                                   /* check-mark column and the space for the submenu arrow */
static const WCHAR k_menu_class[] = L"#32768";

typedef struct {
    HMENU menu;
    HWND hwnd, owner;
    int sel;                                        /* highlighted item or -1 */
    int x, y, w, h;
    int is_sys;
} popup_t;

static int text_width(LPCWSTR s, int n) { int i, w = 0; for (i = 0; i < n; ++i) if (s[i] != '&' || (i + 1 < n && s[i + 1] == '&')) w += 8; return w; }

static void measure(HMENU h, int *w, int *hh)
{
    menu_t *m;
    int i, maxl = 0, maxr = 0, y = 2;
    mlock();
    m = mget(h);
    for (i = 0; m && i < m->n; ++i) {
        const mitem_t *it = &m->items[i];
        if (it->type & MFT_SEPARATOR) { y += SEP_H; continue; }
        if (it->text) {
            const WCHAR *tab = it->text;
            int l;
            while (*tab && *tab != '\t') ++tab;
            l = text_width(it->text, (int)(tab - it->text));
            if (l > maxl) maxl = l;
            if (*tab) { l = text_width(tab + 1, (int)wcslen(tab + 1)); if (l > maxr) maxr = l; }
        }
        y += ITEM_H;
    }
    munlock();
    *w = MARGIN + maxl + (maxr ? 24 + maxr : 0) + MARGIN + 4;
    if (*w < 80) *w = 80;
    *hh = y + 2;
}

static int item_at(HMENU h, int py, int *top)
{
    menu_t *m;
    int i, y = 2, r = -1;
    mlock();
    m = mget(h);
    for (i = 0; m && i < m->n; ++i) {
        const int ih = (m->items[i].type & MFT_SEPARATOR) ? SEP_H : ITEM_H;
        if (py >= y && py < y + ih) { r = i; if (top) *top = y; break; }
        y += ih;
    }
    munlock();
    return r;
}

static void draw_text_mn(HDC dc, int x, int y, LPCWSTR s, int n, COLORREF c)
{
    WCHAR buf[256];
    int i, k = 0, ul = -1;
    for (i = 0; i < n && k < 255; ++i) {
        if (s[i] == '&' && i + 1 < n) { if (s[i + 1] == '&') { buf[k++] = '&'; ++i; } else ul = k; continue; }
        buf[k++] = s[i];
    }
    SetTextColor(dc, c);
    TextOutW(dc, x, y, buf, k);
    if (ul >= 0) {                                                      /* the mnemonic is underlined */
        HPEN p = CreatePen(PS_SOLID, 1, c), o = SelectObject(dc, p);
        MoveToEx(dc, x + ul * 8, y + 15, 0);
        LineTo(dc, x + ul * 8 + 8, y + 15);
        SelectObject(dc, o);
        DeleteObject(p);
    }
}

static void paint_popup(HWND hwnd, popup_t *p)
{
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(hwnd, &ps);
    menu_t *m;
    RECT rc;
    int i, y = 2;
    GetClientRect(hwnd, &rc);
    FillRect(dc, &rc, GetSysColorBrush(COLOR_MENU));
    SetBkMode(dc, TRANSPARENT);
    mlock();
    m = mget(p->menu);
    for (i = 0; m && i < m->n; ++i) {
        const mitem_t *it = &m->items[i];
        const int dis = (it->state & (MFS_GRAYED | MFS_DISABLED)) != 0, hi = i == p->sel && !(it->type & MFT_SEPARATOR);
        RECT r;
        if (it->type & MFT_SEPARATOR) {
            r.left = 2; r.right = rc.right - 2; r.top = y + SEP_H / 2 - 1; r.bottom = r.top + 1;
            FillRect(dc, &r, GetSysColorBrush(COLOR_BTNSHADOW));
            OffsetRect(&r, 0, 1);
            FillRect(dc, &r, GetSysColorBrush(COLOR_BTNHIGHLIGHT));
            y += SEP_H;
            continue;
        }
        r.left = 2; r.right = rc.right - 2; r.top = y; r.bottom = y + ITEM_H;
        if (hi) FillRect(dc, &r, GetSysColorBrush(COLOR_HIGHLIGHT));
        {
            const COLORREF tc = dis ? GetSysColor(COLOR_GRAYTEXT) : hi ? GetSysColor(COLOR_HIGHLIGHTTEXT) : GetSysColor(COLOR_MENUTEXT);
            HFONT f = 0, of = 0;
            if (it->state & MFS_DEFAULT) {
                LOGFONTW lf;
                memset(&lf, 0, sizeof lf);
                lf.lfHeight = -16; lf.lfWeight = FW_BOLD;
                f = CreateFontIndirectW(&lf);
                of = SelectObject(dc, f);
            }
            if (it->state & MFS_CHECKED) {                              /* a check mark or a radio bullet */
                HBRUSH b = CreateSolidBrush(tc);
                RECT c;
                if (it->type & MFT_RADIOCHECK) { c.left = 8; c.top = y + 7; c.right = 14; c.bottom = y + 13; FillRect(dc, &c, b); }
                else {
                    int k;
                    for (k = 0; k < 3; ++k) { c.left = 6 + k; c.top = y + 9 + k; c.right = c.left + 1; c.bottom = c.top + 2; FillRect(dc, &c, b); }
                    for (k = 0; k < 5; ++k) { c.left = 9 + k; c.top = y + 10 - k; c.right = c.left + 1; c.bottom = c.top + 2; FillRect(dc, &c, b); }
                }
                DeleteObject(b);
            }
            if (it->text) {
                const WCHAR *tab = it->text;
                while (*tab && *tab != '\t') ++tab;
                draw_text_mn(dc, MARGIN, y + 2, it->text, (int)(tab - it->text), tc);
                if (*tab) {
                    const int n = (int)wcslen(tab + 1);
                    draw_text_mn(dc, rc.right - MARGIN - text_width(tab + 1, n), y + 2, tab + 1, n, tc);
                }
            }
            if (it->sub) {                                              /* the submenu arrow */
                HBRUSH b = CreateSolidBrush(tc);
                int k;
                for (k = 0; k < 4; ++k) { RECT c; c.left = rc.right - 12 + k; c.right = c.left + 1; c.top = y + 6 + k; c.bottom = y + 14 - k; FillRect(dc, &c, b); }
                DeleteObject(b);
            }
            if (f) { SelectObject(dc, of); DeleteObject(f); }
        }
        y += ITEM_H;
    }
    munlock();
    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK popup_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    popup_t *p = (popup_t *)GetWindowLongPtrW(hwnd, 0);
    switch (msg) {
    case WM_NCCREATE:
        SetWindowLongPtrW(hwnd, 0, (LONG_PTR)((CREATESTRUCTW *)lp)->lpCreateParams);
        return TRUE;
    case WM_PAINT: if (p) { paint_popup(hwnd, p); return 0; } break;
    case WM_ERASEBKGND: return 1;
    case WM_MOUSEACTIVATE: return MA_NOACTIVATE;
    case WM_SETCURSOR: SetCursor(LoadCursorW(0, (LPCWSTR)IDC_ARROW)); return TRUE;
    default: break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static int register_class(void)
{
    static volatile LONG done;
    WNDCLASSEXW wc;
    if (done) return 1;
    memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.style = CS_SAVEBITS | CS_DBLCLKS;
    wc.lpfnWndProc = popup_proc;
    wc.cbWndExtra = sizeof(void *);
    wc.lpszClassName = k_menu_class;
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return 0;
    done = 1;
    return 1;
}

static void select_item(popup_t *p, int i)
{
    UINT id = 0, flags = 0;
    menu_t *m;
    if (i == p->sel) return;
    p->sel = i;
    InvalidateRect(p->hwnd, 0, FALSE);
    mlock();
    m = mget(p->menu);
    if (m && i >= 0 && i < m->n) {
        id = m->items[i].sub ? (UINT)i : m->items[i].id;
        flags = m->items[i].state | m->items[i].type | (m->items[i].sub ? MF_POPUP : 0) | MF_HILITE;
    }
    munlock();
    if (i < 0) SendMessageW(p->owner, WM_MENUSELECT, MAKEWPARAM(0, 0xffff), 0);
    else SendMessageW(p->owner, WM_MENUSELECT, MAKEWPARAM(id, flags), (LPARAM)p->menu);
}

static int item_selectable(HMENU h, int i, HMENU *sub, UINT *id)
{
    menu_t *m;
    int ok = 0;
    mlock();
    m = mget(h);
    if (m && i >= 0 && i < m->n && !(m->items[i].type & MFT_SEPARATOR) && !(m->items[i].state & (MFS_GRAYED | MFS_DISABLED))) {
        ok = 1;
        if (sub) *sub = m->items[i].sub;
        if (id) *id = m->items[i].id;
    }
    munlock();
    return ok;
}

static int step(HMENU h, int from, int dir)
{
    const int n = GetMenuItemCount(h);
    int i, k;
    for (k = 1; k <= n; ++k) {
        i = ((from < 0 ? (dir > 0 ? -1 : 0) : from) + dir * k + n * 2) % n;
        if (item_selectable(h, i, 0, 0)) return i;
    }
    return -1;
}

static int mnemonic(HMENU h, WCHAR ch)
{
    menu_t *m;
    int i, r = -1;
    if (ch >= 'a' && ch <= 'z') ch = (WCHAR)(ch - 32);
    mlock();
    m = mget(h);
    for (i = 0; m && i < m->n && r < 0; ++i) {
        const WCHAR *t = m->items[i].text;
        for (; t && *t; ++t)
            if (t[0] == '&' && t[1] && t[1] != '&') {
                WCHAR c = t[1];
                if (c >= 'a' && c <= 'z') c = (WCHAR)(c - 32);
                if (c == ch) r = i;
                break;
            }
    }
    munlock();
    return r;
}

static int track(HMENU menu, UINT flags, int x, int y, HWND owner, int depth, int *cancel_all);

/* Runs one popup level. Returns the chosen command id, 0 when nothing was chosen (*cancel_all: close every level). */
static int track(HMENU menu, UINT flags, int x, int y, HWND owner, int depth, int *cancel_all)
{
    popup_t p;
    MSG msg;
    int result = 0, done = 0, sx = u32_metric(SM_CXSCREEN), sy = u32_metric(SM_CYSCREEN);
    memset(&p, 0, sizeof p);
    p.menu = menu;
    p.owner = owner;
    p.sel = -1;
    SendMessageW(owner, WM_INITMENUPOPUP, (WPARAM)menu, MAKELPARAM(0, 0));
    measure(menu, &p.w, &p.h);
    if (flags & TPM_RIGHTALIGN) x -= p.w; else if (flags & TPM_CENTERALIGN) x -= p.w / 2;
    if (flags & TPM_BOTTOMALIGN) y -= p.h; else if (flags & TPM_VCENTERALIGN) y -= p.h / 2;
    if (x + p.w > sx) x = sx - p.w;
    if (y + p.h > sy) y = sy - p.h;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    p.x = x; p.y = y;
    p.hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, k_menu_class, L"", WS_POPUP | WS_BORDER, x, y, p.w, p.h, owner, 0, 0, &p);
    if (!p.hwnd) return 0;
    ShowWindow(p.hwnd, SW_SHOWNA);
    UpdateWindow(p.hwnd);
    SetCapture(p.hwnd);
    while (!done) {
        const BOOL got = GetMessageW(&msg, 0, 0, 0);
        if (got <= 0) {                                                 /* WM_QUIT ends every menu; it is posted again */
            if (got == 0) PostQuitMessage((int)msg.wParam);
            *cancel_all = 1;
            break;
        }
        if (CallMsgFilterW(&msg, MSGF_MENU)) continue;
        switch (msg.message) {
        case WM_MOUSEMOVE: case WM_LBUTTONDOWN: case WM_LBUTTONUP: case WM_RBUTTONDOWN: case WM_RBUTTONUP:
        case WM_LBUTTONDBLCLK: case WM_NCMOUSEMOVE: case WM_NCLBUTTONDOWN: case WM_NCLBUTTONUP: case WM_NCRBUTTONDOWN: {
            const int inside = msg.pt.x >= p.x && msg.pt.x < p.x + p.w && msg.pt.y >= p.y && msg.pt.y < p.y + p.h;
            const int it = inside ? item_at(menu, msg.pt.y - p.y - 1, 0) : -1;
            if (msg.message == WM_MOUSEMOVE || msg.message == WM_NCMOUSEMOVE) {
                if (inside) select_item(&p, it >= 0 && item_selectable(menu, it, 0, 0) ? it : -1);
                break;
            }
            if (!inside) {
                if (msg.message == WM_LBUTTONDOWN || msg.message == WM_RBUTTONDOWN || msg.message == WM_NCLBUTTONDOWN || msg.message == WM_NCRBUTTONDOWN) {
                    *cancel_all = 1;
                    done = 1;
                }
                break;
            }
            if (msg.message == WM_LBUTTONUP || (msg.message == WM_RBUTTONUP && (flags & TPM_RIGHTBUTTON))) {
                HMENU sub = 0;
                UINT id = 0;
                if (it >= 0 && item_selectable(menu, it, &sub, &id)) {
                    if (sub) {
                        int top = 0;
                        item_at(menu, msg.pt.y - p.y - 1, &top);
                        result = track(sub, flags & ~(TPM_RIGHTALIGN | TPM_CENTERALIGN | TPM_BOTTOMALIGN | TPM_VCENTERALIGN), p.x + p.w - 4, p.y + top, owner, depth + 1, cancel_all);
                        if (result || *cancel_all) done = 1;
                        else SetCapture(p.hwnd);
                    } else {
                        result = (int)id;
                        done = 1;
                    }
                }
            }
            break;
        }
        case WM_KEYDOWN: case WM_SYSKEYDOWN:
            TranslateMessage(&msg);                                     /* the WM_CHAR of a mnemonic */
            switch (msg.wParam) {
            case VK_ESCAPE: done = 1; if (depth == 0) *cancel_all = 1; break;
            case VK_UP: select_item(&p, step(menu, p.sel, -1)); break;
            case VK_DOWN: select_item(&p, step(menu, p.sel, 1)); break;
            case VK_LEFT: if (depth > 0) done = 1; break;
            case VK_RIGHT: case VK_RETURN: {
                HMENU sub = 0;
                UINT id = 0;
                if (p.sel >= 0 && item_selectable(menu, p.sel, &sub, &id)) {
                    if (sub) {
                        int k, top = 2;
                        for (k = 0; k < p.sel; ++k) top += (GetMenuState(menu, (UINT)k, MF_BYPOSITION) & MF_SEPARATOR) ? SEP_H : ITEM_H;
                        result = track(sub, flags & ~(TPM_RIGHTALIGN | TPM_CENTERALIGN | TPM_BOTTOMALIGN | TPM_VCENTERALIGN), p.x + p.w - 4, p.y + top, owner, depth + 1, cancel_all);
                        if (result || *cancel_all) done = 1;
                        else SetCapture(p.hwnd);
                    } else if (msg.wParam == VK_RETURN) {
                        result = (int)id;
                        done = 1;
                    }
                }
                break;
            }
            case VK_MENU: case VK_F10: done = 1; *cancel_all = 1; break;
            default: break;
            }
            break;
        case WM_CHAR: case WM_SYSCHAR: {
            const int it = mnemonic(menu, (WCHAR)msg.wParam);
            HMENU sub = 0;
            UINT id = 0;
            if (it >= 0 && item_selectable(menu, it, &sub, &id) && !sub) { result = (int)id; done = 1; }
            else if (it >= 0) select_item(&p, it);
            break;
        }
        case WM_KEYUP: case WM_SYSKEYUP:
            break;
        default:
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            break;
        }
        if (GetCapture() != p.hwnd && !done) { *cancel_all = 1; done = 1; }   /* someone took the capture: the menu ends */
    }
    if (GetCapture() == p.hwnd) ReleaseCapture();
    SendMessageW(owner, WM_UNINITMENUPOPUP, (WPARAM)menu, 0);
    DestroyWindow(p.hwnd);
    return result;
}

DLLAPI BOOL WINAPI TrackPopupMenuEx(HMENU menu, UINT flags, int x, int y, HWND owner, LPTPMPARAMS tpm)
{
    int cancel = 0, id, is_sys = 0;
    (void)tpm;
    if (!IsMenu(menu)) { SetLastError(ERROR_INVALID_MENU_HANDLE); return FALSE; }
    if (!IsWindow(owner)) { SetLastError(ERROR_INVALID_WINDOW_HANDLE); return FALSE; }
    if (!register_class()) return FALSE;
    mlock();
    { menu_t *m = mget(menu); is_sys = m && m->sys_owner; }
    munlock();
    if (!(flags & TPM_NONOTIFY)) SendMessageW(owner, WM_ENTERMENULOOP, TRUE, 0);
    id = track(menu, flags, x, y, owner, 0, &cancel);
    if (!(flags & TPM_NONOTIFY)) SendMessageW(owner, WM_EXITMENULOOP, TRUE, 0);
    SendMessageW(owner, WM_MENUSELECT, MAKEWPARAM(0, 0xffff), 0);
    if (flags & TPM_RETURNCMD) return id;
    if (id && !(flags & TPM_NONOTIFY)) PostMessageW(owner, is_sys ? WM_SYSCOMMAND : WM_COMMAND, is_sys ? (WPARAM)id : MAKEWPARAM(id, 0), 0);
    return id != 0 || !cancel ? TRUE : FALSE;
}

DLLAPI BOOL WINAPI TrackPopupMenu(HMENU menu, UINT flags, int x, int y, int reserved, HWND owner, const RECT *rc)
{
    (void)reserved; (void)rc;
    return TrackPopupMenuEx(menu, flags, x, y, owner, 0);
}

DLLAPI BOOL WINAPI EndMenu(void)
{
    HWND cap = GetCapture();
    WCHAR cls[16];
    if (cap && GetClassNameW(cap, cls, 16) && !wcscmp(cls, k_menu_class)) { ReleaseCapture(); return TRUE; }   /* the loop sees the capture go */
    return FALSE;
}

/* ---------------------------------------------------------------- menu templates (RT_MENU) */
static const WORD *load_level(HMENU m, const WORD *p, const WORD *end, int ex)
{
    for (;;) {
        MENUITEMINFOW mi;
        const WCHAR *text;
        WORD flags;
        if (p >= end) return 0;
        memset(&mi, 0, sizeof mi);
        mi.cbSize = sizeof mi;
        if (!ex) {                                                      /* MENUITEMTEMPLATE */
            flags = *p++;
            if (!(flags & MF_POPUP)) mi.wID = *p++;
            text = (const WCHAR *)p;
            while (p < end && *p) ++p;
            ++p;
            mi.fMask = MIIM_FTYPE | MIIM_STATE | MIIM_ID | ((flags & MF_SEPARATOR) || (!text[0] && !(flags & MF_POPUP)) ? 0 : MIIM_STRING);
            mi.fType = (!text[0] && !(flags & MF_POPUP)) ? MFT_SEPARATOR : (flags & (MF_MENUBARBREAK | MF_MENUBREAK | MF_OWNERDRAW));
            mi.fState = flags & (MF_GRAYED | MF_DISABLED | MF_CHECKED | MF_HILITE | MFS_DEFAULT);
            mi.dwTypeData = (LPWSTR)text;
            if (flags & MF_POPUP) {
                HMENU sub = CreatePopupMenu();
                if (!sub) return 0;
                p = load_level(sub, p, end, 0);
                if (!p) { DestroyMenu(sub); return 0; }
                mi.fMask |= MIIM_SUBMENU;
                mi.hSubMenu = sub;
            }
            InsertMenuItemW(m, (UINT)-1, TRUE, &mi);
            if (flags & MF_END) return p;
        } else {                                                        /* MENUEX_TEMPLATE_ITEM */
            const DWORD *d = (const DWORD *)p;
            WORD res;
            if ((const WORD *)(d + 3) + 1 > end) return 0;
            mi.fType = d[0];
            mi.fState = d[1];
            mi.wID = d[2];
            res = *(const WORD *)(d + 3);
            text = (const WCHAR *)((const WORD *)(d + 3) + 1);
            p = (const WORD *)text;
            while (p < end && *p) ++p;
            ++p;
            p = (const WORD *)(((uintptr_t)p + 3) & ~(uintptr_t)3);   /* DWORD alignment */
            mi.fMask = MIIM_FTYPE | MIIM_STATE | MIIM_ID | (text[0] ? MIIM_STRING : 0);
            mi.dwTypeData = (LPWSTR)text;
            if (res & 1) {
                HMENU sub = CreatePopupMenu();
                if (!sub) return 0;
                p += 2;                                                 /* dwHelpId */
                p = load_level(sub, p, end, 1);
                if (!p) { DestroyMenu(sub); return 0; }
                mi.fMask |= MIIM_SUBMENU;
                mi.hSubMenu = sub;
            }
            InsertMenuItemW(m, (UINT)-1, TRUE, &mi);
            if (res & 0x80) return p;
        }
    }
}

static HMENU load_indirect(const void *tpl, DWORD size)
{
    const WORD *p = tpl, *end = (const WORD *)((const uint8_t *)tpl + (size ? size : 0x100000));
    HMENU m;
    int ex;
    if (!p) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    ex = p[0] == 1;
    if (p[0] > 1) { SetLastError(ERROR_INVALID_DATA); return 0; }
    m = CreateMenu();
    if (!m) return 0;
    p = (const WORD *)((const uint8_t *)(p + 2) + p[1]);                /* skip the header and its offset */
    if (!load_level(m, p, end, ex)) { DestroyMenu(m); SetLastError(ERROR_INVALID_DATA); return 0; }
    return m;
}

DLLAPI HMENU WINAPI LoadMenuIndirectW(const MENUTEMPLATEW *tpl) { return load_indirect(tpl, 0); }
DLLAPI HMENU WINAPI LoadMenuW(HINSTANCE inst, LPCWSTR name)
{
    DWORD size = 0;
    const void *p = u32_find_resource(inst, (LPCWSTR)RT_MENU, name, &size);
    if (!p) { SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return 0; }
    return load_indirect(p, size);
}

/* ---------------------------------------------------------------- accelerator tables */
#define NACCEL 64
static struct { int used; unsigned gen; ACCEL *a; int n; } g_acc[NACCEL];

int u32_accel_count(void) { int i, n = 0; for (i = 0; i < NACCEL; ++i) n += g_acc[i].used; return n; }

static HACCEL ahandle(int i) { return (HACCEL)(uintptr_t)(((uintptr_t)g_acc[i].gen << 8) | 0x6000000u | (unsigned)i); }
static int aindex(HACCEL h)
{
    const uintptr_t v = (uintptr_t)h;
    const int i = (int)(v & 0xff);
    if ((v & 0x6000000u) != 0x6000000u || i >= NACCEL || !g_acc[i].used || ahandle(i) != h) return -1;
    return i;
}

DLLAPI HACCEL WINAPI CreateAcceleratorTableW(LPACCEL a, int n)
{
    int i;
    HACCEL h = 0;
    ACCEL *c;
    if (!a || n <= 0) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    c = HeapAlloc(GetProcessHeap(), 0, (size_t)n * sizeof *c);
    if (!c) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    memcpy(c, a, (size_t)n * sizeof *c);
    mlock();
    for (i = 0; i < NACCEL; ++i)
        if (!g_acc[i].used) { g_acc[i].used = 1; g_acc[i].gen = (g_acc[i].gen + 1) & 0xffff; g_acc[i].a = c; g_acc[i].n = n; h = ahandle(i); break; }
    munlock();
    if (!h) { HeapFree(GetProcessHeap(), 0, c); SetLastError(ERROR_NOT_ENOUGH_MEMORY); }
    return h;
}
DLLAPI HACCEL WINAPI CreateAcceleratorTableA(LPACCEL a, int n) { return CreateAcceleratorTableW(a, n); }

DLLAPI BOOL WINAPI DestroyAcceleratorTable(HACCEL h)
{
    int i;
    ACCEL *a = 0;
    mlock();
    i = aindex(h);
    if (i >= 0) { a = g_acc[i].a; g_acc[i].used = 0; g_acc[i].a = 0; }
    munlock();
    if (i < 0) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    HeapFree(GetProcessHeap(), 0, a);
    return TRUE;
}

DLLAPI int WINAPI CopyAcceleratorTableW(HACCEL h, LPACCEL out, int n)
{
    int i, k;
    mlock();
    i = aindex(h);
    if (i < 0) { munlock(); SetLastError(ERROR_INVALID_HANDLE); return 0; }
    if (!out) { k = g_acc[i].n; munlock(); return k; }
    k = n < g_acc[i].n ? n : g_acc[i].n;
    memcpy(out, g_acc[i].a, (size_t)k * sizeof *out);
    munlock();
    return k;
}

DLLAPI HACCEL WINAPI LoadAcceleratorsW(HINSTANCE inst, LPCWSTR name)
{
    DWORD size = 0;
    const uint8_t *p = u32_find_resource(inst, (LPCWSTR)RT_ACCELERATOR, name, &size);
    ACCEL a[256];
    int n = 0;
    if (!p) { SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return 0; }
    while ((DWORD)(n + 1) * 8 <= size && n < 256) {                    /* ACCELTABLEENTRY: fFlags, wAnsi, wId, padding */
        const WORD *e = (const WORD *)(p + n * 8);
        a[n].fVirt = (BYTE)(e[0] & 0x7f);
        a[n].key = e[1];
        a[n].cmd = e[2];
        ++n;
        if (e[0] & 0x80) break;
    }
    return CreateAcceleratorTableW(a, n);
}

DLLAPI int WINAPI TranslateAcceleratorW(HWND hwnd, HACCEL h, LPMSG msg)
{
    ACCEL a[256];
    int n, i;
    if (!msg || !hwnd) return 0;
    if (msg->message != WM_KEYDOWN && msg->message != WM_SYSKEYDOWN && msg->message != WM_CHAR && msg->message != WM_SYSCHAR) return 0;
    n = CopyAcceleratorTableW(h, a, 256);
    for (i = 0; i < n; ++i) {
        const int virt = (a[i].fVirt & FVIRTKEY) != 0;
        const int shift = GetKeyState(VK_SHIFT) < 0, ctrl = GetKeyState(VK_CONTROL) < 0, alt = GetKeyState(VK_MENU) < 0;
        if (virt) {
            if (msg->message != WM_KEYDOWN && msg->message != WM_SYSKEYDOWN) continue;
            if (msg->wParam != a[i].key) continue;
            if (shift != ((a[i].fVirt & FSHIFT) != 0) || ctrl != ((a[i].fVirt & FCONTROL) != 0) || alt != ((a[i].fVirt & FALT) != 0)) continue;
        } else {
            if (msg->message != WM_CHAR && msg->message != WM_SYSCHAR) continue;
            if (msg->wParam != a[i].key || alt != ((a[i].fVirt & FALT) != 0)) continue;
        }
        SendMessageW(hwnd, WM_COMMAND, MAKEWPARAM(a[i].cmd, 1), 0);
        return 1;
    }
    return 0;
}
DLLAPI int WINAPI TranslateAcceleratorA(HWND hwnd, HACCEL h, LPMSG msg) { return TranslateAcceleratorW(hwnd, h, msg); }
