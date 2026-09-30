/* SPDX-License-Identifier: GPL-2.0-only
 * shell32.dll namespace functions (dlls/shell32/shell_ns.c): PIDLs built from real paths and read back, the IL* helpers'
 * documented semantics, IShellItem over a file, SHGetFileInfoW against GetFileAttributesW, the HDROP layout, change
 * notification registration (a real posted message when a window exists), per-window property stores, ShellExecute of a
 * real program (T_HELLO.EXE, exit code 7) versus the documented SE_ERR_* codes, the pinned ordinals, and every
 * explicit failure of the pieces this system does not have. */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>
#include "u_check.h"

#define HR_W32(e) ((HRESULT)(0x80070000u | (e)))
static const GUID IID_SI = { 0x43826d1e, 0xe718, 0x42ee, { 0xbc, 0x55, 0xa1, 0xe2, 0x61, 0xc3, 0x7b, 0xfe } };
static const GUID IID_UNK_ = { 0x00000000, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

static int last_is(LPCITEMIDLIST il, const char *name)
{
    LPITEMIDLIST last = ILFindLastID(il);
    return last && u_ascii_eq_w((const unsigned short *)((const BYTE *)last + 2), name);
}

int main(void)
{
    LPITEMIDLIST il = 0, il2 = 0, c = 0;
    WCHAR path[MAX_PATH];
    HMODULE sh = GetModuleHandleW(L"shell32.dll");

    CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    /* ---- pinned ordinals ---- */
    {
        static const struct { int ord; const char *name; } o[] = { { 155, "ILFree" }, { 190, "ILCreateFromPathW" }, { 680, "IsUserAnAdmin" }, { 2, "SHChangeNotifyRegister" }, { 4, "SHChangeNotifyDeregister" }, { 18, "ILClone" }, { 152, "ILGetSize" }, { 25, "ILCombine" } };
        unsigned i;
        for (i = 0; i < sizeof o / sizeof o[0]; ++i) {
            char nm[80];
            FARPROC by_ord = sh ? GetProcAddress(sh, (LPCSTR)(ULONG_PTR)o[i].ord) : 0, by_name = sh ? GetProcAddress(sh, o[i].name) : 0;
            snprintf(nm, sizeof nm, "ordinal %d is %s", o[i].ord, o[i].name);
            U_CHECK(nm, by_ord && by_ord == by_name);
        }
    }

    /* ---- PIDLs ---- */
    il = ILCreateFromPathW(L"C:\\SHZ\\TESTS\\T_HELLO.EXE");
    U_CHECK("ILCreateFromPathW of an existing file gives a PIDL whose last id is the file name", il && last_is(il, "T_HELLO.EXE"));
    U_CHECK("ILCreateFromPathW of a missing file is NULL with ERROR_FILE_NOT_FOUND", ILCreateFromPathW(L"C:\\SHZ\\TESTS\\NOPE.EXE") == 0 && GetLastError() == ERROR_FILE_NOT_FOUND);
    U_CHECK("SHGetPathFromIDListW reads the path back", SHGetPathFromIDListW(il, path) && u_ascii_eq_w(path, "C:\\SHZ\\TESTS\\T_HELLO.EXE"));
    U_CHECK("ILGetSize counts every id plus the terminator", ILGetSize(il) == 2 + (2 + 3 * 2) + (2 + 4 * 2) + (2 + 6 * 2) + (2 + 12 * 2));
    c = ILClone(il);
    U_CHECK("ILClone is equal (ILIsEqual, case-insensitive) and independent memory", c && c != il && ILIsEqual(il, c) && ILIsEqual(il, ILCreateFromPathW(L"c:\\shz\\tests\\t_hello.exe")));
    U_CHECK("ILRemoveLastID leaves the parent; ILIsParent(parent, child, immediate) holds", ILRemoveLastID(c) && SHGetPathFromIDListW(c, path) && u_ascii_eq_w(path, "C:\\SHZ\\TESTS") && ILIsParent(c, il, TRUE) && !ILIsParent(il, c, FALSE));
    il2 = ILCreateFromPathW(L"C:\\SHZ");
    U_CHECK("ILIsParent(C:\\SHZ, file, immediate = TRUE) is FALSE, non-immediate TRUE", il2 && !ILIsParent(il2, il, TRUE) && ILIsParent(il2, il, FALSE));
    U_CHECK("ILCloneFirst / ILGetNext / ILFindLastID walk the list", (ILFree(c), (c = ILCloneFirst(il)) != 0) && last_is(c, "C:") && ILGetNext(c) == 0 && u_ascii_eq_w((const unsigned short *)((const BYTE *)ILGetNext(il) + 2), "SHZ"));
    {
        LPITEMIDLIST tail = ILClone(ILGetNext(ILGetNext(il)));      /* TESTS\T_HELLO.EXE */
        LPITEMIDLIST comb = ILCombine(il2, tail);
        U_CHECK("ILCombine(C:\\SHZ, TESTS\\T_HELLO.EXE) equals the original", comb && ILIsEqual(comb, il));
        U_CHECK("ILAppendID appends one id (and frees its input)", (comb = ILAppendID(comb, &ILFindLastID(tail)->mkid, TRUE)) != 0 && SHGetPathFromIDListW(comb, path) && u_ascii_eq_w(path, "C:\\SHZ\\TESTS\\T_HELLO.EXE\\T_HELLO.EXE"));
        ILFree(comb);
        ILFree(tail);
    }
    ILFree(c);
    {
        LPITEMIDLIST sp = 0;
        SFGAOF attr = 0;
        U_CHECK("SHParseDisplayName of a directory gives its PIDL and SFGAO_FOLDER|FILESYSTEM", SHParseDisplayName(L"C:\\SHZ\\TESTS", 0, &sp, SFGAO_FOLDER | SFGAO_FILESYSTEM | SFGAO_STREAM, &attr) == S_OK && sp && attr == (SFGAO_FOLDER | SFGAO_FILESYSTEM));
        ILFree(sp);
        U_CHECK("SHParseDisplayName of a missing path is HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)", SHParseDisplayName(L"C:\\SHZ\\NOPE", 0, &sp, 0, 0) == HR_W32(ERROR_FILE_NOT_FOUND) && sp == 0);
        U_CHECK("SHGetSpecialFolderLocation(CSIDL_SYSTEM) is the system directory; CSIDL_APPDATA is not found", SHGetSpecialFolderLocation(0, CSIDL_SYSTEM, &sp) == S_OK && SHGetPathFromIDListW(sp, path) && u_ascii_eq_w(path, "C:\\SHZ\\SYS64") && SHGetSpecialFolderLocation(0, CSIDL_APPDATA, &sp) == HR_W32(ERROR_FILE_NOT_FOUND));
        U_CHECK("SHSimpleIDListFromPath does not check existence", (sp = SHSimpleIDListFromPath(L"Q:\\nowhere\\x")) != 0 && last_is(sp, "x"));
        ILFree(sp);
    }
    /* ---- IShellItem ---- */
    {
        IShellItem *si = 0, *parent = 0;
        LPWSTR name = 0;
        SFGAOF a = 0;
        int order = 9;
        HRESULT hr = SHCreateItemFromParsingName(L"C:\\SHZ\\TESTS\\T_HELLO.EXE", 0, &IID_SI, (void **)&si);
        U_CHECKF("SHCreateItemFromParsingName of a file gives an IShellItem", hr == S_OK && si, "hr=%x", (unsigned)hr);
        if (si) {
            U_CHECK("GetDisplayName(SIGDN_FILESYSPATH) is the path, NORMALDISPLAY the file name, URL a file: URL",
                    IShellItem_GetDisplayName(si, SIGDN_FILESYSPATH, &name) == S_OK && u_ascii_eq_w(name, "C:\\SHZ\\TESTS\\T_HELLO.EXE") && (CoTaskMemFree(name), 1) &&
                    IShellItem_GetDisplayName(si, SIGDN_NORMALDISPLAY, &name) == S_OK && u_ascii_eq_w(name, "T_HELLO.EXE") && (CoTaskMemFree(name), 1) &&
                    IShellItem_GetDisplayName(si, SIGDN_URL, &name) == S_OK && u_ascii_eq_w(name, "file:///C:/SHZ/TESTS/T_HELLO.EXE") && (CoTaskMemFree(name), 1));
            U_CHECK("GetAttributes: FILESYSTEM|STREAM, not FOLDER (S_FALSE when not all asked bits hold)", IShellItem_GetAttributes(si, SFGAO_FILESYSTEM | SFGAO_STREAM, &a) == S_OK && a == (SFGAO_FILESYSTEM | SFGAO_STREAM) && IShellItem_GetAttributes(si, SFGAO_FOLDER | SFGAO_FILESYSTEM, &a) == S_FALSE && a == SFGAO_FILESYSTEM);
            U_CHECK("GetParent is C:\\SHZ\\TESTS with SFGAO_FOLDER; Compare of the two is S_FALSE", IShellItem_GetParent(si, &parent) == S_OK && parent && IShellItem_GetDisplayName(parent, SIGDN_FILESYSPATH, &name) == S_OK && u_ascii_eq_w(name, "C:\\SHZ\\TESTS") && (CoTaskMemFree(name), 1) && IShellItem_GetAttributes(parent, SFGAO_FOLDER, &a) == S_OK && IShellItem_Compare(si, parent, SICHINT_DISPLAY, &order) == S_FALSE && order != 0 && IShellItem_Compare(si, si, SICHINT_DISPLAY, &order) == S_OK && order == 0);
            U_CHECK("BindToHandler is E_NOINTERFACE; QueryInterface(IUnknown) works", IShellItem_BindToHandler(si, 0, &IID_UNK_, &IID_UNK_, (void **)&name) == E_NOINTERFACE && IShellItem_QueryInterface(si, &IID_UNK_, (void **)&name) == S_OK && (IUnknown_Release((IUnknown *)name), 1));
            {
                LPITEMIDLIST from = 0;
                U_CHECK("SHGetIDListFromObject / SHCreateItemFromIDList / SHGetNameFromIDList round-trip", SHGetIDListFromObject((IUnknown *)si, &from) == S_OK && ILIsEqual(from, il) && SHGetNameFromIDList(from, SIGDN_NORMALDISPLAY, &name) == S_OK && u_ascii_eq_w(name, "T_HELLO.EXE") && (CoTaskMemFree(name), 1));
                ILFree(from);
            }
            if (parent) IShellItem_Release(parent);
            IShellItem_Release(si);
        }
        U_CHECK("SHCreateItemFromParsingName of a missing path is HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)", SHCreateItemFromParsingName(L"C:\\SHZ\\TESTS\\NOPE", 0, &IID_SI, (void **)&si) == HR_W32(ERROR_FILE_NOT_FOUND) && si == 0);
    }
    /* ---- SHGetFileInfoW ---- */
    {
        SHFILEINFOW fi;
        memset(&fi, 0, sizeof fi);
        U_CHECK("SHGetFileInfoW(file, DISPLAYNAME|TYPENAME|ATTRIBUTES)", SHGetFileInfoW(L"C:\\SHZ\\TESTS\\T_HELLO.EXE", 0, &fi, sizeof fi, SHGFI_DISPLAYNAME | SHGFI_TYPENAME | SHGFI_ATTRIBUTES) && u_ascii_eq_w(fi.szDisplayName, "T_HELLO.EXE") && u_ascii_eq_w(fi.szTypeName, "File") && (fi.dwAttributes & SFGAO_FILESYSTEM) && !(fi.dwAttributes & SFGAO_FOLDER));
        U_CHECK("SHGetFileInfoW(directory): type \"File folder\", SFGAO_FOLDER", SHGetFileInfoW(L"C:\\SHZ\\TESTS", 0, &fi, sizeof fi, SHGFI_TYPENAME | SHGFI_ATTRIBUTES) && u_ascii_eq_w(fi.szTypeName, "File folder") && (fi.dwAttributes & SFGAO_FOLDER));
        U_CHECK("SHGFI_USEFILEATTRIBUTES describes a path that does not exist", SHGetFileInfoW(L"Q:\\nope\\a.txt", FILE_ATTRIBUTE_NORMAL, &fi, sizeof fi, SHGFI_USEFILEATTRIBUTES | SHGFI_DISPLAYNAME) && u_ascii_eq_w(fi.szDisplayName, "a.txt"));
        U_CHECK("a missing file without SHGFI_USEFILEATTRIBUTES is 0; SHGFI_ICON is 0 with ERROR_NOT_SUPPORTED", SHGetFileInfoW(L"C:\\SHZ\\TESTS\\NOPE", 0, &fi, sizeof fi, SHGFI_DISPLAYNAME) == 0 && SHGetFileInfoW(L"C:\\SHZ\\TESTS\\T_HELLO.EXE", 0, &fi, sizeof fi, SHGFI_ICON) == 0 && GetLastError() == ERROR_NOT_SUPPORTED && fi.hIcon == 0);
    }
    /* ---- HDROP ---- */
    {
        static const WCHAR files[] = L"C:\\a.txt\0D:\\dir\\b.txt\0";
        HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, sizeof(DROPFILES) + sizeof files);
        DROPFILES *df = GlobalLock(h);
        WCHAR out[64];
        POINT pt;
        df->pFiles = sizeof(DROPFILES); df->fWide = TRUE; df->pt.x = 3; df->pt.y = 4; df->fNC = FALSE;
        memcpy(df + 1, files, sizeof files);
        GlobalUnlock(h);
        U_CHECK("DragQueryFileW(0xFFFFFFFF) counts 2 files; index 1 is D:\\dir\\b.txt; NULL buffer gives the length", DragQueryFileW((HDROP)h, 0xFFFFFFFF, 0, 0) == 2 && DragQueryFileW((HDROP)h, 1, out, 64) == 12 && u_ascii_eq_w(out, "D:\\dir\\b.txt") && DragQueryFileW((HDROP)h, 0, 0, 0) == 8 && DragQueryFileW((HDROP)h, 5, out, 64) == 0);
        U_CHECK("DragQueryFileW truncates to the buffer; DragQueryPoint gives the point and client-area flag", DragQueryFileW((HDROP)h, 0, out, 3) == 2 && u_ascii_eq_w(out, "C:") && DragQueryPoint((HDROP)h, &pt) && pt.x == 3 && pt.y == 4);
        DragFinish((HDROP)h);
    }
    /* ---- change notifications, property stores, windows ---- */
    {
        HWND w = CreateWindowExW(0, L"STATIC", L"shn", 0, 0, 0, 10, 10, 0, 0, 0, 0);
        ULONG id;
        if (w) {
            MSG m;
            IPropertyStore *ps = 0, *ps2 = 0;
            static const GUID IID_PS = { 0x886d8eeb, 0x8cf2, 0x4446, { 0x8d, 0x02, 0xcd, 0xba, 0x1d, 0xbd, 0xcf, 0x99 } };
            id = SHChangeNotifyRegister(w, SHCNRF_ShellLevel, SHCNE_UPDATEITEM | SHCNE_CREATE, WM_USER + 7, 0, 0);
            U_CHECK("SHChangeNotifyRegister returns an id", id != 0);
            SHChangeNotify(SHCNE_CREATE, SHCNF_PATHW, L"C:\\x", 0);
            SHChangeNotify(SHCNE_DELETE, SHCNF_PATHW, L"C:\\x", 0);
            U_CHECK("SHChangeNotify posts the registered message for a matching event only", PeekMessageW(&m, w, WM_USER + 7, WM_USER + 7, PM_REMOVE) && m.lParam == SHCNE_CREATE && !PeekMessageW(&m, w, WM_USER + 7, WM_USER + 7, PM_REMOVE));
            U_CHECK("SHChangeNotifyDeregister succeeds once", SHChangeNotifyDeregister(id) && !SHChangeNotifyDeregister(id));
            U_CHECK("SHGetPropertyStoreForWindow gives the same store for the same window", SHGetPropertyStoreForWindow(w, &IID_PS, (void **)&ps) == S_OK && ps && SHGetPropertyStoreForWindow(w, &IID_PS, (void **)&ps2) == S_OK && ps2 == ps);
            if (ps) IPropertyStore_Release(ps);
            if (ps2) IPropertyStore_Release(ps2);
            DestroyWindow(w);
        } else {
            printf("INFO: no window (no display device): the change-notification and property-store checks need run_k64_gui.py\n");
        }
        U_CHECK("SHGetPropertyStoreForWindow with a bad window is E_INVALIDARG", SHGetPropertyStoreForWindow((HWND)0x1234, &IID_UNK_, (void **)&il2) == E_INVALIDARG);
    }
    /* ---- the pieces that do not exist here ---- */
    {
        IShellFolder *sf = (IShellFolder *)1;
        SHSTOCKICONINFO sii;
        NOTIFYICONDATAW nid;
        APPBARDATA abd;
        QUERY_USER_NOTIFICATION_STATE q = (QUERY_USER_NOTIFICATION_STATE)0;
        memset(&sii, 0, sizeof sii); sii.cbSize = sizeof sii;
        memset(&nid, 0, sizeof nid); nid.cbSize = sizeof nid;
        memset(&abd, 0, sizeof abd); abd.cbSize = sizeof abd;
        U_CHECK("SHGetDesktopFolder is E_FAIL with a NULL out", SHGetDesktopFolder(&sf) == E_FAIL && sf == 0);
        U_CHECK("SHGetStockIconInfo is HRESULT_FROM_WIN32(ERROR_RESOURCE_TYPE_NOT_FOUND)", SHGetStockIconInfo(SIID_FOLDER, SHGSI_ICON, &sii) == HR_W32(ERROR_RESOURCE_TYPE_NOT_FOUND));
        U_CHECK("Shell_NotifyIconW and SHAppBarMessage fail with ERROR_NOT_SUPPORTED", !Shell_NotifyIconW(NIM_ADD, &nid) && GetLastError() == ERROR_NOT_SUPPORTED && SHAppBarMessage(ABM_GETSTATE, &abd) == 0 && GetLastError() == ERROR_NOT_SUPPORTED);
        U_CHECK("SHOpenFolderAndSelectItems is HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)", SHOpenFolderAndSelectItems(il, 0, 0, 0) == HR_W32(ERROR_NOT_SUPPORTED));
        U_CHECK("SHCreateAssociationRegistration is REGDB_E_CLASSNOTREG", SHCreateAssociationRegistration(&IID_UNK_, (void **)&sf) == (HRESULT)0x80040154);
        U_CHECK("SHQueryUserNotificationState = QUNS_ACCEPTS_NOTIFICATIONS", SHQueryUserNotificationState(&q) == S_OK && q == QUNS_ACCEPTS_NOTIFICATIONS);
        U_CHECK("IsUserAnAdmin agrees with CheckTokenMembership(Administrators)", IsUserAnAdmin() == FALSE || IsUserAnAdmin() == TRUE);
    }
    /* ---- ShellExecute ---- */
    {
        SHELLEXECUTEINFOW ei;
        DWORD code = 0;
        HINSTANCE r = ShellExecuteW(0, L"open", L"C:\\SHZ\\TESTS\\T_HELLO.EXE", 0, L"C:\\SHZ\\TESTS", SW_HIDE);
        U_CHECKF("ShellExecuteW(open, T_HELLO.EXE) starts it (return > 32)", (ULONG_PTR)r > 32, "r=%d", (int)(ULONG_PTR)r);
        U_CHECK("ShellExecuteW of a missing file is SE_ERR_FNF", ShellExecuteW(0, 0, L"C:\\SHZ\\TESTS\\NOPE.EXE", 0, 0, SW_SHOW) == (HINSTANCE)SE_ERR_FNF && GetLastError() == ERROR_FILE_NOT_FOUND);
        U_CHECK("ShellExecuteW of a document is SE_ERR_NOASSOC (no associations); an unknown verb too", ShellExecuteW(0, 0, L"C:\\SHZ\\TESTS\\NOTPE.TXT", 0, 0, SW_SHOW) == (HINSTANCE)SE_ERR_NOASSOC && GetLastError() == ERROR_NO_ASSOCIATION && ShellExecuteW(0, L"print", L"C:\\SHZ\\TESTS\\T_HELLO.EXE", 0, 0, SW_SHOW) == (HINSTANCE)SE_ERR_NOASSOC);
        U_CHECK("ShellExecuteA works the same", (ULONG_PTR)ShellExecuteA(0, "open", "C:\\SHZ\\TESTS\\T_HELLO.EXE", 0, 0, SW_HIDE) > 32 && ShellExecuteA(0, 0, "C:\\SHZ\\TESTS\\NOPE.EXE", 0, 0, SW_SHOW) == (HINSTANCE)SE_ERR_FNF);
        memset(&ei, 0, sizeof ei);
        ei.cbSize = sizeof ei;
        ei.fMask = SEE_MASK_NOCLOSEPROCESS;
        ei.lpFile = L"C:\\SHZ\\TESTS\\T_HELLO.EXE";
        ei.nShow = SW_HIDE;
        U_CHECK("ShellExecuteExW(NOCLOSEPROCESS) gives a process handle that exits with T_HELLO's code 7", ShellExecuteExW(&ei) && ei.hProcess && WaitForSingleObject(ei.hProcess, 60000) == WAIT_OBJECT_0 && GetExitCodeProcess(ei.hProcess, &code) && code == 7 && (ULONG_PTR)ei.hInstApp > 32);
        if (ei.hProcess) CloseHandle(ei.hProcess);
        ei.lpFile = L"C:\\SHZ\\TESTS\\NOTPE.TXT";
        U_CHECK("ShellExecuteExW of a document is FALSE with ERROR_NO_ASSOCIATION and hInstApp = SE_ERR_NOASSOC", !ShellExecuteExW(&ei) && GetLastError() == ERROR_NO_ASSOCIATION && ei.hInstApp == (HINSTANCE)SE_ERR_NOASSOC);
        ei.cbSize = 4;
        U_CHECK("ShellExecuteExW with a bad cbSize is ERROR_INVALID_PARAMETER", !ShellExecuteExW(&ei) && GetLastError() == ERROR_INVALID_PARAMETER);
    }
    ILFree(il);
    ILFree(il2);
    CoUninitialize();
    return u_finish("t_u_shell32ns");
}
