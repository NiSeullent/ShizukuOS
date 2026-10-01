/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine window/client IAccessible objects from the isolated Wine11 subset.
 * Actual in-process transfers coexist with standard objects; RPC is separate.
 */
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <oleacc.h>
#include "k32test.h"

static const IID iid_accessible = {0x618736e0, 0x3c3d, 0x11cf, {0x81,0x0c,0x00,0xaa,0x00,0x38,0x9b,0x71}};
typedef HRESULT (WINAPI *create_fn)(HWND, LONG, REFIID, void **);
typedef HRESULT (WINAPI *from_window_fn)(HWND, DWORD, REFIID, void **);
typedef HRESULT (WINAPI *children_fn)(IAccessible *, LONG, LONG, VARIANT *, LONG *);
typedef HRESULT (WINAPI *window_fn)(IAccessible *, HWND *);
typedef LRESULT (WINAPI *result_fn)(REFIID, WPARAM, LPUNKNOWN);
typedef HRESULT (WINAPI *object_fn)(LRESULT, REFIID, WPARAM, void **);

int main(void)
{
    HMODULE dll = LoadLibraryW(L"oleacc.dll");
    create_fn create;
    from_window_fn from_window;
    children_fn children;
    window_fn from_object;
    result_fn marshal;
    object_fn unmarshal;
    IAccessible *client = 0, *window = 0;
    HWND parent = 0, child = 0, obtained = 0;
    WNDCLASSW cls;
    VARIANT self, role, item;
    BSTR name = 0;
    LONG count = -1, returned = -1;
    HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    CHECK(SUCCEEDED(hr), "actual COM apartment initializes");
    CHECK(dll != 0, "real ported oleacc DLL loads");
    if (!dll || FAILED(hr)) { if (dll) FreeLibrary(dll); return 1; }
    create = (create_fn)GetProcAddress(dll, "CreateStdAccessibleObject");
    from_window = (from_window_fn)GetProcAddress(dll, "AccessibleObjectFromWindow");
    children = (children_fn)GetProcAddress(dll, "AccessibleChildren");
    from_object = (window_fn)GetProcAddress(dll, "WindowFromAccessibleObject");
    marshal = (result_fn)GetProcAddress(dll, "LresultFromObject");
    unmarshal = (object_fn)GetProcAddress(dll, "ObjectFromLresult");
    CHECK(create && from_window && children && from_object && marshal && unmarshal, "all five Chromium delay imports and actual transfer receiver resolve");
    if (!create || !from_window || !children || !from_object || !marshal || !unmarshal) goto done;
    CHECK(!GetProcAddress(dll, "CreateStdAccessibleProxyW") && !GetProcAddress(dll, "DllRegisterServer"),
          "unported RPC proxy and registration exports remain absent");
    memset(&cls, 0, sizeof cls);
    cls.lpfnWndProc = DefWindowProcW; cls.hInstance = GetModuleHandleW(0); cls.lpszClassName = L"OleaccLocalContract";
    CHECK(RegisterClassW(&cls) != 0, "actual test window class registers");
    parent = CreateWindowExW(0, cls.lpszClassName, L"OLEACC actual window", WS_OVERLAPPEDWINDOW,
                             40, 40, 320, 200, 0, 0, cls.hInstance, 0);
    CHECK(parent != 0, "actual parent HWND exists");
    if (!parent) goto done;
    child = CreateWindowExW(0, L"Static", L"actual child", WS_CHILD | WS_VISIBLE, 10, 10, 100, 30,
                            parent, (HMENU)100, cls.hInstance, 0);
    CHECK(child != 0, "actual child HWND exists");
    hr = create(parent, OBJID_CLIENT, &iid_accessible, (void **)&client);
    CHECK(hr == S_OK && client != 0, "standard client returns a real IAccessible vtable");
    if (!client) goto done;
    VariantInit(&self); V_VT(&self) = VT_I4; V_I4(&self) = CHILDID_SELF;
    VariantInit(&role);
    CHECK(IAccessible_get_accName(client, self, &name) == S_OK && name && k32t_weq(name, L"OLEACC actual window"),
          "accessible name comes from actual HWND text");
    if (name) { SysFreeString(name); name = 0; }
    CHECK(IAccessible_get_accRole(client, self, &role) == S_OK && V_VT(&role) == VT_I4 && V_I4(&role) == ROLE_SYSTEM_CLIENT,
          "real client role is reported");
    VariantClear(&role);
    CHECK(IAccessible_get_accChildCount(client, &count) == S_OK && count == 1,
          "real HWND hierarchy supplies actual child count");
    VariantInit(&item);
    CHECK(children(client, 0, 1, &item, &returned) == S_OK && returned == 1 &&
          (V_VT(&item) == VT_I4 || V_VT(&item) == VT_DISPATCH), "children enumerates an actual child reference");
    VariantClear(&item);
    CHECK(from_object(client, &obtained) == S_OK && obtained == parent, "accessible object returns its real parent HWND");
    CHECK(from_window(parent, OBJID_WINDOW, &iid_accessible, (void **)&window) == S_OK && window,
          "window lookup creates a real default window accessible object");
    if (window) {
        obtained = 0;
        CHECK(from_object(window, &obtained) == S_OK && obtained == parent, "default window object retains actual HWND identity");
        IAccessible_Release(window); window = 0;
    }
    CHECK(children(0, 0, 1, &item, &returned) == E_INVALIDARG, "null children container fails");
    CHECK(children(client, -1, 1, &item, &returned) == E_INVALIDARG, "negative child offset fails");
    CHECK(from_object(0, &obtained) == E_INVALIDARG && from_object(client, 0) == E_INVALIDARG,
          "null accessible object and HWND output fail without a fault");
    CHECK(create(parent, OBJID_CLIENT, &iid_accessible, 0) == E_INVALIDARG,
          "null standard-object output fails without a fault");
    CHECK((HRESULT)marshal(&iid_accessible, 0, 0) == E_INVALIDARG, "null marshaling object fails");
    {
        LRESULT token = marshal(&iid_accessible, 0, (IUnknown *)client);
        IAccessible *received = NULL;
        CHECK(token > 0 && SUCCEEDED((HRESULT)token), "a real local standard object yields a usable positive transfer token");
        CHECK(unmarshal(token, &iid_accessible, 0, (void **)&received) == S_OK && received != NULL,
              "the actual receiver transfers a real standard object reference");
        if (received) {
            obtained = NULL;
            CHECK(from_object(received, &obtained) == S_OK && obtained == parent,
                  "transferred standard object retains its actual HWND");
            IAccessible_Release(received); received = NULL;
        }
        CHECK(unmarshal(token, &iid_accessible, 0, (void **)&received) == E_INVALIDARG && !received,
              "a consumed transfer token cannot be reused");
    }
 done:
    if (window) IAccessible_Release(window);
    if (client) IAccessible_Release(client);
    if (name) SysFreeString(name);
    if (child) DestroyWindow(child);
    if (parent) DestroyWindow(parent);
    CoUninitialize();
    FreeLibrary(dll);
    return k32t_finish("T_OLEACC_LOCAL");
}
