/* SPDX-License-Identifier: GPL-2.0-only
 * Actual IMM32 loader/registry/output extent contracts. A private synthetic
 * catalog entry is test data only: no IME engine is installed or selected. */
#include "k32test.h"

typedef UINT (WINAPI *metadata_w_fn)(HKL, LPWSTR, UINT);
typedef UINT (WINAPI *metadata_a_fn)(HKL, LPSTR, UINT);

int main(void)
{
    static const WCHAR key_path[] = L"System\\CurrentControlSet\\Control\\Keyboard Layouts\\e0fe0409";
    static const WCHAR file_name[] = L"fixture-only.ime", description[] = L"Registry metadata fixture";
    HMODULE module = LoadLibraryW(L"imm32.dll");
    metadata_w_fn file_w, description_w;
    metadata_a_fn file_a, description_a;
    HKL layout = GetKeyboardLayout(0), fixture_layout = (HKL)(ULONG_PTR)0xe0fe0409;
    WCHAR layout_name[9], before_name[9];
    WCHAR wide[64];
    char ansi[64];
    HKEY key = NULL;
    DWORD disposition = 0;
    LONG status;
    UINT n;
    CHECK(module != NULL, "actual imm32.dll loads with its registry dependency");
    if (!module) return 1;
    file_w = (metadata_w_fn)GetProcAddress(module, "ImmGetIMEFileNameW");
    file_a = (metadata_a_fn)GetProcAddress(module, "ImmGetIMEFileNameA");
    description_w = (metadata_w_fn)GetProcAddress(module, "ImmGetDescriptionW");
    description_a = (metadata_a_fn)GetProcAddress(module, "ImmGetDescriptionA");
    CHECK(file_w && file_a && description_w && description_a, "four real input-layout metadata exports resolve");
    if (!file_w || !file_a || !description_w || !description_a) return 1;
    CHECK(!GetProcAddress(module, "ImmSetOpenStatus") && !GetProcAddress(module, "ImmCreateContext"),
          "unimplemented IME engine and context operations are absent");
    CHECK(layout && GetKeyboardLayoutNameW(before_name), "genuine current keyboard layout is available");
    n = file_w(layout, NULL, 0);
    CHECK(n == 0, "current US layout has no registered IME filename");
    CHECK(GetKeyboardLayout(0) == layout && GetKeyboardLayoutNameW(layout_name) && k32t_weq(layout_name, before_name),
          "metadata query preserves the actual keyboard layout");

    status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, key_path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, &disposition);
    CHECK(status == ERROR_SUCCESS && disposition == REG_CREATED_NEW_KEY, "fixture creates its own isolated registry catalog entry");
    if (status != ERROR_SUCCESS || disposition != REG_CREATED_NEW_KEY) {
        if (key) RegCloseKey(key);
        FreeLibrary(module);
        return k32t_finish("T_IMM32_METADATA");
    }
    CHECK(RegSetValueExW(key, L"Ime File", 0, REG_SZ, (const BYTE *)file_name, sizeof file_name) == ERROR_SUCCESS,
          "fixture stores real registry filename bytes");
    CHECK(RegSetValueExW(key, L"Layout Text", 0, REG_SZ, (const BYTE *)description, sizeof description) == ERROR_SUCCESS,
          "fixture stores independent real layout description");
    n = file_w(fixture_layout, NULL, 0);
    CHECK(n == 16, "wide registry filename size query excludes terminator");
    CHECK(file_w(fixture_layout, wide, 64) == 16 && k32t_weq(wide, file_name), "wide query returns actual registry catalog filename");
    CHECK(file_a(fixture_layout, ansi, sizeof ansi) == 16 && !strcmp(ansi, "fixture-only.ime"),
          "ANSI query converts the actual catalog filename");
    CHECK(description_w(fixture_layout, wide, 64) == 25 && k32t_weq(wide, description), "wide description reads Layout Text independently");
    CHECK(description_a(fixture_layout, ansi, sizeof ansi) == 25 && !strcmp(ansi, "Registry metadata fixture"),
          "ANSI description uses the real catalog text");
    {
        struct { WCHAR before, value[5], after; } bounded = {0x1234, {0}, 0x5678};
        n = file_w(fixture_layout, bounded.value, 5);
        CHECK(n == 4 && bounded.value[0] == 'f' && bounded.value[3] == 't' && bounded.value[4] == 0 &&
              bounded.before == 0x1234 && bounded.after == 0x5678,
              "wide truncation copies four units plus terminator within declared extent");
        bounded.value[0] = 0xabcd;
        CHECK(file_w(fixture_layout, bounded.value, 0) == 16 && bounded.value[0] == 0xabcd,
              "zero-capacity query does not modify output");
        CHECK(file_w(fixture_layout, bounded.value, 1) == 0 && bounded.value[0] == 0 && bounded.after == 0x5678,
              "one-unit capacity writes only the terminator");
    }
    CHECK(RegDeleteValueW(key, L"Ime File") == ERROR_SUCCESS && file_w(fixture_layout, NULL, 0) == 0,
          "deleting filename changes the live query result instead of retaining fabricated metadata");
    CHECK(GetKeyboardLayout(0) == layout, "synthetic catalog test never activates an IME or another keyboard layout");
    CHECK(RegCloseKey(key) == ERROR_SUCCESS && RegDeleteKeyW(HKEY_LOCAL_MACHINE, key_path) == ERROR_SUCCESS,
          "owned registry fixture is removed");
    CHECK(FreeLibrary(module), "actual metadata DLL reference released");
    return k32t_finish("T_IMM32_METADATA");
}
