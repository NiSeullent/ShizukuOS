/* SPDX-License-Identifier: GPL-2.0-only
 * Actual formatter, UTF-8 window/dialog resource, and information-DC contracts.
 * Graphics checks explicitly SKIP without a display; formatter checks still run.
 */
#include "k32test.h"
#include <string.h>

static unsigned dialog_visits, dialog_faults;
static INT_PTR CALLBACK end_dialog(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    (void)wparam;
    if (message == WM_INITDIALOG) {
        ++dialog_visits;
        if (lparam != 0x12345678) ++dialog_faults;
        if (!EndDialog(window, 73)) ++dialog_faults;
        return TRUE;
    }
    return FALSE;
}
static int poison(const BYTE *bytes, unsigned count) { unsigned i; for (i = 0; i < count; ++i) if (bytes[i] != 0xa5) return 0; return 1; }

int main(void)
{
    struct { char text[1024]; BYTE guard[16]; } narrow;
    struct { WCHAR text[1024]; BYTE guard[16]; } wide;
    static const char expected[] = "0000002a|abc   |wide|-9223372036854775808|18446744073709551615";
    static const WCHAR expected_wide[] = L"한|narrow|ffffffffffffffff";
    HWND window;
    HDC information, drawable;
    COLORREF before, after;
    HINSTANCE instance = GetModuleHandleW(NULL);
    int count;

    memset(&narrow, 0xa5, sizeof narrow);
    count = wsprintfA(narrow.text, "%08x|%-6.3s|%S|%I64d|%I64u", 42, "abcdef", L"wide", (-9223372036854775807ll - 1), 18446744073709551615ull);
    CHECK(count == sizeof expected - 1 && strcmp(narrow.text, expected) == 0 && poison(narrow.guard, sizeof narrow.guard),
          "ANSI wsprintf has Windows width/precision/opposite-width and exact signed/unsigned I64 syntax");
    memset(&wide, 0xa5, sizeof wide);
    count = wsprintfW(wide.text, L"%s|%S|%I64x", L"한", "narrow", 18446744073709551615ull);
    CHECK(count == sizeof expected_wide / sizeof(WCHAR) - 1 && k32t_weq(wide.text, expected_wide) && poison(wide.guard, sizeof wide.guard),
          "wide wsprintf has legacy Unicode s/opposite-width S and I64 hexadecimal syntax");
    CHECK(wsprintfA(narrow.text, "%s", "\xc3\xa9\xe4\xb8\xad") == 5 && memcmp(narrow.text, "\xc3\xa9\xe4\xb8\xad", 6) == 0,
          "same-width ANSI formatter preserves actual UTF-8 bytes");
    memset(&narrow, 0xa5, sizeof narrow);
    CHECK(wsprintfA(narrow.text, "%1100s", "x") == 1023 && narrow.text[0] == ' ' && narrow.text[1022] == ' ' && narrow.text[1023] == 0 &&
          poison(narrow.guard, sizeof narrow.guard), "ANSI formatter truncates and terminates at 1024 units without suffix writes");
    memset(&wide, 0xa5, sizeof wide);
    CHECK(wsprintfW(wide.text, L"%1100s", L"x") == 1023 && wide.text[0] == ' ' && wide.text[1022] == ' ' && wide.text[1023] == 0 &&
          poison(wide.guard, sizeof wide.guard), "Unicode formatter truncates and terminates at 1024 units without suffix writes");
    CHECK(wsprintfA(narrow.text, "%f", 1.0) == 0 && narrow.text[0] == 0 && GetLastError() == ERROR_NOT_SUPPORTED,
          "unsupported floating-point wsprintf mode fails explicitly");
    CHECK(wsprintfA(narrow.text, "%S", L"한") == 0 && narrow.text[0] == 0 && GetLastError() == ERROR_NOT_SUPPORTED,
          "known CRT code-page limit: non-ASCII cross-width formatting fails explicitly");
    CHECK(wsprintfW(wide.text, L"%S", "\xc3\xa9") == 0 && wide.text[0] == 0 && GetLastError() == ERROR_NOT_SUPPORTED,
          "known CRT code-page limit: UTF-8 cross-width formatting fails explicitly");
    CHECK(wsprintfA(narrow.text, "%100000000000000000000s", "x") == 0 && GetLastError() == ERROR_NOT_SUPPORTED,
          "unsupported huge width fails before formatter arithmetic");
    CHECK(!CreateICW(L"printer", NULL, NULL, NULL) && GetLastError() == ERROR_NOT_SUPPORTED, "unsupported information-device driver fails explicitly");
    if (GetSystemMetrics(SM_CXSCREEN) == 0) {
        printf("SKIP: T_STEAM_TEXT actual window/dialog/information-DC checks require a display\n");
        return k32t_finish("T_STEAM_TEXT_FORMAT_ONLY");
    }
    window = CreateWindowExW(0, L"STATIC", L"é中😀", WS_POPUP, 20, 20, 100, 40, NULL, NULL, instance, NULL);
    CHECK(window != NULL, "actual Unicode window created");
    if (!window) return 1;
    CHECK(GetWindowTextLengthW(window) == 4 && GetWindowTextLengthA(window) == 9, "ANSI title length counts UTF-8 bytes including a supplementary scalar");
    CHECK(SetWindowTextW(window, L"ASCII") && GetWindowTextLengthA(window) == 5, "ASCII title byte length matches real window text");
    CHECK(SetWindowTextW(window, L"") && GetWindowTextLengthA(window) == 0, "empty title length is zero");
    CHECK(DialogBoxParamA(instance, MAKEINTRESOURCEA(701), window, end_dialog, 0x12345678) == 73 && !dialog_faults,
          "ANSI dialog preserves ordinal resource identity, initialization and modal result");
    CHECK(DialogBoxParamA(instance, "STEAM_NAMED_DIALOG", window, end_dialog, 0x12345678) == 73 && dialog_visits == 2 && !dialog_faults,
          "ANSI dialog converts a real named resource and executes its modal procedure");
    CHECK(DialogBoxParamA(instance, "\xff", window, end_dialog, 0x12345678) == -1 && GetLastError() == ERROR_NO_UNICODE_TRANSLATION && dialog_visits == 2,
          "invalid UTF-8 resource name fails before a dialog is created");
    drawable = CreateDCW(L"DISPLAY", NULL, NULL, NULL);
    information = CreateICW(L"DISPLAY", L"\\\\.\\DISPLAY1", NULL, NULL);
    CHECK(drawable && information && drawable != information, "real primary-display information and drawable contexts are distinct");
    if (drawable && information) {
        CHECK(GetDeviceCaps(information, HORZRES) == GetSystemMetrics(SM_CXSCREEN) && GetDeviceCaps(information, VERTRES) == GetSystemMetrics(SM_CYSCREEN) &&
              GetDeviceCaps(information, TECHNOLOGY) == DT_RASDISPLAY && GetDeviceCaps(information, BITSPIXEL) == GetDeviceCaps(drawable, BITSPIXEL),
              "information context reports actual display dimensions and capabilities");
        before = GetPixel(drawable, 1, 1);
        CHECK(SetPixel(information, 1, 1, RGB(1, 2, 3)) == CLR_INVALID && GetLastError() == ERROR_INVALID_HANDLE,
              "information context refuses a drawing target");
        CHECK(!Rectangle(information, 0, 0, 10, 10) && GetLastError() == ERROR_INVALID_HANDLE, "information context refuses shape drawing");
        after = GetPixel(drawable, 1, 1);
        CHECK(before == after, "rejected information-context drawing never changes the display pixel buffer");
        CHECK(DeleteDC(information) && GetDeviceCaps(information, HORZRES) == 0, "information context deletes and rejects its stale handle");
    } else if (information) DeleteDC(information);
    if (drawable) DeleteDC(drawable);
    DestroyWindow(window);
    return k32t_finish("T_STEAM_TEXT");
}
