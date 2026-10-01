/* SPDX-License-Identifier: GPL-2.0-only
 * Actual production WinHttpCrackUrl omission contract fixture.
 * Includes the complete TU, never an extracted or copied parser. Windows
 * declarations are test-only; only SetLastError/GetLastError are implemented.
 * No socket, HTTP/TLS, Windows guest or application behavior is established.
 */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define DLLAPI
#include "../win64/dlls/winhttp/winhttp.c"

static DWORD fixture_error;
VOID WINAPI SetLastError(DWORD error) { fixture_error = error; }
DWORD WINAPI GetLastError(void) { return fixture_error; }

static unsigned checks, failures;
static void check(int condition, const char *tag)
{
    ++checks;
    if (!condition) { ++failures; fprintf(stderr, "ASSERT: %s\n", tag); }
}
static size_t fixture_length(const WCHAR *text)
{
    size_t count = 0;
    while (text[count]) ++count;
    return count;
}
static int wide_equal(const WCHAR *actual, const WCHAR *expected)
{
    size_t length = fixture_length(expected);
    return !memcmp(actual, expected, (length + 1) * sizeof(WCHAR));
}
static void fill(WCHAR *data, size_t count)
{
    size_t i;
    for (i = 0; i < count; ++i) data[i] = (WCHAR)0x5aa5;
}
static void tagged_check(int condition, const char *mode, const char *name, const char *property)
{
    char tag[160];
    int count = snprintf(tag, sizeof tag, "%s %s %s", mode, name, property);
    if (count < 0 || (size_t)count >= sizeof tag) {
        fprintf(stderr, "FIXTURE_ERROR: assertion tag overflow\n");
        failures += 1;
        return;
    }
    check(condition, tag);
}

typedef struct { const char *name; const WCHAR *url, *path; } omission_case;
static const omission_case OMITTED[] = {
    { "query", L"https://h.test/update?channel=stable", L"/update?channel=stable" },
    { "fragment", L"https://h.test/page#part", L"/page#part" },
    { "query-fragment", L"https://h.test/update?channel=stable#part", L"/update?channel=stable#part" },
    { "empty-query-fragment", L"https://h.test/page?#part", L"/page?#part" }
};

static void omitted_copy(const omission_case *item)
{
    WCHAR input[128], original[128], guarded[96];
    URL_COMPONENTS uc;
    size_t bytes = (fixture_length(item->url) + 1) * sizeof(WCHAR);
    int result;
    memset(input, 0, sizeof input);
    memcpy(input, item->url, bytes);
    memcpy(original, input, sizeof input);
    fill(guarded, sizeof guarded / sizeof guarded[0]);
    memset(&uc, 0, sizeof uc);
    uc.dwStructSize = sizeof uc;
    uc.lpszUrlPath = guarded + 2;
    uc.dwUrlPathLength = 80;
    result = WinHttpCrackUrl(input, 0, 0, &uc);
    tagged_check(result == TRUE, "omitted copy", item->name, "succeeds");
    tagged_check(uc.nScheme == INTERNET_SCHEME_HTTPS, "omitted copy", item->name, "scheme");
    tagged_check(uc.nPort == 443, "omitted copy", item->name, "port");
    tagged_check(uc.lpszExtraInfo == NULL && uc.dwExtraInfoLength == 0,
                 "omitted copy", item->name, "extra remains unrequested");
    tagged_check(uc.dwUrlPathLength == fixture_length(item->path),
                 "omitted copy", item->name, "full length");
    tagged_check(wide_equal(guarded + 2, item->path), "omitted copy", item->name, "full payload");
    tagged_check(!memcmp(input, original, sizeof input), "omitted copy", item->name, "input preserved");
    tagged_check(guarded[0] == (WCHAR)0x5aa5 && guarded[1] == (WCHAR)0x5aa5 &&
                 guarded[82] == (WCHAR)0x5aa5, "omitted copy", item->name, "guards preserved");
}

static void omitted_borrow(const omission_case *item)
{
    WCHAR input[128], original[128];
    URL_COMPONENTS uc;
    size_t bytes = (fixture_length(item->url) + 1) * sizeof(WCHAR);
    int result;
    memset(input, 0, sizeof input);
    memcpy(input, item->url, bytes);
    memcpy(original, input, sizeof input);
    memset(&uc, 0, sizeof uc);
    uc.dwStructSize = sizeof uc;
    uc.dwUrlPathLength = 1; /* NULL plus nonzero length explicitly borrows. */
    result = WinHttpCrackUrl(input, 0, 0, &uc);
    tagged_check(result == TRUE, "omitted borrow", item->name, "succeeds");
    tagged_check(uc.nScheme == INTERNET_SCHEME_HTTPS && uc.nPort == 443,
                 "omitted borrow", item->name, "scheme and port");
    tagged_check(uc.lpszUrlPath == input + 14, "omitted borrow", item->name, "exact input pointer");
    tagged_check(uc.dwUrlPathLength == fixture_length(item->path),
                 "omitted borrow", item->name, "full length");
    tagged_check(uc.lpszExtraInfo == NULL && uc.dwExtraInfoLength == 0,
                 "omitted borrow", item->name, "extra remains unrequested");
    tagged_check(!memcmp(input, original, sizeof input), "omitted borrow", item->name, "input preserved");
}

static void requested_extra_controls(void)
{
    static const WCHAR input[] = L"https://h.test/update?channel=stable#part";
    static const WCHAR path[] = L"/update", extra[] = L"?channel=stable#part";
    WCHAR host[32], copied_path[64], copied_extra[64];
    URL_COMPONENTS uc;
    int result;
    fill(host, 32); fill(copied_path, 64); fill(copied_extra, 64);
    memset(&uc, 0, sizeof uc);
    uc.dwStructSize = sizeof uc;
    uc.lpszHostName = host; uc.dwHostNameLength = 32;
    uc.lpszUrlPath = copied_path; uc.dwUrlPathLength = 64;
    uc.lpszExtraInfo = copied_extra; uc.dwExtraInfoLength = 64;
    result = WinHttpCrackUrl(input, 0, 0, &uc);
    check(result == TRUE, "requested copy succeeds");
    check(uc.nScheme == INTERNET_SCHEME_HTTPS, "requested copy scheme");
    check(uc.nPort == 443, "requested copy port");
    check(uc.dwHostNameLength == 6, "requested copy host length");
    check(wide_equal(host, L"h.test"), "requested copy host payload");
    check(uc.dwUrlPathLength == fixture_length(path), "requested copy path length");
    check(wide_equal(copied_path, path), "requested copy path payload");
    check(uc.dwExtraInfoLength == fixture_length(extra), "requested copy extra length");
    check(wide_equal(copied_extra, extra), "requested copy extra payload");
    check(copied_path[63] == (WCHAR)0x5aa5, "requested copy path guard");
    check(copied_extra[63] == (WCHAR)0x5aa5, "requested copy extra guard");

    memset(&uc, 0, sizeof uc);
    uc.dwStructSize = sizeof uc;
    uc.dwUrlPathLength = 1;
    uc.dwExtraInfoLength = 1; /* NULL plus nonzero means requested, not omitted. */
    result = WinHttpCrackUrl(input, 0, 0, &uc);
    check(result == TRUE, "requested borrow succeeds");
    check(uc.lpszUrlPath == input + 14, "requested borrow exact path pointer");
    check(uc.dwUrlPathLength == fixture_length(path), "requested borrow path length");
    check(uc.lpszExtraInfo == input + 14 + fixture_length(path), "requested borrow exact extra pointer");
    check(uc.dwExtraInfoLength == fixture_length(extra), "requested borrow extra length");
    check(wide_equal(uc.lpszExtraInfo, extra), "requested borrow extra payload");

    /* Mixed copied/borrowed fields obey the same independent request lengths. */
    memset(&uc, 0, sizeof uc);
    uc.dwStructSize = sizeof uc;
    uc.lpszUrlPath = copied_path; uc.dwUrlPathLength = 64;
    uc.dwExtraInfoLength = 1;
    check(WinHttpCrackUrl(input, 0, 0, &uc) == TRUE, "mixed copied path borrowed extra succeeds");
    check(wide_equal(copied_path, path) && uc.dwUrlPathLength == fixture_length(path),
          "mixed copied path excludes requested extra");
    check(uc.lpszExtraInfo == input + 21 && uc.dwExtraInfoLength == fixture_length(extra),
          "mixed borrowed extra has exact pointer and length");
}

static void omitted_capacity(const char *name, DWORD capacity)
{
    static const WCHAR input[] = L"https://h.test/update?channel=stable#part";
    static const WCHAR expected[] = L"/update?channel=stable#part";
    WCHAR destination[64], original[64];
    URL_COMPONENTS uc;
    int result;
    fill(destination, 64); memcpy(original, destination, sizeof destination);
    memset(&uc, 0, sizeof uc);
    uc.dwStructSize = sizeof uc;
    uc.lpszUrlPath = destination; uc.dwUrlPathLength = capacity;
    SetLastError(0x13572468);
    result = WinHttpCrackUrl(input, 0, 0, &uc);
    tagged_check(result == FALSE, "omitted capacity", name, "rejected");
    tagged_check(GetLastError() == ERROR_INSUFFICIENT_BUFFER,
                 "omitted capacity", name, "insufficient buffer");
    tagged_check(uc.dwUrlPathLength == fixture_length(expected) + 1,
                 "omitted capacity", name, "full requirement");
    tagged_check(!memcmp(destination, original, sizeof destination),
                 "omitted capacity", name, "destination preserved");
}

static void exact_capacity_and_explicit_length(void)
{
    static const WCHAR input[] = L"https://h.test/update?channel=stable#part";
    static const WCHAR expected[] = L"/update?channel=stable#part";
    WCHAR guarded[64], bounded[128], original[128];
    URL_COMPONENTS uc;
    size_t length = fixture_length(expected), valid_length = fixture_length(input);
    int result;
    fill(guarded, 64);
    memset(&uc, 0, sizeof uc);
    uc.dwStructSize = sizeof uc;
    uc.lpszUrlPath = guarded + 2; uc.dwUrlPathLength = (DWORD)length + 1;
    check(WinHttpCrackUrl(input, 0, 0, &uc) == TRUE, "omitted exact capacity succeeds");
    check(uc.dwUrlPathLength == length, "omitted exact capacity full length");
    check(wide_equal(guarded + 2, expected), "omitted exact capacity full payload");
    check(guarded[1] == (WCHAR)0x5aa5, "omitted exact capacity prefix guard");
    check(guarded[2 + length + 1] == (WCHAR)0x5aa5, "omitted exact capacity suffix guard");

    /* The supplied prefix has no NUL. A readable suffix is outside dwUrlLength. */
    fill(bounded, 128);
    memcpy(bounded, input, valid_length * sizeof(WCHAR));
    memcpy(bounded + valid_length, L"IGNORED?wrong#tail", sizeof L"IGNORED?wrong#tail");
    memcpy(original, bounded, sizeof bounded);
    fill(guarded, 64);
    memset(&uc, 0, sizeof uc);
    uc.dwStructSize = sizeof uc;
    uc.lpszUrlPath = guarded; uc.dwUrlPathLength = 64;
    result = WinHttpCrackUrl(bounded, (DWORD)valid_length, 0, &uc);
    check(result == TRUE, "omitted explicit copy succeeds");
    check(uc.dwUrlPathLength == length, "omitted explicit copy full length");
    check(wide_equal(guarded, expected), "omitted explicit copy full payload");
    check(!memcmp(bounded, original, sizeof bounded), "omitted explicit copy input preserved");
    memset(&uc, 0, sizeof uc);
    uc.dwStructSize = sizeof uc; uc.dwUrlPathLength = 1;
    result = WinHttpCrackUrl(bounded, (DWORD)valid_length, 0, &uc);
    check(result == TRUE, "omitted explicit borrow succeeds");
    check(uc.lpszUrlPath == bounded + 14, "omitted explicit borrow exact pointer");
    check(uc.dwUrlPathLength == length, "omitted explicit borrow full length");
    check(!memcmp(bounded, original, sizeof bounded), "omitted explicit borrow input preserved");

    memset(&uc, 0, sizeof uc);
    uc.dwStructSize = sizeof uc; uc.dwUrlPathLength = 1; uc.dwExtraInfoLength = 1;
    check(WinHttpCrackUrl(bounded, (DWORD)valid_length, 0, &uc) == TRUE,
          "requested explicit borrowed fields succeed");
    check(uc.dwUrlPathLength == 7 && uc.dwExtraInfoLength == length - 7,
          "requested explicit borrowed fields exclude suffix");
    check(uc.lpszExtraInfo == bounded + 21, "requested explicit borrowed extra pointer");
}

static void ordinary_controls(void)
{
    URL_COMPONENTS uc;
    WCHAR destination[32];
    memset(&uc, 0, sizeof uc);
    uc.dwStructSize = sizeof uc; uc.lpszUrlPath = destination; uc.dwUrlPathLength = 32;
    check(WinHttpCrackUrl(L"http://h.test/plain", 0, 0, &uc) == TRUE,
          "ordinary path copy succeeds");
    check(uc.nScheme == INTERNET_SCHEME_HTTP && uc.nPort == 80,
          "ordinary path HTTP scheme and port");
    check(uc.dwUrlPathLength == 6 && wide_equal(destination, L"/plain"),
          "ordinary path without extra unchanged");
    memset(&uc, 0, sizeof uc);
    uc.dwStructSize = sizeof uc;
    check(WinHttpCrackUrl(L"https://h.test/update?channel=stable#part", 0, 0, &uc) == TRUE,
          "unrequested path and extra succeed");
    check(uc.lpszUrlPath == NULL && uc.dwUrlPathLength == 0 &&
          uc.lpszExtraInfo == NULL && uc.dwExtraInfoLength == 0,
          "unrequested path and extra remain untouched");
    check(!WinHttpCrackUrl(NULL, 0, 0, &uc) && GetLastError() == ERROR_INVALID_PARAMETER,
          "null URL rejected");
    check(!WinHttpCrackUrl(L"https://h.test/x", 0, 0, NULL) && GetLastError() == ERROR_INVALID_PARAMETER,
          "null component descriptor rejected");
    uc.dwStructSize = 3;
    check(!WinHttpCrackUrl(L"https://h.test/x", 0, 0, &uc) && GetLastError() == ERROR_INVALID_PARAMETER,
          "wrong component descriptor size rejected");
}

int main(void)
{
    size_t i;
    check(sizeof(WCHAR) == 2 && sizeof L"x" == 4, "UTF16 scalar and literal widths");
    check(sizeof(DWORD) == 4 && sizeof(INTERNET_PORT) == 2 && sizeof(URL_COMPONENTS) == 104,
          "Win64 URL component ABI sizes");
    for (i = 0; i < sizeof OMITTED / sizeof OMITTED[0]; ++i) {
        omitted_copy(&OMITTED[i]); omitted_borrow(&OMITTED[i]);
    }
    requested_extra_controls();
    omitted_capacity("prefix-only", 8);
    omitted_capacity("missing-terminator", (DWORD)fixture_length(L"/update?channel=stable#part"));
    exact_capacity_and_explicit_length();
    ordinary_controls();
    if (failures) {
        printf("FAIL: %u of %u WinHTTP URL omission checks\n", failures, checks);
        return 1;
    }
    printf("PASS: %u WinHTTP URL omission checks\n", checks);
    return 0;
}
