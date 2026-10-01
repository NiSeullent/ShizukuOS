/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine transport marshalling code with mocked Windows transport endpoints.
 * iconv performs strict UTF-8 <-> UTF-16LE conversions for the host CP_ACP.
 * This tests conversion, buffer sizes, error propagation and ownership, not
 * the Kernel64 implementation of the W endpoints or Windows ABI execution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <iconv.h>
#define M98_THEME_TRANSPORT_HOST_TEST
#include "transport.c"

static unsigned checks, endpoint_calls, alloc_calls, free_calls, conversions;
static int alloc_failure, free_failure, conversion_failure, substitution, bestfit;
static unsigned heap_live;
static DWORD last_error;
static int draw_value = 19;
static BOOL spi_value = TRUE, property_success = TRUE;
static LOGFONTW source_font;
static WCHAR drawn_text[128];
static int drawn_length;
static UINT drawn_flags;
static HWND expected_window;
static HANDLE property_value;
static WCHAR property_key[64];
static LRESULT message_value = 0x12345;

#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expression); exit(1); } } while (0)

DWORD GetLastError(void) { return last_error; }
void SetLastError(DWORD value) { last_error = value; }
HANDLE GetProcessHeap(void) { return (HANDLE)(uintptr_t)0x12345678; }
PVOID HeapAlloc(HANDLE heap, DWORD flags, size_t bytes)
{
    void *value;
    CHECK(heap == GetProcessHeap()); CHECK(bytes <= 2097160u);
    ++alloc_calls;
    if (alloc_failure == (int)alloc_calls) return NULL;
    value = flags & HEAP_ZERO_MEMORY ? calloc(1, bytes) : malloc(bytes);
    CHECK(value != NULL); ++heap_live; return value;
}
BOOL HeapFree(HANDLE heap, DWORD flags, PVOID value)
{
    CHECK(heap == GetProcessHeap() && flags == 0 && value != NULL && heap_live > 0);
    free(value); --heap_live; ++free_calls;
    SetLastError(0x5555); /* Test preserving the endpoint's real error. */
    return free_failure != (int)free_calls;
}

static int convert(const char *from, const char *to, const void *input, size_t bytes,
                   void *output, size_t capacity, unsigned width)
{
    iconv_t converter;
    char scratch[8192], *source = (char *)(uintptr_t)input, *destination = scratch;
    size_t source_left = bytes, remaining = sizeof(scratch), used;
    ++conversions;
    if (conversion_failure == (int)conversions) { SetLastError(ERROR_NO_UNICODE_TRANSLATION); return 0; }
    converter = iconv_open(to, from); CHECK(converter != (iconv_t)-1);
    if (iconv(converter, &source, &source_left, &destination, &remaining) == (size_t)-1) {
        iconv_close(converter); SetLastError(ERROR_NO_UNICODE_TRANSLATION); return 0;
    }
    CHECK(iconv_close(converter) == 0); CHECK(source_left == 0);
    used = sizeof(scratch) - remaining; CHECK(used % width == 0);
    if (output) {
        if (used > capacity) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
        memcpy(output, scratch, used);
        if (bestfit && used) ((char *)output)[0] = '?';
    }
    return (int)(used / width);
}

int MultiByteToWideChar(UINT cp, DWORD flags, LPCSTR source, int count, WCHAR *out, int cap)
{
    CHECK(cp == CP_ACP && flags == MB_ERR_INVALID_CHARS && source && count > 0 && cap >= 0);
    return convert("UTF-8", "UTF-16LE", source, (size_t)count, out, (size_t)cap * 2u, 2);
}
int WideCharToMultiByte(UINT cp, DWORD flags, LPCWSTR source, int count, char *out, int cap,
                        LPCSTR default_char, BOOL *used_default)
{
    CHECK(cp == CP_ACP && flags == 0 && source && count > 0 && cap >= 0 && !default_char);
    CHECK(used_default != NULL); *used_default = substitution;
    return convert("UTF-16LE", "UTF-8", source, (size_t)count * 2u, out, (size_t)cap, 1);
}

static void record_property(HWND window, LPCWSTR key)
{
    unsigned i;
    CHECK(window == expected_window);
    for (i = 0; i < 64; ++i) { property_key[i] = key[i]; if (!key[i]) return; }
    CHECK(0);
}
HANDLE GetPropW(HWND window, LPCWSTR key)
{ ++endpoint_calls; record_property(window, key); return property_value; }
BOOL SetPropW(HWND window, LPCWSTR key, HANDLE value)
{ ++endpoint_calls; record_property(window, key); if (!property_success) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
  property_value = value; return TRUE; }
HANDLE RemovePropW(HWND window, LPCWSTR key)
{ HANDLE old = property_value; ++endpoint_calls; record_property(window, key); property_value = NULL; return old; }
LRESULT SendMessageW(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{ CHECK(window == expected_window && message == WM_THEMECHANGED && !wparam && !lparam);
  ++endpoint_calls; SetLastError(0x2345); return message_value; }

BOOL SystemParametersInfoW(UINT action, UINT parameter, PVOID out, UINT flags)
{
    NONCLIENTMETRICSW *m = out;
    ++endpoint_calls; CHECK(flags == 0 && out);
    if (!spi_value) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
    if (action == SPI_GETICONTITLELOGFONT) {
        CHECK(parameter == sizeof(LOGFONTW)); *(LOGFONTW *)out = source_font; return TRUE;
    }
    CHECK(action == SPI_GETNONCLIENTMETRICS && parameter == sizeof(*m) && m->cbSize == sizeof(*m));
    m->iBorderWidth = 2; m->iScrollWidth = 11; m->iScrollHeight = 12;
    m->iCaptionWidth = 13; m->iCaptionHeight = 14; m->iSmCaptionWidth = 15; m->iSmCaptionHeight = 16;
    m->iMenuWidth = 17; m->iMenuHeight = 18; m->iPaddedBorderWidth = 19;
    m->lfCaptionFont = m->lfSmCaptionFont = m->lfMenuFont = m->lfStatusFont = m->lfMessageFont = source_font;
    return TRUE;
}
int DrawTextW(HDC dc, LPCWSTR text, int length, LPRECT area, UINT flags)
{
    CHECK(dc == (HDC)(uintptr_t)23 && text && area && length >= 0 && length < 128);
    ++endpoint_calls; drawn_length = length; drawn_flags = flags;
    memcpy(drawn_text, text, (size_t)length * 2u); drawn_text[length] = 0;
    area->right = area->left + 123; area->bottom = area->top + 19;
    SetLastError(draw_value ? 0x1234 : ERROR_GEN_FAILURE); return draw_value;
}

static void reset(void)
{
    CHECK(heap_live == 0);
    endpoint_calls = alloc_calls = free_calls = conversions = 0;
    alloc_failure = free_failure = conversion_failure = substitution = bestfit = 0;
    draw_value = 19; spi_value = property_success = TRUE;
    last_error = 0; drawn_length = -1;
}
static void font_fixture(void)
{
    memset(&source_font, 0, sizeof(source_font));
    source_font.lfHeight = -17; source_font.lfWidth = 8; source_font.lfEscapement = 20;
    source_font.lfOrientation = 30; source_font.lfWeight = 444; source_font.lfItalic = 1;
    source_font.lfUnderline = 2; source_font.lfStrikeOut = 3; source_font.lfCharSet = 4;
    source_font.lfOutPrecision = 5; source_font.lfClipPrecision = 6; source_font.lfQuality = 7;
    source_font.lfPitchAndFamily = 8;
    source_font.lfFaceName[0] = 0xac00; source_font.lfFaceName[1] = ' '; source_font.lfFaceName[2] = 'A';
}

int main(void)
{
    HWND window = (HWND)(uintptr_t)42;
    HANDLE value = (HANDLE)(uintptr_t)0x100000101;
    char key[65];
    RECT initial = {3,4,100,50}, area;
    HDC dc = (HDC)(uintptr_t)23;
    LOGFONTA ansi, font_before;
    NONCLIENTMETRICSA metrics, before;
    const char korean[] = "\xea\xb0\x80!";
    expected_window = window; reset();
    CHECK(m98w_SetPropA(window, "M98ThemeEngine.Handle", value));
    CHECK(m98w_GetPropA(window, "M98ThemeEngine.Handle") == value);
    CHECK(m98w_RemovePropA(window, "M98ThemeEngine.Handle") == value);
    CHECK(m98w_GetPropA(window, "M98ThemeEngine.Handle") == NULL);
    CHECK(endpoint_calls == 4 && property_key[0] == 'M' && property_key[14] == '.');
    property_success = FALSE;
    CHECK(!m98w_SetPropA(window, "M98ThemeEngine.Override", value));
    CHECK(GetLastError() == ERROR_GEN_FAILURE);
    reset(); memset(key,'x',sizeof(key));
    CHECK(!m98w_SetPropA(window, key, value)); CHECK(GetLastError() == ERROR_INVALID_PARAMETER && !endpoint_calls);
    CHECK(!m98w_GetPropA(window, "")); CHECK(GetLastError() == ERROR_INVALID_PARAMETER && !endpoint_calls);
    CHECK(!m98w_GetPropA(window, NULL)); CHECK(GetLastError() == ERROR_INVALID_PARAMETER && !endpoint_calls);
    CHECK(!m98w_GetPropA(window, (LPCSTR)(uintptr_t)4)); CHECK(GetLastError() == ERROR_INVALID_PARAMETER && !endpoint_calls);
    CHECK(!m98w_RemovePropA(window, "\xc3\xa9")); CHECK(GetLastError() == ERROR_NO_UNICODE_TRANSLATION && !endpoint_calls);
    reset(); CHECK(m98w_SendMessageA(window, WM_THEMECHANGED, 0, 0) == message_value);
    CHECK(endpoint_calls == 1 && GetLastError() == 0x2345);
    CHECK(!m98w_SendMessageA(window, WM_THEMECHANGED, 1, 0)); CHECK(endpoint_calls == 1 && GetLastError() == ERROR_NOT_SUPPORTED);
    CHECK(!m98w_SendMessageA(window, 12, 0, 1)); CHECK(endpoint_calls == 1 && GetLastError() == ERROR_NOT_SUPPORTED);

    for (UINT bytes = 340; bytes <= 344; bytes += 4) {
        reset(); font_fixture(); memset(&metrics,0xa5,sizeof(metrics)); metrics.cbSize = bytes;
        CHECK(m98w_SystemParametersInfoA(SPI_GETNONCLIENTMETRICS, bytes, &metrics, 0));
        CHECK(endpoint_calls == 1 && metrics.cbSize == bytes && metrics.iBorderWidth == 2);
        CHECK(metrics.iScrollWidth == 11 && metrics.iScrollHeight == 12 && metrics.iCaptionWidth == 13 && metrics.iCaptionHeight == 14);
        CHECK(metrics.iSmCaptionWidth == 15 && metrics.iSmCaptionHeight == 16 && metrics.iMenuWidth == 17 && metrics.iMenuHeight == 18);
        CHECK(metrics.iPaddedBorderWidth == (bytes == 340 ? (int)0xa5a5a5a5u : 19));
        CHECK(!memcmp(&metrics.lfMessageFont, &source_font, offsetof(LOGFONTA, lfFaceName)));
        CHECK(!strcmp(metrics.lfCaptionFont.lfFaceName,"\xea\xb0\x80 A"));
        CHECK(!strcmp(metrics.lfSmCaptionFont.lfFaceName,"\xea\xb0\x80 A"));
        CHECK(!strcmp(metrics.lfMenuFont.lfFaceName,"\xea\xb0\x80 A"));
        CHECK(!strcmp(metrics.lfStatusFont.lfFaceName,"\xea\xb0\x80 A"));
        CHECK(!strcmp(metrics.lfMessageFont.lfFaceName,"\xea\xb0\x80 A"));
    }
    reset(); font_fixture(); memset(&ansi,0xa5,sizeof(ansi)); font_before=ansi;
    CHECK(m98w_SystemParametersInfoA(SPI_GETICONTITLELOGFONT, sizeof(ansi), &ansi, 0));
    CHECK(endpoint_calls==1 && !strcmp(ansi.lfFaceName,"\xea\xb0\x80 A"));
    CHECK(!memcmp(&ansi,&source_font,offsetof(LOGFONTA,lfFaceName)));
    reset(); ansi=font_before; spi_value=FALSE;
    CHECK(!m98w_SystemParametersInfoA(SPI_GETICONTITLELOGFONT,sizeof(ansi),&ansi,0));
    CHECK(GetLastError()==ERROR_NOT_SUPPORTED && !memcmp(&ansi,&font_before,sizeof(ansi)));
    reset(); CHECK(!m98w_SystemParametersInfoA(99,sizeof(ansi),&ansi,0)); CHECK(GetLastError()==ERROR_NOT_SUPPORTED && !endpoint_calls);
    CHECK(!m98w_SystemParametersInfoA(SPI_GETICONTITLELOGFONT,sizeof(ansi)-1,&ansi,0)); CHECK(GetLastError()==ERROR_INVALID_PARAMETER && !endpoint_calls);
    CHECK(!m98w_SystemParametersInfoA(SPI_GETICONTITLELOGFONT,sizeof(ansi),&ansi,1)); CHECK(GetLastError()==ERROR_INVALID_PARAMETER && !endpoint_calls);
    CHECK(!m98w_SystemParametersInfoA(SPI_GETNONCLIENTMETRICS,340,NULL,0)); CHECK(GetLastError()==ERROR_INVALID_PARAMETER && !endpoint_calls);
    memset(&metrics,0xa5,sizeof(metrics)); metrics.cbSize=339; before=metrics;
    CHECK(!m98w_SystemParametersInfoA(SPI_GETNONCLIENTMETRICS,339,&metrics,0)); CHECK(!endpoint_calls && !memcmp(&before,&metrics,sizeof(metrics)));
    metrics.cbSize=340; before=metrics;
    CHECK(!m98w_SystemParametersInfoA(SPI_GETNONCLIENTMETRICS,344,&metrics,0)); CHECK(!endpoint_calls && !memcmp(&before,&metrics,sizeof(metrics)));
    for (int failure=1; failure<=10; ++failure) {
        reset(); font_fixture(); memset(&metrics,0xa5,sizeof(metrics)); metrics.cbSize=344; before=metrics;
        conversion_failure=failure;
        CHECK(!m98w_SystemParametersInfoA(SPI_GETNONCLIENTMETRICS,344,&metrics,0));
        CHECK(GetLastError()==ERROR_NO_UNICODE_TRANSLATION && !memcmp(&before,&metrics,sizeof(metrics)));
    }
    reset(); font_fixture(); ansi=font_before; substitution=1;
    CHECK(!m98w_SystemParametersInfoA(SPI_GETICONTITLELOGFONT,sizeof(ansi),&ansi,0)); CHECK(GetLastError()==ERROR_NO_UNICODE_TRANSLATION && !memcmp(&ansi,&font_before,sizeof(ansi)));
    reset(); font_fixture(); ansi=font_before; bestfit=1;
    CHECK(!m98w_SystemParametersInfoA(SPI_GETICONTITLELOGFONT,sizeof(ansi),&ansi,0)); CHECK(GetLastError()==ERROR_NO_UNICODE_TRANSLATION && !memcmp(&ansi,&font_before,sizeof(ansi)));
    reset(); font_fixture(); ansi=font_before; for (unsigned i=0;i<LF_FACESIZE;++i) source_font.lfFaceName[i]='a';
    CHECK(!m98w_SystemParametersInfoA(SPI_GETICONTITLELOGFONT,sizeof(ansi),&ansi,0)); CHECK(GetLastError()==ERROR_INVALID_DATA && !memcmp(&ansi,&font_before,sizeof(ansi)));
    reset(); font_fixture(); ansi=font_before; for(unsigned i=0;i<16;++i)source_font.lfFaceName[i]=0xac00;source_font.lfFaceName[16]=0;
    CHECK(!m98w_SystemParametersInfoA(SPI_GETICONTITLELOGFONT,sizeof(ansi),&ansi,0)); CHECK(GetLastError()==ERROR_INSUFFICIENT_BUFFER && !memcmp(&ansi,&font_before,sizeof(ansi)));

    reset(); area=initial;
    CHECK(m98w_DrawTextA(dc,korean,4,&area,DT_CALCRECT|DT_NOPREFIX)==19);
    CHECK(endpoint_calls==1 && drawn_length==2 && drawn_text[0]==0xac00 && drawn_text[1]=='!' && drawn_flags==(DT_CALCRECT|DT_NOPREFIX));
    CHECK(area.right==126 && area.bottom==23 && GetLastError()==0x1234 && !heap_live);
    reset(); area=initial;
    CHECK(m98w_DrawTextA(dc,"\xf0\x9f\x98\x80",-1,&area,DT_SINGLELINE)==19);
    CHECK(drawn_length==2 && drawn_text[0]==0xd83d && drawn_text[1]==0xde00 && !heap_live);
    reset(); area=initial;
    CHECK(m98w_DrawTextA(dc,"a\0b",3,&area,0)==19); CHECK(drawn_length==3 && drawn_text[1]==0 && drawn_text[2]=='b');
    reset(); area=initial; CHECK(m98w_DrawTextA(dc,"",0,&area,0)==19); CHECK(drawn_length==0 && !heap_live);
    for (int failure=1; failure<=3; ++failure) {
        reset(); area=initial; conversion_failure=failure;
        CHECK(m98w_DrawTextA(dc,korean,4,&area,0)==0);
        CHECK(GetLastError()==ERROR_NO_UNICODE_TRANSLATION && !endpoint_calls && !heap_live && !memcmp(&area,&initial,sizeof(area)));
    }
    for (int failure=1; failure<=2; ++failure) {
        reset(); area=initial; alloc_failure=failure;
        CHECK(!m98w_DrawTextA(dc,korean,4,&area,0));
        CHECK(GetLastError()==ERROR_NOT_ENOUGH_MEMORY && !endpoint_calls && !heap_live && !memcmp(&area,&initial,sizeof(area)));
    }
    for (int failure=1; failure<=2; ++failure) {
        reset(); area=initial; free_failure=failure;
        CHECK(!m98w_DrawTextA(dc,korean,4,&area,0));
        CHECK(GetLastError()==ERROR_GEN_FAILURE && endpoint_calls==1 && !heap_live && !memcmp(&area,&initial,sizeof(area)));
    }
    reset(); area=initial; draw_value=0;
    CHECK(!m98w_DrawTextA(dc,korean,4,&area,0)); CHECK(GetLastError()==ERROR_GEN_FAILURE && !heap_live && !memcmp(&area,&initial,sizeof(area)));
    reset(); area=initial; substitution=1;
    CHECK(!m98w_DrawTextA(dc,korean,4,&area,0)); CHECK(GetLastError()==ERROR_NO_UNICODE_TRANSLATION && !endpoint_calls && !heap_live);
    reset(); area=initial; bestfit=1;
    CHECK(!m98w_DrawTextA(dc,korean,4,&area,0)); CHECK(GetLastError()==ERROR_NO_UNICODE_TRANSLATION && !endpoint_calls && !heap_live);
    reset(); area=initial;
    CHECK(!m98w_DrawTextA(dc,"\xc0\xaf",2,&area,0)); CHECK(GetLastError()==ERROR_NO_UNICODE_TRANSLATION && !endpoint_calls && !heap_live);
    CHECK(!m98w_DrawTextA(dc,"a",1,&area,DT_EXPANDTABS)); CHECK(GetLastError()==ERROR_NOT_SUPPORTED && !endpoint_calls && !heap_live);
    CHECK(!m98w_DrawTextA(dc,"a",1,&area,DT_MODIFYSTRING)); CHECK(GetLastError()==ERROR_NOT_SUPPORTED && !endpoint_calls && !heap_live);
    CHECK(!m98w_DrawTextA(dc,"a",-2,&area,0)); CHECK(GetLastError()==ERROR_INVALID_PARAMETER && !endpoint_calls && !heap_live);
    CHECK(!m98w_DrawTextA(NULL,"a",1,&area,0)); CHECK(GetLastError()==ERROR_INVALID_PARAMETER && !endpoint_calls && !heap_live);
    CHECK(!m98w_DrawTextA(dc,NULL,1,&area,0)); CHECK(GetLastError()==ERROR_INVALID_PARAMETER && !endpoint_calls && !heap_live);
    CHECK(!m98w_DrawTextA(dc,"a",1,NULL,0)); CHECK(GetLastError()==ERROR_INVALID_PARAMETER && !endpoint_calls && !heap_live);
    CHECK(!m98w_DrawTextA(dc,"a",1048577,&area,0)); CHECK(GetLastError()==ERROR_INVALID_PARAMETER && !endpoint_calls && !heap_live);
    printf("PASS: %u private Unicode transport, buffer, failure and cleanup assertions\n",checks);
    return 0;
}
