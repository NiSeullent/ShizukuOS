/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku checks of the ported DirectWrite: DWriteCreateFactory (chrome.dll's load-time import) must give a working
 * IDWriteFactory whose system collection contains the fonts shipped in \SHZ\FONTS (Noto Sans / Serif / Sans Mono),
 * the Windows family names Chrome asks for must resolve to them, and text must lay out with FreeType metrics and
 * rasterize (IDWriteGlyphRunAnalysis) to non-empty coverage.
 */
#define COBJMACROS
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "windef.h"
#include "winbase.h"
#include "initguid.h"
#include "dwrite_3.h"
#include "winreg.h"
#include "wine/test.h"

static void test_font_files(void)
{
    WCHAR dir[MAX_PATH], path[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    IDWriteFactory *factory;
    IDWriteFontFile *file;
    BOOL supported;
    DWRITE_FONT_FILE_TYPE ftype;
    DWRITE_FONT_FACE_TYPE face;
    UINT32 faces;
    HKEY key;
    DWORD n = 0, values = 0;
    HRESULT hr;

    GetWindowsDirectoryW(dir, MAX_PATH);
    wcscat(dir, L"\\fonts\\");
    swprintf(path, MAX_PATH, L"%s*", dir);
    if ((h = FindFirstFileW(path, &fd)) != INVALID_HANDLE_VALUE)
    {
        do { trace("font dir entry %s\n", wine_dbgstr_w(fd.cFileName)); n++; } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    ok(n >= 3, "%s holds the shipped fonts, found %lu entries (%lu)\n", wine_dbgstr_w(dir), n, GetLastError());
    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Fonts", 0, KEY_READ, &key))
    {
        RegQueryInfoKeyW(key, NULL, NULL, NULL, NULL, NULL, NULL, &values, NULL, NULL, NULL, NULL);
        RegCloseKey(key);
    }
    trace("registered fonts: %lu\n", values);
    if (FAILED(DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, &IID_IDWriteFactory, (IUnknown **)&factory))) return;
    swprintf(path, MAX_PATH, L"%sNotoSans.ttf", dir);
    hr = IDWriteFactory_CreateFontFileReference(factory, path, NULL, &file);
    ok(hr == S_OK, "CreateFontFileReference(%s): %#lx\n", wine_dbgstr_w(path), hr);
    if (hr == S_OK)
    {
        hr = IDWriteFontFile_Analyze(file, &supported, &ftype, &face, &faces);
        ok(hr == S_OK && supported && faces == 1, "Analyze: hr %#lx supported %d file type %d face type %d faces %u\n",
           hr, supported, ftype, face, faces);
        IDWriteFontFile_Release(file);
    }
    IDWriteFactory_Release(factory);
}

static void test_factory(void)
{
    IDWriteFactory *factory = NULL;
    IDWriteFontCollection *collection = NULL;
    IDWriteFontFamily *family;
    IDWriteLocalizedStrings *names;
    IDWriteTextFormat *format;
    IDWriteTextLayout *layout;
    DWRITE_TEXT_METRICS tm;
    IDWriteFont *font;
    IDWriteFontFace *face;
    DWRITE_FONT_METRICS fm;
    UINT32 count, i, index;
    BOOL exists;
    WCHAR name[128];
    HRESULT hr;

    hr = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, &IID_IDWriteFactory, (IUnknown **)&factory);
    ok(hr == S_OK && factory, "DWriteCreateFactory: %#lx\n", hr);
    if (!factory) return;
    hr = IDWriteFactory_GetSystemFontCollection(factory, &collection, FALSE);
    ok(hr == S_OK, "GetSystemFontCollection: %#lx\n", hr);
    if (!collection) { IDWriteFactory_Release(factory); return; }
    count = IDWriteFontCollection_GetFontFamilyCount(collection);
    ok(count >= 3, "expected the three Noto families, got %u\n", count);
    for (i = 0; i < count; i++)
    {
        if (FAILED(IDWriteFontCollection_GetFontFamily(collection, i, &family))) continue;
        if (SUCCEEDED(IDWriteFontFamily_GetFamilyNames(family, &names)))
        {
            IDWriteLocalizedStrings_GetString(names, 0, name, ARRAY_SIZE(name));
            trace("family %u: %s, %u fonts\n", i, wine_dbgstr_w(name), IDWriteFontFamily_GetFontCount(family));
            IDWriteLocalizedStrings_Release(names);
        }
        IDWriteFontFamily_Release(family);
    }
    hr = IDWriteFontCollection_FindFamilyName(collection, L"Noto Sans", &index, &exists);
    ok(hr == S_OK && exists, "Noto Sans is in the system collection\n");
    if (exists && SUCCEEDED(IDWriteFontCollection_GetFontFamily(collection, index, &family)))
    {
        hr = IDWriteFontFamily_GetFirstMatchingFont(family, DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STRETCH_NORMAL,
                                                    DWRITE_FONT_STYLE_NORMAL, &font);
        ok(hr == S_OK, "GetFirstMatchingFont: %#lx\n", hr);
        if (hr == S_OK)
        {
            IDWriteFont_GetMetrics(font, &fm);
            ok(fm.designUnitsPerEm == 1000 && fm.ascent > 0 && fm.descent > 0, "Noto Sans metrics: upem %u ascent %u descent %u\n",
               fm.designUnitsPerEm, fm.ascent, fm.descent);
            hr = IDWriteFont_CreateFontFace(font, &face);
            ok(hr == S_OK, "CreateFontFace: %#lx\n", hr);
            if (hr == S_OK)
            {
                UINT32 cp = 'A';
                UINT16 glyph = 0;
                DWRITE_GLYPH_METRICS gm;
                ok(IDWriteFontFace_GetGlyphIndices(face, &cp, 1, &glyph) == S_OK && glyph, "glyph for 'A': %u\n", glyph);
                ok(IDWriteFontFace_GetDesignGlyphMetrics(face, &glyph, 1, &gm, FALSE) == S_OK && gm.advanceWidth > 0,
                   "design advance of 'A': %u\n", gm.advanceWidth);
                IDWriteFontFace_Release(face);
            }
            IDWriteFont_Release(font);
        }
        IDWriteFontFamily_Release(family);
    }

    /* a text format for a family Chrome requests by its Windows name */
    hr = IDWriteFactory_CreateTextFormat(factory, L"Arial", NULL, DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STYLE_NORMAL,
                                         DWRITE_FONT_STRETCH_NORMAL, 16.0f, L"en-us", &format);
    ok(hr == S_OK, "CreateTextFormat(Arial): %#lx\n", hr);
    if (hr == S_OK)
    {
        hr = IDWriteFactory_CreateTextLayout(factory, L"Hello, Shizuku", 14, format, 500.0f, 100.0f, &layout);
        ok(hr == S_OK, "CreateTextLayout: %#lx\n", hr);
        if (hr == S_OK)
        {
            hr = IDWriteTextLayout_GetMetrics(layout, &tm);
            ok(hr == S_OK && tm.width > 50.0f && tm.width < 200.0f && tm.height > 10.0f && tm.lineCount == 1,
               "layout metrics: hr %#lx width %.2f height %.2f lines %u\n", hr, tm.width, tm.height, tm.lineCount);
            IDWriteTextLayout_Release(layout);
        }
        IDWriteTextFormat_Release(format);
    }
    IDWriteFontCollection_Release(collection);
    IDWriteFactory_Release(factory);
}

static void test_rasterization(void)
{
    IDWriteFactory *factory;
    IDWriteFontCollection *collection;
    IDWriteFontFamily *family;
    IDWriteFont *font;
    IDWriteFontFace *face;
    IDWriteGlyphRunAnalysis *analysis;
    DWRITE_GLYPH_RUN run;
    UINT32 cp = 'W', index;
    UINT16 glyph;
    FLOAT advance = 0.0f;
    DWRITE_GLYPH_OFFSET offset = { 0 };
    RECT bounds;
    BYTE *bits;
    unsigned int size, covered = 0, k;
    BOOL exists;
    HRESULT hr;

    if (FAILED(DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, &IID_IDWriteFactory, (IUnknown **)&factory))) return;
    IDWriteFactory_GetSystemFontCollection(factory, &collection, FALSE);
    IDWriteFontCollection_FindFamilyName(collection, L"Noto Serif", &index, &exists);
    ok(exists, "Noto Serif is in the system collection\n");
    if (!exists) { IDWriteFontCollection_Release(collection); IDWriteFactory_Release(factory); return; }
    IDWriteFontCollection_GetFontFamily(collection, index, &family);
    IDWriteFontFamily_GetFirstMatchingFont(family, DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STRETCH_NORMAL,
                                           DWRITE_FONT_STYLE_NORMAL, &font);
    IDWriteFont_CreateFontFace(font, &face);
    IDWriteFontFace_GetGlyphIndices(face, &cp, 1, &glyph);
    memset(&run, 0, sizeof(run));
    run.fontFace = face;
    run.fontEmSize = 32.0f;
    run.glyphCount = 1;
    run.glyphIndices = &glyph;
    run.glyphAdvances = &advance;
    run.glyphOffsets = &offset;
    hr = IDWriteFactory_CreateGlyphRunAnalysis(factory, &run, 1.0f, NULL, DWRITE_RENDERING_MODE_NATURAL,
                                               DWRITE_MEASURING_MODE_NATURAL, 0.0f, 0.0f, &analysis);
    ok(hr == S_OK, "CreateGlyphRunAnalysis: %#lx\n", hr);
    if (hr == S_OK)
    {
        hr = IDWriteGlyphRunAnalysis_GetAlphaTextureBounds(analysis, DWRITE_TEXTURE_CLEARTYPE_3x1, &bounds);
        ok(hr == S_OK && bounds.right - bounds.left > 10 && bounds.bottom - bounds.top > 10,
           "texture bounds %ld,%ld-%ld,%ld (%#lx)\n", bounds.left, bounds.top, bounds.right, bounds.bottom, hr);
        size = (bounds.right - bounds.left) * (bounds.bottom - bounds.top) * 3;
        bits = malloc(size ? size : 1);
        hr = IDWriteGlyphRunAnalysis_CreateAlphaTexture(analysis, DWRITE_TEXTURE_CLEARTYPE_3x1, &bounds, bits, size);
        for (k = 0; k < size; k++) covered += bits[k] != 0;
        ok(hr == S_OK && covered > size / 20, "'W' at 32 px covers %u of %u samples (%#lx)\n", covered, size, hr);
        free(bits);
        IDWriteGlyphRunAnalysis_Release(analysis);
    }
    IDWriteFontFace_Release(face);
    IDWriteFont_Release(font);
    IDWriteFontFamily_Release(family);
    IDWriteFontCollection_Release(collection);
    IDWriteFactory_Release(factory);
}

START_TEST(factory)
{
    test_font_files();
    test_factory();
    test_rasterization();
}
