/*
 * SPDX-License-Identifier: GPL-2.0-only
 * T_WK_RENDER.EXE (milestone R1): renders a local HTML file with the Shizuku WebKit port, offscreen, into a 32-bit
 * top-down BMP.
 *
 *   T_WK_RENDER <page.html> <out.bmp> [width height]      (default 800x600)
 *
 * Prints one line with the timings the ISO packaging needs (milliseconds, measured in the process, QueryPerformance-
 * Counter based) and the document title:
 *   T_WK_RENDER init_ms=<> load_ms=<> layout_ms=<> paint_ms=<> first_paint_ms=<> size=<w>x<h> title="<>"
 * first_paint_ms is from process start (the earliest point the program sees) to the end of the first paint.
 * Exit code 0 when the BMP was written.
 */
#include "ShizukuConfig.h"
#include "ShizukuWebKit.h"

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <windows.h>
#include <wtf/MonotonicTime.h>
#include <wtf/text/CString.h>

static bool writeBMP(const char* path, const uint32_t* pixels, int width, int height)
{
    BITMAPFILEHEADER file { };
    BITMAPINFOHEADER info { };
    const DWORD imageBytes = static_cast<DWORD>(width) * height * 4;
    file.bfType = 0x4d42;
    file.bfOffBits = sizeof file + sizeof info;
    file.bfSize = file.bfOffBits + imageBytes;
    info.biSize = sizeof info;
    info.biWidth = width;
    info.biHeight = -height; // top-down
    info.biPlanes = 1;
    info.biBitCount = 32;
    info.biCompression = BI_RGB;
    info.biSizeImage = imageBytes;
    FILE* f = std::fopen(path, "wb");
    if (!f)
        return false;
    bool ok = std::fwrite(&file, sizeof file, 1, f) == 1 && std::fwrite(&info, sizeof info, 1, f) == 1
        && std::fwrite(pixels, 1, imageBytes, f) == imageBytes;
    return std::fclose(f) == 0 && ok;
}

int main(int argc, char** argv)
{
    auto start = WTF::MonotonicTime::now();
    if (argc < 3) {
        std::fprintf(stderr, "usage: T_WK_RENDER <page.html> <out.bmp> [width height]\n");
        return 2;
    }
    int width = argc > 4 ? std::atoi(argv[3]) : 800;
    int height = argc > 4 ? std::atoi(argv[4]) : 600;
    FILE* in = std::fopen(argv[1], "rb");
    if (!in) {
        std::fprintf(stderr, "T_WK_RENDER: cannot open %s\n", argv[1]);
        return 3;
    }
    std::vector<uint8_t> html;
    uint8_t chunk[65536];
    for (size_t n; (n = std::fread(chunk, 1, sizeof chunk, in)) > 0;)
        html.insert(html.end(), chunk, chunk + n);
    std::fclose(in);

    Shizuku::initialize();
    auto afterInit = WTF::MonotonicTime::now();
    Shizuku::OffscreenPage page(width, height);
    page.loadHTML(std::span<const uint8_t>(html.data(), html.size()), "file:///D:/WK/page.html"_s);
    Shizuku::pumpEvents(50);
    auto afterLoad = WTF::MonotonicTime::now();
    std::vector<uint32_t> pixels(static_cast<size_t>(width) * height);
    auto times = page.paint(pixels.data(), static_cast<size_t>(width) * 4);
    auto afterPaint = WTF::MonotonicTime::now();

    std::printf("T_WK_RENDER init_ms=%.1f load_ms=%.1f layout_ms=%.1f paint_ms=%.1f first_paint_ms=%.1f size=%dx%d title=\"%s\"\n",
        (afterInit - start).milliseconds(), (afterLoad - afterInit).milliseconds(), times.layoutMs, times.paintMs,
        (afterPaint - start).milliseconds(), width, height, page.documentTitle().utf8().data());
    std::fflush(stdout);
    if (!writeBMP(argv[2], pixels.data(), width, height)) {
        std::fprintf(stderr, "T_WK_RENDER: cannot write %s\n", argv[2]);
        return 4;
    }
    return 0;
}
