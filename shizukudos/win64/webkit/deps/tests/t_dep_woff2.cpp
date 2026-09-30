// SPDX-License-Identifier: GPL-2.0-only
// Guest check of woff2 (libwoff2enc.dll, libwoff2dec.dll over brotli; C++ through libc++.dll): convert a shipped
// TrueType font (\SHZ\FONTS\tahoma.ttf) to WOFF2 and back, and compare the sfnt table directory.
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>
#include <woff2/decode.h>
#include <woff2/encode.h>
#include <woff2/output.h>
#include "deptest.h"

static uint32_t be32(const uint8_t *p) { return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]; }
static uint16_t be16(const uint8_t *p) { return uint16_t(p[0] << 8 | p[1]); }

int main()
{
    std::ifstream in(dt_font_path("tahoma.ttf"), std::ios::binary);
    std::vector<uint8_t> ttf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::printf("font %s: %zu bytes\n", dt_font_path("tahoma.ttf"), ttf.size());
    CHECK(ttf.size() > 10000 && be32(ttf.data()) == 0x00010000);
    if (ttf.size() < 12) return DONE("t_dep_woff2");
    std::vector<uint8_t> w2(woff2::MaxWOFF2CompressedSize(ttf.data(), ttf.size()));
    size_t w2len = w2.size();
    CHECK(woff2::ConvertTTFToWOFF2(ttf.data(), ttf.size(), w2.data(), &w2len));
    CHECK(w2len > 12 && be32(w2.data()) == 0x774f4632 && w2len < ttf.size());          // 'wOF2', smaller
    std::printf("WOFF2 %zu bytes (%.1f%%)\n", w2len, 100.0 * double(w2len) / double(ttf.size()));
    const size_t final_size = woff2::ComputeWOFF2FinalSize(w2.data(), w2len);
    std::string back(final_size, '\0');
    woff2::WOFF2StringOut out(&back);
    CHECK(woff2::ConvertWOFF2ToTTF(w2.data(), w2len, &out));
    back.resize(out.Size());
    const uint8_t *b = reinterpret_cast<const uint8_t *>(back.data());
    CHECK(back.size() > 12 && be32(b) == 0x00010000 && be16(b + 4) == be16(ttf.data() + 4));   // same table count
    int same_tags = 0;
    for (int i = 0; i < be16(b + 4) && back.size() >= size_t(12 + 16 * (i + 1)); ++i)
        for (int j = 0; j < be16(ttf.data() + 4); ++j)
            if (be32(b + 12 + 16 * i) == be32(ttf.data() + 12 + 16 * j)) { ++same_tags; break; }
    CHECK(same_tags == be16(ttf.data() + 4));
    return DONE("t_dep_woff2");
}
