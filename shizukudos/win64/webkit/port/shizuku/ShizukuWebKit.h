/*
 * SPDX-License-Identifier: GPL-2.0-only
 * ShizukuDOS "Shizuku" WebKit port: the embedding API of the single-process port.
 */
#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <wtf/text/WTFString.h>

namespace WebCore {
class Page;
}

namespace Shizuku {

// JavaScriptCore, WTF (main thread, Win32 message-pump RunLoop) and WebCore, plus the port's platform strategies and
// no accelerated buffers. Call once, on the thread that will be WebKit's main thread.
void initialize();

// Runs the main thread's pending work (window messages of the RunLoop, WebCore timers) for up to `milliseconds`.
void pumpEvents(unsigned milliseconds);

struct PaintTimes {
    double layoutMs { 0 };
    double paintMs { 0 };
};

// A page without a window (milestone R1): the document is written straight into the main frame's DocumentWriter
// (no loader, as WebCore's own SVGImage does), laid out at a fixed viewport size and painted by Skia into caller
// memory, 32-bit BGRA premultiplied, top-down (the layout of a Windows top-down DIB section).
class OffscreenPage {
public:
    OffscreenPage(int width, int height, bool scriptEnabled = true);
    ~OffscreenPage();

    void loadHTML(std::span<const uint8_t> html, const String& baseURL);
    PaintTimes paint(uint32_t* pixels, size_t rowBytes);
    String documentTitle() const;

private:
    int m_width;
    int m_height;
    RefPtr<WebCore::Page> m_page;
};

} // namespace Shizuku
