/*
 * SPDX-License-Identifier: GPL-2.0-only
 * ShizukuDOS "Shizuku" WebKit port: initialization and the offscreen page (milestone R1).
 */
#include "ShizukuConfig.h"
#include "ShizukuWebKit.h"

#include "ShizukuPlatformStrategies.h"
#include <JavaScriptCore/InitializeThreading.h>
#include <WebCore/CommonAtomStrings.h>
#include <WebCore/Document.h>
#include <WebCore/DocumentLoader.h>
#include <WebCore/DocumentWriter.h>
#include <WebCore/EmptyClients.h>
#include <WebCore/FrameLoader.h>
#include <WebCore/GraphicsContextSkia.h>
#include <WebCore/LocalFrame.h>
#include <WebCore/LocalFrameView.h>
#include <WebCore/Page.h>
#include <WebCore/ProcessCapabilities.h>
#include <WebCore/Settings.h>
#include <WebCore/SharedBuffer.h>
#include <wtf/MainThread.h>
#include <wtf/MonotonicTime.h>
#include <wtf/RunLoop.h>
#include <wtf/URL.h>
#include <windows.h>

WTF_IGNORE_WARNINGS_IN_THIRD_PARTY_CODE_BEGIN
#include <skia/core/SkCanvas.h>
#include <skia/core/SkSurface.h>
WTF_IGNORE_WARNINGS_IN_THIRD_PARTY_CODE_END

namespace Shizuku {
using namespace WebCore;

void initialize()
{
    static bool done;
    if (done)
        return;
    done = true;
    JSC::initialize();
    WTF::initializeMainThread();
    initializeCommonAtomStrings();
    ProcessCapabilities::setCanUseAcceleratedBuffers(false);
    installPlatformStrategies();
}

void pumpEvents(unsigned milliseconds)
{
    auto deadline = MonotonicTime::now() + Seconds::fromMilliseconds(milliseconds);
    do {
        MSG message;
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        auto left = deadline - MonotonicTime::now();
        if (left <= 0_s)
            break;
        MsgWaitForMultipleObjectsEx(0, nullptr, static_cast<DWORD>(std::max(1.0, left.milliseconds())), QS_ALLINPUT,
            MWMO_INPUTAVAILABLE);
    } while (true);
}

OffscreenPage::OffscreenPage(int width, int height, bool scriptEnabled)
    : m_width(width)
    , m_height(height)
{
    auto configuration = pageConfigurationWithEmptyClients(std::nullopt, PAL::SessionID::defaultSessionID());
    m_page = Page::create(WTF::move(configuration));
    Ref settings = m_page->settings();
    settings->setScriptEnabled(scriptEnabled);
    settings->setAcceleratedCompositingEnabled(false);
    settings->setAcceleratedDrawingEnabled(false);

    RefPtr frame = m_page->localMainFrame();
    frame->setView(LocalFrameView::create(*frame, IntSize(width, height)));
    frame->init();
}

OffscreenPage::~OffscreenPage() = default;

void OffscreenPage::loadHTML(std::span<const uint8_t> html, const String& baseURL)
{
    RefPtr frame = m_page->localMainFrame();
    RefPtr loader = frame->loader().activeDocumentLoader();
    auto& writer = loader->writer();
    writer.setMIMEType("text/html"_s);
    writer.begin(URL { baseURL });
    writer.addData(SharedBuffer::create(html));
    writer.end();
}

PaintTimes OffscreenPage::paint(uint32_t* pixels, size_t rowBytes)
{
    PaintTimes times;
    RefPtr frame = m_page->localMainFrame();
    RefPtr view = frame->view();
    auto t0 = MonotonicTime::now();
    view->resize(IntSize(m_width, m_height));
    if (RefPtr document = frame->document())
        document->updateLayoutIgnorePendingStylesheets();
    view->updateLayoutAndStyleIfNeededRecursive();
    auto t1 = MonotonicTime::now();

    auto info = SkImageInfo::MakeN32Premul(m_width, m_height);
    auto surface = SkSurfaces::WrapPixels(info, pixels, rowBytes);
    RELEASE_ASSERT(surface);
    SkCanvas& canvas = *surface->getCanvas();
    canvas.clear(SK_ColorWHITE);
    {
        GraphicsContextSkia context(canvas, RenderingMode::Unaccelerated, RenderingPurpose::Unspecified);
        view->paint(context, IntRect(0, 0, m_width, m_height));
    }
    auto t2 = MonotonicTime::now();
    times.layoutMs = (t1 - t0).milliseconds();
    times.paintMs = (t2 - t1).milliseconds();
    return times;
}

String OffscreenPage::documentTitle() const
{
    RefPtr frame = m_page->localMainFrame();
    RefPtr document = frame ? frame->document() : nullptr;
    return document ? document->title() : String();
}

} // namespace Shizuku
