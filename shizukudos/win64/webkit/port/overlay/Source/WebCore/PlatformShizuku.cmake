# ShizukuDOS "Shizuku" port (overlay, shizukudos/win64/webkit/port): WebCore for the Kernel64 Win64 runtime.
# The Shizuku port is PLATFORM(WIN) (WTF's PlatformLegacy.h defines it for OS(WINDOWS) ports without their own
# PLATFORM), so this is the Windows port's file list (PlatformWin.cmake at the pinned commit) minus what the Shizuku
# runtime cannot back at all: the resource-usage overlay, ANGLE (PlatformDisplayANGLE, GraphicsContextGLEGL: no
# Direct3D/OpenGL), full-screen windows and Media Foundation --
# with the Skia fonts from FreeType and the system font directory instead of DirectWrite (FontCacheSkiaWin.cpp is
# replaced by the port's FontManagerShizuku.cpp, selected by USE(SHIZUKU) in FontCacheSkia.cpp). Win32 functions the
# runtime lacks bind to the W3 compat library at link time (deps/compat), not to #ifdefs here.

include(platform/Adwaita.cmake)
include(platform/Curl.cmake)
include(platform/ImageDecoders.cmake)
include(platform/OpenSSL.cmake)
include(platform/Skia.cmake)

list(APPEND WebCore_PRIVATE_INCLUDE_DIRECTORIES
    "${WEBCORE_DIR}/accessibility/win"
    "${WEBCORE_DIR}/page/win"
    "${WEBCORE_DIR}/platform/graphics/egl"
    "${WEBCORE_DIR}/platform/graphics/opengl"
    "${WEBCORE_DIR}/platform/graphics/opentype"
    "${WEBCORE_DIR}/platform/graphics/win"
    "${WEBCORE_DIR}/platform/mediacapabilities"
    "${WEBCORE_DIR}/platform/network/win"
    "${WEBCORE_DIR}/platform/video-codecs"
    "${WEBCORE_DIR}/platform/win"
    "${SHIZUKU_PORT_DIR}/webcore"
)

list(APPEND WebCore_SOURCES
    accessibility/win/AXObjectCacheWin.cpp
    accessibility/win/AccessibilityObjectWin.cpp
    accessibility/win/AccessibilityObjectWrapperWin.cpp
    editing/win/EditorWin.cpp
    html/HTMLSelectElementWin.cpp
    page/win/DragControllerWin.cpp
    page/win/EventHandlerWin.cpp
    page/win/FrameWin.cpp
    platform/Cursor.cpp
    platform/LocalizedStrings.cpp
    platform/StaticPasteboard.cpp
    platform/audio/PlatformMediaSessionManager.cpp
    platform/generic/KeyedDecoderGeneric.cpp
    platform/generic/KeyedEncoderGeneric.cpp
    platform/graphics/PlatformDisplay.cpp
    platform/graphics/egl/BitmapTexture.cpp
    platform/graphics/egl/BitmapTexturePool.cpp
    platform/graphics/egl/GLContext.cpp
    platform/graphics/egl/GLContextWrapper.cpp
    platform/graphics/egl/GLDisplay.cpp
    platform/graphics/egl/GLFence.cpp
    platform/graphics/egl/GLFenceEGL.cpp
    platform/graphics/egl/GLFenceGL.cpp
    platform/graphics/opentype/OpenTypeUtilities.cpp
    platform/graphics/win/DIBPixelData.cpp
    platform/graphics/win/DisplayRefreshMonitorWin.cpp
    platform/graphics/win/FloatPointWin.cpp
    platform/graphics/win/FloatRectWin.cpp
    platform/graphics/win/GraphicsContextWin.cpp
    platform/graphics/win/IconWin.cpp
    platform/graphics/win/ImageAdapterWin.cpp
    platform/graphics/win/IntPointWin.cpp
    platform/graphics/win/IntRectWin.cpp
    platform/graphics/win/IntSizeWin.cpp
    platform/graphics/win/PlatformDisplayWin.cpp
    platform/graphics/win/SystemFontDatabaseWin.cpp
    platform/graphics/win/TransformationMatrixWin.cpp
    platform/network/win/CurlSSLHandleWin.cpp
    platform/network/win/NetworkStateNotifierWin.cpp
    platform/text/Hyphenation.cpp
    platform/text/LocaleICU.cpp
    platform/win/BString.cpp
    platform/win/BitmapInfo.cpp
    platform/win/ClipboardUtilitiesWin.cpp
    platform/win/CursorWin.cpp
    platform/win/DragDataWin.cpp
    platform/win/GDIUtilities.cpp
    platform/win/KeyEventWin.cpp
    platform/win/LoggingWin.cpp
    platform/win/MIMETypeRegistryWin.cpp
    platform/win/MainThreadSharedTimerWin.cpp
    platform/win/PasteboardWin.cpp
    platform/win/PlatformMouseEventWin.cpp
    platform/win/PlatformPasteboardWin.cpp
    platform/win/PlatformScreenWin.cpp
    platform/win/SearchPopupMenuDB.cpp
    platform/win/SharedMemoryWin.cpp
    platform/win/SystemInfo.cpp
    platform/win/UserAgentWin.cpp
    platform/win/WCDataObject.cpp
    platform/win/WebCoreBundleWin.cpp
    platform/win/WebCoreInstanceHandle.cpp
    platform/win/WebCoreTextRenderer.cpp
    platform/win/WheelEventWin.cpp
    platform/win/WindowMessageBroadcaster.cpp
    platform/win/WindowsKeyNames.cpp

    platform/skia/DragImageSkia.cpp

    "${SHIZUKU_PORT_DIR}/webcore/FontManagerShizuku.cpp"
)

list(APPEND WebCore_PRIVATE_FRAMEWORK_HEADERS
    accessibility/win/AccessibilityObjectWrapperWin.h
    page/win/FrameWin.h
    platform/graphics/opentype/FontMemoryResource.h
    platform/graphics/win/DIBPixelData.h
    platform/graphics/win/LocalWindowsContext.h
    platform/graphics/win/SharedGDIObject.h
    platform/win/BString.h
    platform/win/BitmapInfo.h
    platform/win/COMPtr.h
    platform/win/GDIUtilities.h
    platform/win/HWndDC.h
    platform/win/SearchPopupMenuDB.h
    platform/win/SystemInfo.h
    platform/win/WCDataObject.h
    platform/win/WebCoreBundleWin.h
    platform/win/WebCoreTextRenderer.h
    platform/win/WindowMessageBroadcaster.h
    platform/win/WindowMessageListener.h
    platform/win/WindowsKeyNames.h
)

list(APPEND WebCore_LIBRARIES
    ShizukuEGL
    crypt32
    iphlpapi
    usp10
    ws2_32
)

if (USE_WOFF2)
    # Static WOFF2: add what WOFF2::dec needs (as the Windows port does)
    list(APPEND WebCore_LIBRARIES
        Brotli::dec
        WOFF2::common
    )
endif ()

set(iconFiles
    Resources/missingImage.png
    Resources/missingImage@2x.png
    Resources/missingImage@3x.png
    Resources/panIcon.png
    Resources/textAreaResizeCorner.png
    Resources/textAreaResizeCorner@2x.png
)
file(COPY ${iconFiles} DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/WebKit.resources/icons)
