/*
 * SPDX-License-Identifier: GPL-2.0-only
 * ShizukuDOS "Shizuku" WebKit port: WebCore's platform strategies for the single-process port.
 *
 * This first version serves milestone R1 (offscreen rendering of documents given as data): the loader strategy fails
 * every network load with a cancellation error (documents are written straight into the frame's DocumentWriter, so
 * no resource loader is needed), the pasteboard is empty, and blobs are not supported. R2/R3 replace the loader with
 * the curl-backed one.
 */
#include "ShizukuConfig.h"
#include "ShizukuPlatformStrategies.h"

#include <WebCore/BlobRegistry.h>
#include <WebCore/CachedResource.h>
#include <WebCore/LoaderStrategy.h>
#include <WebCore/LocalFrame.h>
#include <WebCore/MediaStrategy.h>
#include <WebCore/NetworkLoadMetrics.h>
#include <WebCore/PasteboardItemInfo.h>
#include <WebCore/PasteboardStrategy.h>
#include <WebCore/ResourceError.h>
#include <WebCore/ResourceRequest.h>
#include <WebCore/ResourceResponse.h>
#include <WebCore/SharedBuffer.h>
#include <WebCore/SubresourceLoader.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/URL.h>

namespace Shizuku {
using namespace WebCore;

static constexpr auto errorDomain = "ShizukuWebKit"_s;

class LoaderStrategyNoNetwork final : public LoaderStrategy {
    WTF_MAKE_FAST_ALLOCATED;
public:
    static ResourceError error(const URL& url, int code, ASCIILiteral text, ResourceError::Type type = ResourceError::Type::General)
    {
        return ResourceError(errorDomain, code, url, String(text), type);
    }

    void loadResource(LocalFrame&, CachedResource&, ResourceRequest&&, const ResourceLoaderOptions&, CompletionHandler<void(RefPtr<SubresourceLoader>&&)>&& completion) final
    {
        completion(nullptr);
    }
    void loadResourceSynchronously(FrameLoader&, ResourceLoaderIdentifier, const ResourceRequest& request, ClientCredentialPolicy, const FetchOptions&, const HTTPHeaderMap&, ResourceError& outError, ResourceResponse&, Vector<uint8_t>&) final
    {
        outError = cancelledError(request);
    }
    void pageLoadCompleted(Page&) final { }
    void browsingContextRemoved(LocalFrame&) final { }
    void remove(ResourceLoader*) final { }
    void setDefersLoading(ResourceLoader&, bool) final { }
    void crossOriginRedirectReceived(ResourceLoader*, const URL&) final { }
    void servePendingRequests(ResourceLoadPriority) final { }
    void suspendPendingRequests() final { }
    void resumePendingRequests() final { }
    void preconnectTo(FrameLoader&, ResourceRequest&& request, StoredCredentialsPolicy, ShouldPreconnectAsFirstParty, PreconnectCompletionHandler&& completion) final
    {
        if (completion)
            completion(cancelledError(request));
    }
    void setCaptureExtraNetworkLoadMetricsEnabled(bool) final { }
    bool isOnLine() const final { return false; }
    void addOnlineStateChangeListener(Function<void(bool)>&&) final { }
    void isResourceLoadFinished(CachedResource&, CompletionHandler<void(bool)>&& callback) final { callback(true); }

    ResourceError cancelledError(const ResourceRequest& r) const final { return error(r.url(), 1, "Cancelled"_s, ResourceError::Type::Cancellation); }
    ResourceError blockedError(const ResourceRequest& r) const final { return error(r.url(), 2, "Blocked"_s); }
    bool isBlockedError(const ResourceError& e) const final { return e.domain() == errorDomain && e.errorCode() == 2; }
    ResourceError blockedByContentBlockerError(const ResourceRequest& r) const final { return error(r.url(), 3, "Blocked by a content blocker"_s); }
    ResourceError cannotShowURLError(const ResourceRequest& r) const final { return error(r.url(), 4, "Cannot show this URL"_s); }
    ResourceError interruptedForPolicyChangeError(const ResourceRequest& r) const final { return error(r.url(), 5, "Interrupted by a policy change"_s); }
#if ENABLE(CONTENT_FILTERING)
    ResourceError blockedByContentFilterError(const ResourceRequest& r) const final { return error(r.url(), 6, "Blocked by a content filter"_s); }
#endif
    ResourceError cannotShowMIMETypeError(const ResourceResponse& r) const final { return error(r.url(), 7, "Cannot show this content type"_s); }
    ResourceError fileDoesNotExistError(const ResourceResponse& r) const final { return error(r.url(), 8, "File does not exist"_s); }
    ResourceError httpsUpgradeRedirectLoopError(const ResourceRequest& r) const final { return error(r.url(), 9, "HTTPS upgrade redirect loop"_s); }
    ResourceError httpNavigationWithHTTPSOnlyError(const ResourceRequest& r) const final { return error(r.url(), 10, "HTTP navigation in HTTPS-only mode"_s); }
    bool isHttpNavigationWithHTTPSOnlyError(const ResourceError& e) const final { return e.domain() == errorDomain && e.errorCode() == 10; }
    ResourceError pluginWillHandleLoadError(const ResourceResponse& r) const final { return error(r.url(), 11, "Plug-in will handle the load"_s); }
};

class PasteboardStrategyEmpty final : public PasteboardStrategy {
    WTF_MAKE_FAST_ALLOCATED;
public:
    String readStringFromPasteboard(size_t, const String&, const String&, const PasteboardContext*) final { return { }; }
    RefPtr<SharedBuffer> readBufferFromPasteboard(std::optional<size_t>, const String&, const String&, const PasteboardContext*) final { return nullptr; }
    URL readURLFromPasteboard(size_t, const String&, String&, const PasteboardContext*) final { return { }; }
    std::optional<PasteboardItemInfo> informationForItemAtIndex(size_t, const String&, int64_t, const PasteboardContext*) final { return std::nullopt; }
    std::optional<Vector<PasteboardItemInfo>> allPasteboardItemInfo(const String&, int64_t, const PasteboardContext*) final { return std::nullopt; }
    int getPasteboardItemsCount(const String&, const PasteboardContext*) final { return 0; }
    Vector<String> typesSafeForDOMToReadAndWrite(const String&, const String&, const PasteboardContext*) final { return { }; }
    int64_t writeCustomData(const Vector<PasteboardCustomData>&, const String&, const PasteboardContext*) final { return 0; }
    bool containsStringSafeForDOMToReadForType(const String&, const String&, const PasteboardContext*) final { return false; }
    int64_t changeCount(const String&) final { return 0; }
};

class MediaStrategyNone final : public MediaStrategy {
    WTF_MAKE_FAST_ALLOCATED;
};

class BlobRegistryNone final : public BlobRegistry {
    WTF_MAKE_FAST_ALLOCATED;
public:
    void registerInternalFileBlobURL(const URL&, Ref<BlobDataFileReference>&&, const String&, const String&) final { }
    void registerInternalBlobURL(const URL&, Vector<BlobPart>&&, const String&) final { }
    void registerBlobURL(const URL&, const URL&, const PolicyContainer&, const std::optional<SecurityOriginData>&) final { }
    void registerInternalBlobURLOptionallyFileBacked(const URL&, const URL&, RefPtr<BlobDataFileReference>&&, const String&) final { }
    void registerInternalBlobURLForSlice(const URL&, const URL&, long long, long long, const String&) final { }
    void unregisterBlobURL(const URL&, const std::optional<SecurityOriginData>&) final { }
    void registerBlobURLHandle(const URL&, const std::optional<SecurityOriginData>&) final { }
    void unregisterBlobURLHandle(const URL&, const std::optional<SecurityOriginData>&) final { }
    String blobType(const URL&) final { return { }; }
    unsigned long long blobSize(const URL&) final { return 0; }
    void writeBlobsToTemporaryFilesForIndexedDB(const Vector<String>&, CompletionHandler<void(Vector<String>&&)>&& completion) final { completion({ }); }
};

class ShizukuPlatformStrategies final : public PlatformStrategies {
private:
    LoaderStrategy* createLoaderStrategy() final { return new LoaderStrategyNoNetwork; }
    PasteboardStrategy* createPasteboardStrategy() final { return new PasteboardStrategyEmpty; }
    MediaStrategy* createMediaStrategy() final { return new MediaStrategyNone; }
    BlobRegistry* createBlobRegistry() final { return new BlobRegistryNone; }
#if ENABLE(DECLARATIVE_WEB_PUSH)
    PushStrategy* createPushStrategy() final { return nullptr; }
#endif
};

void installPlatformStrategies()
{
    static NeverDestroyed<ShizukuPlatformStrategies> strategies;
    static bool installed;
    if (installed)
        return;
    installed = true;
    setPlatformStrategies(&strategies.get());
}

} // namespace Shizuku
