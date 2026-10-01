#ifndef IEWEBKIT_ENGINE_H
#define IEWEBKIT_ENGINE_H
#include <stddef.h>
#include <stdint.h>
#ifdef _WIN32
#define IEWK_CALL __cdecl
#else
#define IEWK_CALL
#endif
#ifdef __cplusplus
extern "C" {
#endif
#define IEWK_ABI_V1 1u
#define IEWK_HTML 1u
#define IEWK_CSS 2u
#define IEWK_DOM 4u
#define IEWK_JAVASCRIPTCORE 8u
#define IEWK_VERIFIED_TLS 16u
#define IEWK_ORIGIN_ISOLATION 32u
#define IEWK_REQUIRED_CAPS 63u
#define IEWK_URL_LIMIT 8192u
/* All callbacks/entrypoints run on the owning IE apartment thread. Strings are
 UTF-8 with explicit byte lengths, borrowed until return. The actual engine owns
 canonical URLs, origins, cookies, TLS, subresources and navigation IDs. The
 host never derives committed origin or certificate state from an address-bar
 HWND. */
typedef struct IEWKView IEWKView;
typedef struct {
  uint32_t size, abi;
  void *context;
  void(IEWK_CALL *committed)(void *, uint32_t, const char *, size_t,
                             const char *, size_t, uint32_t);
  void(IEWK_CALL *title)(void *, const char *, size_t);
  void(IEWK_CALL *failed)(void *, uint32_t, int, const char *, size_t);
  /* Variant adapter performs real IE navigation/history, including POST data.
   */
  void(IEWK_CALL *navigate_requested)(void *, const char *, size_t,
                                      const char *, size_t, const void *,
                                      size_t);
} IEWKHostV1;
typedef struct {
  uint32_t size, abi, capabilities;
  const char *engine_name;
  const char *source_sha256;
  int(IEWK_CALL *create)(const IEWKHostV1 *, void *parent_window, IEWKView **);
  /* Quiesce all tasks; no further callbacks after return. */
  void(IEWK_CALL *destroy)(IEWKView *);
  int(IEWK_CALL *navigate)(IEWKView *, uint32_t, const char *, size_t,
                           const char *, size_t, const void *, size_t);
  void(IEWK_CALL *resize)(IEWKView *, int, int, int, int);
  void(IEWK_CALL *focus)(IEWKView *, int);
  int(IEWK_CALL *command)(IEWKView *, uint32_t);
} IEWKEngineV1;
typedef int(IEWK_CALL *IEWKGetEngineV1)(uint32_t, const IEWKEngineV1 **);
enum {
  IEWK_OK = 0,
  IEWK_BAD_ABI = -1,
  IEWK_MISSING_ENGINE = -2,
  IEWK_INCOMPLETE_ENGINE = -3,
  IEWK_BAD_ORIGIN = -4
};
int iewk_engine_validate(const IEWKEngineV1 *engine);
/* ASCII canonical URL after engine IDNA; not a replacement for WebKit URL
 * parsing. */
int iewk_web_url(const char *url, size_t length);
#ifdef __cplusplus
}
#endif
#endif
