/* Zetscape's optional extension to the unchanged shared IEWebKit ABI.
 * SPDX-License-Identifier: GPL-2.0-only */
#ifndef ZETSCAPE_EXTENSIONS_H
#define ZETSCAPE_EXTENSIONS_H
#include "upstream/engine.h"

#define ZETSCAPE_EXTENSION_ABI 1u
#define ZET_DEVICE_HARDWARE 1u
#define ZET_COMPOSITOR_HARDWARE 2u
#define ZET_WEBGL_HARDWARE 4u
#define ZET_SOFTWARE_RENDERER 0x80000000u
#define ZET_REQUIRED_HARDWARE 7u

/* Provider observations are admission metadata. Independent driver, native
 * submission/presentation and page evidence are still required for acceptance.
 * Query runs on the same owning apartment and must not initiate navigation. */
typedef struct {
    uint32_t size, abi, flags, pci_vendor, pci_device;
    uint64_t submitted_frames, presented_frames;
    char driver_sha256[65];
    char renderer_name[64];
} ZetscapeGraphicsV1;

typedef struct {
    uint32_t size, abi;
    /* Actual engine session history, including POST/document state. The host
     * never substitutes URL replay for engine history. */
    int(IEWK_CALL *history)(IEWKView *, uint32_t navigation_id, int delta);
    int(IEWK_CALL *graphics)(IEWKView *, ZetscapeGraphicsV1 *);
} ZetscapeExtensionsV1;
typedef int(IEWK_CALL *ZetscapeGetExtensionsV1)(uint32_t,
                                               const ZetscapeExtensionsV1 **);
#endif
