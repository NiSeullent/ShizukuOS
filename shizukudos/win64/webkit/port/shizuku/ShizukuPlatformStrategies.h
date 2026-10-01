/*
 * SPDX-License-Identifier: GPL-2.0-only
 * ShizukuDOS "Shizuku" WebKit port: WebCore's platform strategies for the single-process port.
 */
#pragma once

#include <WebCore/PlatformStrategies.h>

namespace Shizuku {

// Installs the strategies with WebCore::setPlatformStrategies (once; idempotent).
void installPlatformStrategies();

} // namespace Shizuku
