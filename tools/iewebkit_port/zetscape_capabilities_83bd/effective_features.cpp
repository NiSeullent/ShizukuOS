// Compile against the actual generated engine headers, not cached toggles.
// Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
#include "config.h"
#include <wtf/Platform.h>

static_assert(IEWEBKIT_WIN9X == 1, "Require the actual Win9x generated profile");
#if !CPU(X86) || !CPU(ADDRESS32) || !USE(JSVALUE32_64)
#error "Require the actual x86/32-bit-JSValue target, not a 64-bit host profile"
#endif
static_assert(ENABLE_C_LOOP == 1, "This is the current interpreter bring-up");
static_assert(ENABLE_JIT == 0 && ENABLE_DFG_JIT == 0 && ENABLE_FTL_JIT == 0,
              "The current x86 profile has no JIT tiers");
static_assert(ENABLE_WEBASSEMBLY == 0, "Current native Wasm is unavailable");
static_assert(ENABLE_WEBGL == 0 && ENABLE_WEBGPU == 0,
              "JSCOnly does not compile WebCore GPU frontends");
