/* SPDX-License-Identifier: GPL-2.0-only
 * PE forwarder carrier for current Steam's actual PSAPI eager imports.
 * All query behavior executes the existing measured kernel32 K32* backends.
 * This DLL has no entry point and no synthetic query implementation.
 */
#include "nt.h"
const char shz_psapi_forwarder_description[] = "PSAPI queries backed by Kernel64 accounting and loader modules";
