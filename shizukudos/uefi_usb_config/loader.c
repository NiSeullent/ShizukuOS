/* SPDX-License-Identifier: GPL-2.0-only
 * Reuse the project's original firmware handoff with a separate proof ABI.
 * The source manifest binds the included loader and original layout as inputs.
 */
#include "layout.h"
#undef SDUSB_MAGIC
#undef SDUSB_VERSION
#define SDUSB_MAGIC SDUSBC_MAGIC
#define SDUSB_VERSION SDUSBC_VERSION
#include "../uefi_usb/loader.c"
