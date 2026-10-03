/* SPDX-License-Identifier: GPL-2.0-only
 * Reuse the tested allocation-free laptop firmware parser in the native build.
 * kbuild discovers all Kernel64 C files; the production parser stays shared.
 */
#include "../../drivers/shz_laptop/acpi.c"
#include "../../drivers/shz_laptop/firmware.c"
