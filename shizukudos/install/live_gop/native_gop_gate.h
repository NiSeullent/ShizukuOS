/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_NATIVE_GOP_GATE_H
#define SHZ_NATIVE_GOP_GATE_H
/* Validates the currently loaded source-bound VxD, live native GOP
 * descriptor, PCI/BAR ownership and successful actual display-backend probe.
 * The current descriptor ABI has no Supervisor epoch; this does not prove it.
 * A historical receipt, INI flag, copied descriptor or file hash is inadequate.
 */
int shz_gop_current_boot_ready(const unsigned char *expected_provider, unsigned char *snapshot, unsigned bytes);
#endif
