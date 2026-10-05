/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_FIRSTBOOT_H
#define SHZ_FIRSTBOOT_H
#include <windows.h>
/* Run before desktop/taskbar creation, after actual Noto/theme initialization.
 * Trusted authority is granted solely by kernel launch, never argv parsing. */
int ShzFirstBootRun(void);
/* Authenticated --firstboot-complete child: verifies medium token/profile,
 * commits protected done record, then ordinary shell starts on success. */
BOOL ShzFirstBootComplete(void);
#endif
