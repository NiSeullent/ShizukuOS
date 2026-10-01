/* Opt-in source overlay, after the real Windows declarations.
 * Statically link chromium_win9x_wait.c into every process using this overlay.
 * SPDX-License-Identifier: GPL-2.0-only */
#ifndef CHROMIUM_WIN9X_WAIT_REDIRECT_H
#define CHROMIUM_WIN9X_WAIT_REDIRECT_H
#include "chromium_win9x_wait.h"
#ifdef CHROMIUM_WIN9X_ADDRESS_WAIT_REDIRECT
#define WaitOnAddress chromium_win9x_WaitOnAddress
#define WakeByAddressSingle chromium_win9x_WakeByAddressSingle
#define WakeByAddressAll chromium_win9x_WakeByAddressAll
#endif
#endif
