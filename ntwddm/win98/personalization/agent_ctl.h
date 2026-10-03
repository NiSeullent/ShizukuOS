/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SZW_AGENT_CTL_H
#define SZW_AGENT_CTL_H
#include <windows.h>
#include "desktop_agent.h"
/* Missing key => defaults. Corrupt record => ERROR_INVALID_DATA, *out untouched. */
DWORD szw_load_settings(szw_settings *out);
/* Writes, reads back and flushes every value; rejects invalid records. */
DWORD szw_save_settings(const szw_settings *s);
/* HKCU Run value with the quoted path of the current module (enable) or removal. */
DWORD szw_set_startup(int enable);
/* Launch sibling SHZWALL.EXE /enable (not awaited) or /disable (awaited, 5 s). */
DWORD szw_launch(int enable);
#endif
