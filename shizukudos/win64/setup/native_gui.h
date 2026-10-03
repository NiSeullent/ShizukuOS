/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_NATIVE_GUI_H
#define SHZ_NATIVE_GUI_H
#include "native_runtime.h"
/* Private packaging contract: exact accepted archive nodes, not arbitrary files.
 * Packaging belongs to producer/media owners. Kernel ADMIT still authenticates
 * every sealed byte; paths never grant authority. */
#define SHZ_NATIVE_GUI_MANIFEST "C:\\SHZ\\SETUP\\NATIVE\\MANIFEST.JSON"
#define SHZ_NATIVE_GUI_SIM "C:\\SHZ\\SETUP\\NATIVE\\ESP.SIM"
typedef struct {
 shz_native_runtime runtime;
 native_setup_request_v1_t request;
 unsigned prepared,reviewed,confirmed,started;
} shz_native_gui;
/* -2 only actual admission absence permits ordinary public-development GUI. */
int shz_native_gui_prepare(shz_native_gui *,const plat_t *);
int shz_native_gui_review(shz_native_gui *,unsigned,native_setup_target_v1_t *);
int shz_native_gui_confirm(shz_native_gui *,const native_setup_target_v1_t *,const char *);
int shz_native_gui_close(shz_native_gui *);
void shz_native_gui_run(shz_native_gui *,native_setup_result_v1_t *);
#endif
