/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_EDITOR_H
#define SHZ_EDITOR_H
#include <windows.h>
#define SHZ_EDITOR_TEXT_CAP 32767u
#define SHZ_EDITOR_FILE_CAP 131072u
BOOL ShzEditorRegister(void);
HWND ShzEditorOpen(const WCHAR *path); /* NULL: new document. Accepted work may complete asynchronously. */
BOOL ShzEditorCanExit(void); /* Dirty/busy: FALSE and focus the actual document. */
void ShzEditorCloseAll(void); /* After CanExit succeeds; never waits on disk I/O on the UI thread. */
void ShzEditorRelayout(void);
#endif
