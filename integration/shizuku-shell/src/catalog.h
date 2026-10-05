/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef SHZ_CATALOG_H
#define SHZ_CATALOG_H
#include "shell.h"
typedef enum {
    SHZ_CMD_FILES=1, SHZ_CMD_DOCUMENTS, SHZ_CMD_TEXT, SHZ_CMD_SETTINGS,
    SHZ_CMD_SEARCH, SHZ_CMD_RUN, SHZ_CMD_SAPPHIRE, SHZ_CMD_MUZIK,
    SHZ_CMD_GAMES, SHZ_CMD_EXIT
} SHZ_COMMAND;
typedef struct {
    SHZ_COMMAND id;
    const WCHAR *name, *keywords, *verb;
} SHZ_COMMAND_INFO;
unsigned ShzCommandCount(void);
const SHZ_COMMAND_INFO *ShzCommandAt(unsigned index);
BOOL ShzCommandInvoke(SHZ_COMMAND id);
BOOL ShzOpenDocument(const WCHAR *path);
BOOL ShzRunInput(const WCHAR *text);
BOOL ShzClipboardWriteText(HWND owner, const WCHAR *text);
void ShzUserMessage(const WCHAR *text, DWORD error);
#define SHZ_DOCUMENTS_ROOT L"E:\\SHZ\\DOCUMENTS"
#endif
