/* Host unit-test declarations only; these do not provide Windows API evidence.
 * Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
 */
#ifndef IEWK_TEST_WINDOWS_H
#define IEWK_TEST_WINDOWS_H
#include <stddef.h>
typedef unsigned short WCHAR;
typedef int BOOL;
typedef unsigned long DWORD;
#define FALSE 0
#define CP_ACP 0
#define MAX_PATH 260
#define ERROR_INVALID_PARAMETER 87
#define ERROR_FILENAME_EXCED_RANGE 206
#define ERROR_INVALID_NAME 123
#define ERROR_NO_UNICODE_TRANSLATION 1113
#define ERROR_INSUFFICIENT_BUFFER 122
void SetLastError(DWORD);
DWORD GetLastError(void);
int WideCharToMultiByte(unsigned, DWORD, const WCHAR*, int, char*, int, const char*, BOOL*);
int MultiByteToWideChar(unsigned, DWORD, const char*, int, WCHAR*, int);
#endif
