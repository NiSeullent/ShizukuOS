/* SPDX-License-Identifier: GPL-2.0-only
 * The Win32 / ntdll functions the Shizuku UCRT calls, declared with plain C types. The CRT's own translation units must
 * not include <windows.h>: mingw-w64's winnt.h pulls in its <string.h> and <ctype.h>, whose dllimport declarations of
 * strlen, isalpha, ... would clash with the definitions this DLL exports. Only functions the Shizuku kernel32/ntdll
 * really export are declared here (see build/shizukudos/win64/kernel32.def). Win64 only; never used by host tests.
 */
#ifndef SHZ_CRTOS_H
#define SHZ_CRTOS_H
#include <stdint.h>
#include <stddef.h>

#define WINAPI_ __stdcall
#define IMP_ __declspec(dllimport)
typedef void *os_handle;
typedef int os_bool;
typedef unsigned long os_dword;                 /* DWORD: 32 bits on LLP64 */
#define OS_INVALID_HANDLE ((os_handle)(intptr_t)-1)

typedef struct { os_dword lo, hi; } os_filetime;
typedef struct { unsigned short wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds; } os_systemtime;
typedef struct {
    int32_t Bias;
    unsigned short StandardName[32];
    os_systemtime StandardDate;
    int32_t StandardBias;
    unsigned short DaylightName[32];
    os_systemtime DaylightDate;
    int32_t DaylightBias;
} os_tzinfo;
typedef struct { void *p; } os_srwlock;
typedef struct { void *p; } os_condvar;
typedef struct { void *DebugInfo; int32_t LockCount, RecursionCount; os_handle OwningThread, LockSemaphore; uintptr_t SpinCount; } os_critsec;
typedef struct {
    os_dword cb; unsigned short *lpReserved, *lpDesktop, *lpTitle;
    os_dword dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    unsigned short wShowWindow, cbReserved2; unsigned char *lpReserved2;
    os_handle hStdInput, hStdOutput, hStdError;
} os_startupinfow;
typedef struct {
    os_dword dwFileAttributes;
    os_filetime ftCreationTime, ftLastAccessTime, ftLastWriteTime;
    os_dword nFileSizeHigh, nFileSizeLow, dwReserved0, dwReserved1;
    unsigned short cFileName[260];
    unsigned short cAlternateFileName[14];
} os_find_dataw;

IMP_ void *WINAPI_ HeapAlloc(os_handle heap, os_dword flags, size_t n);
IMP_ os_bool WINAPI_ HeapFree(os_handle heap, os_dword flags, void *p);
IMP_ void *WINAPI_ HeapReAlloc(os_handle heap, os_dword flags, void *p, size_t n);
IMP_ size_t WINAPI_ HeapSize(os_handle heap, os_dword flags, const void *p);
IMP_ os_bool WINAPI_ HeapValidate(os_handle heap, os_dword flags, const void *p);
IMP_ os_handle WINAPI_ GetProcessHeap(void);
IMP_ os_dword WINAPI_ GetLastError(void);
IMP_ void WINAPI_ SetLastError(os_dword e);
IMP_ os_dword WINAPI_ TlsAlloc(void);
IMP_ void *WINAPI_ TlsGetValue(os_dword i);
IMP_ os_bool WINAPI_ TlsSetValue(os_dword i, void *v);
IMP_ os_bool WINAPI_ TlsFree(os_dword i);
IMP_ void WINAPI_ AcquireSRWLockExclusive(os_srwlock *l);
IMP_ void WINAPI_ ReleaseSRWLockExclusive(os_srwlock *l);
IMP_ void WINAPI_ AcquireSRWLockShared(os_srwlock *l);
IMP_ void WINAPI_ ReleaseSRWLockShared(os_srwlock *l);
IMP_ unsigned char WINAPI_ TryAcquireSRWLockExclusive(os_srwlock *l);
IMP_ void WINAPI_ InitializeCriticalSection(os_critsec *c);
IMP_ void WINAPI_ EnterCriticalSection(os_critsec *c);
IMP_ void WINAPI_ LeaveCriticalSection(os_critsec *c);
IMP_ void WINAPI_ DeleteCriticalSection(os_critsec *c);
IMP_ void WINAPI_ ExitProcess(unsigned code);
IMP_ os_bool WINAPI_ TerminateProcess(os_handle p, unsigned code);
IMP_ os_handle WINAPI_ GetCurrentProcess(void);
IMP_ os_dword WINAPI_ GetCurrentProcessId(void);
IMP_ os_dword WINAPI_ GetCurrentThreadId(void);
IMP_ os_handle WINAPI_ GetCurrentThread(void);
IMP_ void WINAPI_ ExitThread(os_dword code);
IMP_ os_handle WINAPI_ CreateThread(void *sa, size_t stack, os_dword (WINAPI_ *fn)(void *), void *arg, os_dword flags, os_dword *tid);
IMP_ os_dword WINAPI_ ResumeThread(os_handle t);
IMP_ os_bool WINAPI_ CloseHandle(os_handle h);
IMP_ os_bool WINAPI_ DuplicateHandle(os_handle sp, os_handle s, os_handle tp, os_handle *t, os_dword acc, os_bool inh, os_dword opt);
IMP_ os_dword WINAPI_ WaitForSingleObject(os_handle h, os_dword ms);
IMP_ void WINAPI_ Sleep(os_dword ms);
IMP_ unsigned short *WINAPI_ GetCommandLineW(void);
IMP_ char *WINAPI_ GetCommandLineA(void);
IMP_ unsigned short *WINAPI_ GetEnvironmentStringsW(void);
IMP_ os_bool WINAPI_ FreeEnvironmentStringsW(unsigned short *e);
IMP_ os_bool WINAPI_ SetEnvironmentVariableW(const unsigned short *n, const unsigned short *v);
IMP_ os_dword WINAPI_ GetModuleFileNameW(os_handle m, unsigned short *buf, os_dword n);
IMP_ os_dword WINAPI_ GetModuleFileNameA(os_handle m, char *buf, os_dword n);
IMP_ unsigned WINAPI_ GetACP(void);
IMP_ int WINAPI_ MultiByteToWideChar(unsigned cp, os_dword fl, const char *s, int n, unsigned short *d, int dn);
IMP_ int WINAPI_ WideCharToMultiByte(unsigned cp, os_dword fl, const unsigned short *s, int n, char *d, int dn, const char *def, os_bool *used);
IMP_ os_handle WINAPI_ GetStdHandle(os_dword which);
IMP_ os_bool WINAPI_ SetStdHandle(os_dword which, os_handle h);
IMP_ os_dword WINAPI_ GetFileType(os_handle h);
IMP_ os_bool WINAPI_ GetConsoleMode(os_handle h, os_dword *mode);
IMP_ os_bool WINAPI_ WriteConsoleW(os_handle h, const void *buf, os_dword n, os_dword *written, void *res);
IMP_ os_bool WINAPI_ ReadFile(os_handle h, void *buf, os_dword n, os_dword *got, void *ov);
IMP_ os_bool WINAPI_ WriteFile(os_handle h, const void *buf, os_dword n, os_dword *put, void *ov);
IMP_ os_handle WINAPI_ CreateFileW(const unsigned short *path, os_dword acc, os_dword share, void *sa, os_dword disp, os_dword attrs, os_handle tmpl);
IMP_ os_bool WINAPI_ SetFilePointerEx(os_handle h, int64_t dist, int64_t *newpos, os_dword method);
IMP_ os_bool WINAPI_ SetEndOfFile(os_handle h);
IMP_ os_bool WINAPI_ FlushFileBuffers(os_handle h);
IMP_ os_bool WINAPI_ GetFileSizeEx(os_handle h, int64_t *size);
IMP_ os_bool WINAPI_ DeleteFileW(const unsigned short *p);
IMP_ os_bool WINAPI_ MoveFileExW(const unsigned short *a, const unsigned short *b, os_dword flags);
IMP_ os_dword WINAPI_ GetFileAttributesW(const unsigned short *p);
IMP_ os_bool WINAPI_ CreateDirectoryW(const unsigned short *p, void *sa);
IMP_ os_bool WINAPI_ RemoveDirectoryW(const unsigned short *p);
IMP_ os_dword WINAPI_ GetCurrentDirectoryW(os_dword n, unsigned short *buf);
IMP_ os_bool WINAPI_ SetCurrentDirectoryW(const unsigned short *p);
IMP_ os_dword WINAPI_ GetFullPathNameW(const unsigned short *p, os_dword n, unsigned short *buf, unsigned short **file);
IMP_ os_dword WINAPI_ GetTempPathW(os_dword n, unsigned short *buf);
IMP_ os_handle WINAPI_ FindFirstFileW(const unsigned short *p, os_find_dataw *d);
IMP_ os_bool WINAPI_ FindNextFileW(os_handle h, os_find_dataw *d);
IMP_ os_bool WINAPI_ FindClose(os_handle h);
IMP_ void WINAPI_ GetSystemTimeAsFileTime(os_filetime *ft);
IMP_ void WINAPI_ GetSystemTimePreciseAsFileTime(os_filetime *ft);
IMP_ os_dword WINAPI_ GetTimeZoneInformation(os_tzinfo *tz);
IMP_ os_bool WINAPI_ QueryPerformanceCounter(int64_t *c);
IMP_ os_bool WINAPI_ QueryPerformanceFrequency(int64_t *f);
IMP_ uint64_t WINAPI_ GetTickCount64(void);
IMP_ void *WINAPI_ EncodePointer(void *p);
IMP_ void *WINAPI_ DecodePointer(void *p);
IMP_ os_bool WINAPI_ IsProcessorFeaturePresent(os_dword f);
IMP_ void WINAPI_ RaiseException(os_dword code, os_dword flags, os_dword n, const uintptr_t *args);
IMP_ os_handle WINAPI_ LoadLibraryExW(const unsigned short *name, os_handle file, os_dword flags);
IMP_ void *WINAPI_ GetProcAddress(os_handle m, const char *name);
IMP_ os_handle WINAPI_ GetModuleHandleW(const unsigned short *name);
IMP_ void WINAPI_ OutputDebugStringA(const char *s);
IMP_ void WINAPI_ GetStartupInfoW(os_startupinfow *si);
IMP_ os_bool WINAPI_ GetExitCodeProcess(os_handle p, os_dword *code);
IMP_ os_bool WINAPI_ CreateProcessW(const unsigned short *app, unsigned short *cmd, void *psa, void *tsa, os_bool inh, os_dword fl,
                                    void *env, const unsigned short *dir, os_startupinfow *si, void *pi);

#define OS_STD_INPUT ((os_dword)-10)
#define OS_STD_OUTPUT ((os_dword)-11)
#define OS_STD_ERROR ((os_dword)-12)
#define OS_FILE_TYPE_DISK 1
#define OS_FILE_TYPE_CHAR 2
#define OS_FILE_TYPE_PIPE 3
#define OS_HEAP_ZERO_MEMORY 0x8
#define OS_GENERIC_READ 0x80000000u
#define OS_GENERIC_WRITE 0x40000000u
#define OS_FILE_SHARE_READ 1
#define OS_FILE_SHARE_WRITE 2
#define OS_FILE_SHARE_DELETE 4
#define OS_CREATE_NEW 1
#define OS_CREATE_ALWAYS 2
#define OS_OPEN_EXISTING 3
#define OS_OPEN_ALWAYS 4
#define OS_TRUNCATE_EXISTING 5
#define OS_FILE_ATTRIBUTE_READONLY 0x1
#define OS_FILE_ATTRIBUTE_DIRECTORY 0x10
#define OS_FILE_ATTRIBUTE_NORMAL 0x80
#define OS_FILE_ATTRIBUTE_TEMPORARY 0x100
#define OS_FILE_FLAG_DELETE_ON_CLOSE 0x04000000u
#define OS_FILE_FLAG_SEQUENTIAL_SCAN 0x08000000u
#define OS_FILE_FLAG_RANDOM_ACCESS 0x10000000u
#define OS_FILE_FLAG_BACKUP_SEMANTICS 0x02000000u
#define OS_INVALID_FILE_ATTRIBUTES 0xffffffffu
#define OS_MOVEFILE_REPLACE_EXISTING 1
#define OS_MOVEFILE_COPY_ALLOWED 2
#define OS_TIME_ZONE_ID_INVALID 0xffffffffu
#define OS_TIME_ZONE_ID_DAYLIGHT 2
#define OS_CP_ACP 0
#define OS_CP_UTF8 65001
#define OS_PF_FASTFAIL_AVAILABLE 23
#define OS_INFINITE 0xffffffffu
#define OS_DUPLICATE_SAME_ACCESS 2
#endif
