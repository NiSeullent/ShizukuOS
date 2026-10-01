#ifndef TEST_WINDOWS_H
#define TEST_WINDOWS_H
#include <stddef.h>
#include <stdint.h>
typedef uint32_t DWORD;
typedef int BOOL;
typedef void *HANDLE;
#define FALSE 0
#define TRUE 1
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define OPEN_EXISTING 3u
#define WAIT_OBJECT_0 0u
#define WAIT_TIMEOUT 258u
#define WAIT_FAILED 0xffffffffu
HANDLE CreateEventA(void *, BOOL, BOOL, const char *);
HANDLE CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
BOOL CloseHandle(HANDLE);
BOOL ResetEvent(HANDLE);
BOOL DeviceIoControl(HANDLE, DWORD, void *, DWORD, void *, DWORD, DWORD *,
                     void *);
DWORD GetLastError(void);
DWORD GetCurrentThreadId(void);
DWORD GetTickCount(void);
DWORD WaitForSingleObject(HANDLE, DWORD);
void Sleep(DWORD);
#endif
