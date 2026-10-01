/* SPDX-License-Identifier: GPL-2.0-only
 * Windows AMD64 ABI types and POSIX file/TLS/heap adapters for the exact
 * production getservbyname body. Adapters are not guest/kernel evidence.
 */
#ifndef WS2_SERVICES_HOST_CONTRACT_H
#define WS2_SERVICES_HOST_CONTRACT_H
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
typedef uint16_t WCHAR, u_short;
typedef uint32_t DWORD, UINT;
typedef uint64_t ULONGLONG;
typedef void *HANDLE, *HINSTANCE, *LPVOID;
typedef int BOOL;
typedef struct { int64_t QuadPart; } LARGE_INTEGER;
typedef pthread_mutex_t SRWLOCK;
struct servent { char *s_name; char **s_aliases; char *s_proto; short s_port; };
#define SRWLOCK_INIT PTHREAD_MUTEX_INITIALIZER
#define WINAPI
#define WSAAPI
#define DLLAPI
#define TRUE 1
#define MAX_PATH 260
#define TLS_OUT_OF_INDEXES UINT32_MAX
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define GENERIC_READ 0x80000000u
#define FILE_SHARE_READ 1u
#define FILE_SHARE_WRITE 2u
#define FILE_SHARE_DELETE 4u
#define OPEN_EXISTING 3u
#define FILE_ATTRIBUTE_NORMAL 0x80u
#define HEAP_ZERO_MEMORY 8u
#define DLL_PROCESS_DETACH 0u
#define DLL_PROCESS_ATTACH 1u
#define DLL_THREAD_ATTACH 2u
#define DLL_THREAD_DETACH 3u
#define WSANOTINITIALISED 10093
#define WSAEFAULT 10014
#define WSAENOBUFS 10055
#define WSAHOST_NOT_FOUND 11001
#define WSANO_RECOVERY 11003
#define WSANO_DATA 11004
_Static_assert(sizeof(struct servent) == 32, "Windows AMD64 SERVENT size");
_Static_assert(offsetof(struct servent,s_name)==0 && offsetof(struct servent,s_aliases)==8
               && offsetof(struct servent,s_proto)==16 && offsetof(struct servent,s_port)==24, "Windows AMD64 SERVENT fields");
static int g_started;
#define NEED_INIT(ret) do { if (!g_started) { SetLastError(WSANOTINITIALISED); return (ret); } } while (0)
DWORD GetLastError(void);
void SetLastError(DWORD);
UINT GetSystemDirectoryW(WCHAR *, UINT);
HANDLE CreateFileW(const WCHAR *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
BOOL GetFileSizeEx(HANDLE, LARGE_INTEGER *);
BOOL ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
BOOL CloseHandle(HANDLE);
HANDLE GetProcessHeap(void);
void *HeapAlloc(HANDLE, DWORD, size_t);
BOOL HeapFree(HANDLE, DWORD, void *);
DWORD GetCurrentThreadId(void);
DWORD TlsAlloc(void);
void *TlsGetValue(DWORD);
BOOL TlsSetValue(DWORD, void *);
BOOL TlsFree(DWORD);
void AcquireSRWLockExclusive(SRWLOCK *);
void ReleaseSRWLockExclusive(SRWLOCK *);
#endif
