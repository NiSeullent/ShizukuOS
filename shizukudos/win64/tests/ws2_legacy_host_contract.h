/* SPDX-License-Identifier: GPL-2.0-only
 * Windows AMD64 ABI types and POSIX file/TLS/heap adapters for the exact
 * production service/protocol/host and ANSI enum bodies. Adapters are not guest/kernel evidence.
 */
#ifndef WS2_LEGACY_HOST_CONTRACT_H
#define WS2_LEGACY_HOST_CONTRACT_H
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
typedef uint32_t ULONG;
typedef int INT, *LPINT;
typedef DWORD *LPDWORD;
struct protoent { char *p_name; char **p_aliases; short p_proto; };
struct hostent { char *h_name; char **h_aliases; short h_addrtype, h_length; char **h_addr_list; };
typedef struct { uint32_t Data1; uint16_t Data2, Data3; uint8_t Data4[8]; } GUID;
struct sockaddr_in { uint16_t family, port; uint32_t addr; char zero[8]; };
#define PROTOCOL_FIELDS DWORD dwServiceFlags1, dwServiceFlags2, dwServiceFlags3, dwServiceFlags4, dwProviderFlags; GUID ProviderId; DWORD dwCatalogEntryId; struct { int ChainLen; DWORD ChainEntries[7]; } ProtocolChain; int iVersion, iAddressFamily, iMaxSockAddr, iMinSockAddr, iSocketType, iProtocol, iProtocolMaxOffset, iNetworkByteOrder, iSecurityScheme; DWORD dwMessageSize, dwProviderReserved
typedef struct { PROTOCOL_FIELDS; char szProtocol[256]; } WSAPROTOCOL_INFOA, *LPWSAPROTOCOL_INFOA;
typedef struct { PROTOCOL_FIELDS; WCHAR szProtocol[256]; } WSAPROTOCOL_INFOW;
#undef PROTOCOL_FIELDS
#define AF_INET 2
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCKET_ERROR (-1)
#define WSAEAFNOSUPPORT 10047
#define XP1_GUARANTEED_DELIVERY 2u
#define XP1_GUARANTEED_ORDER 4u
#define XP1_GRACEFUL_CLOSE 32u
#define XP1_CONNECTIONLESS 1u
#define XP1_MESSAGE_ORIENTED 8u
#define XP1_SUPPORT_BROADCAST 512u
#define PFL_MATCHES_PROTOCOL_ZERO 8u
#define BASE_PROTOCOL 1
#define BIGENDIAN 0
#define SECURITY_PROTOCOL_NONE 0
#define WSAPROTOCOL_LEN 255
_Static_assert(sizeof(struct protoent)==24 && offsetof(struct protoent,p_proto)==16,"Windows AMD64 PROTOENT");
_Static_assert(sizeof(struct hostent)==32 && offsetof(struct hostent,h_addr_list)==24,"Windows AMD64 HOSTENT");
void SetLastError(DWORD);
static int fail_code(int error) { SetLastError((DWORD)error); return SOCKET_ERROR; }
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
