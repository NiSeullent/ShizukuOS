/* SPDX-License-Identifier: GPL-2.0-only
 * Semantic API doubles only, not proof of SDK ABI or native networking. */
#ifndef M98_NET_WIN32_MOCK_H
#define M98_NET_WIN32_MOCK_H
#include <stdint.h>
#include <stddef.h>
#define WINAPI
typedef uint32_t DWORD,UINT,u_long,SOCKET,HCRYPTPROV;
typedef uint16_t WORD;
typedef unsigned char BYTE;
typedef int BOOL;
typedef void *HMODULE;
typedef const char *LPCSTR;
typedef void (*FARPROC)(void);
typedef struct{DWORD dwLowDateTime,dwHighDateTime;} FILETIME;
typedef struct{WORD wVersion;} WSADATA,*LPWSADATA;
typedef struct{uint32_t fd_count;SOCKET fd_array[64];} fd_set;
struct timeval {long tv_sec,tv_usec;};
struct sockaddr {uint16_t sa_family;char sa_data[14];};
struct sockaddr_in {uint16_t sin_family,sin_port;struct{uint32_t s_addr;}sin_addr;char sin_zero[8];};
#define INVALID_SOCKET UINT32_MAX
#define SOCKET_ERROR (-1)
#define MAX_PATH 260
#define ERROR_BAD_PATHNAME 161
#define ERROR_INVALID_DATA 13
#define ERROR_PROC_NOT_FOUND 127
#define AF_INET 2
#define SOCK_STREAM 1
#define IPPROTO_TCP 6
#define FIONBIO ((long)0x8004667e)
#define SOL_SOCKET 0xffff
#define SO_ERROR 0x1007
#define WSAEWOULDBLOCK 10035
#define WSAETIMEDOUT 10060
#define WSAEINVAL 10022
#define WSAVERNOTSUPPORTED 10092
#define PROV_RSA_FULL 1
#define CRYPT_VERIFYCONTEXT 0xf0000000u
DWORD GetModuleFileNameA(HMODULE,char *,DWORD);
UINT GetSystemDirectoryA(char *,UINT);
HMODULE LoadLibraryA(const char *);
HMODULE GetModuleHandleA(const char *);
FARPROC GetProcAddress(HMODULE,const char *);
BOOL FreeLibrary(HMODULE);
DWORD GetLastError(void);
DWORD GetTickCount(void);
int lstrcmpiA(const char *,const char *);
void GetSystemTimeAsFileTime(FILETIME *);
#endif
