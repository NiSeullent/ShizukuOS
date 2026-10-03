/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef SHZ_WSOCK32_COMPAT_H
#define SHZ_WSOCK32_COMPAT_H
#include <stdint.h>
#ifdef SHZ_WSOCK32_HOST_TEST
#define DLLAPI
#define WINAPI __attribute__((ms_abi))
typedef uint32_t DWORD;
typedef void VOID;
typedef void *PVOID;
typedef int *LPINT;
struct sockaddr { uint16_t sa_family; char sa_data[14]; };
#define WSAEINVAL 10022
#define NTAPI __attribute__((ms_abi))
typedef int32_t LONG;
typedef uint32_t ULONG, *PULONG;
typedef uintptr_t ULONG_PTR;
void WINAPI WSASetLastError(int);
#else
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#define DLLAPI __declspec(dllexport)
#endif
#endif
