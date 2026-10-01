/* SPDX-License-Identifier: GPL-2.0-only
 * Host-side dependency adapter. Context switching itself uses the production
 * source and the actual Microsoft AMD64 calling convention. This adapter is
 * not a substitute for the Kernel64 guest FLS/virtual-memory tests. */
#ifndef SHZ_STEAM_FIBER_HOST_H
#define SHZ_STEAM_FIBER_HOST_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define WINAPI __attribute__((ms_abi))
#define K32API
#define VOID void
#define TRUE 1
#define FALSE 0
typedef void *PVOID, *LPVOID;
typedef uintptr_t ULONG_PTR;
typedef size_t SIZE_T;
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef uint16_t USHORT;
typedef int BOOL;
typedef void (WINAPI *LPFIBER_START_ROUTINE)(LPVOID);
typedef void (WINAPI *PFLS_CALLBACK_FUNCTION)(LPVOID);
#define HEAP_ZERO_MEMORY 8
#define FIBER_FLAG_FLOAT_SWITCH 1
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_RELEASE 0x8000
#define PAGE_READWRITE 4
#define PAGE_NOACCESS 1
#define ERROR_INVALID_PARAMETER 87
#define ERROR_NOT_ENOUGH_MEMORY 8
#define ERROR_NOT_SUPPORTED 50
#define ERROR_ALREADY_FIBER 1280
#define ERROR_ALREADY_THREAD 1281
typedef struct { char before_lfanew[60]; int32_t e_lfanew; } IMAGE_DOS_HEADER;
typedef struct { struct { uint64_t SizeOfStackReserve, SizeOfStackCommit; } OptionalHeader; } IMAGE_NT_HEADERS64;
uint64_t shz_teb(void);
DWORD shz_last_error(void);
void shz_set_last_error(DWORD);
DWORD shz_tid(void);
BOOL k32_unsupported(const char *, const char *, DWORD);
void *ShzProcessHeap(void);
void *RtlAllocateHeap(void *, DWORD, size_t);
BOOL RtlFreeHeap(void *, DWORD, void *);
void *WINAPI VirtualAlloc(void *, SIZE_T, DWORD, DWORD);
BOOL WINAPI VirtualFree(void *, SIZE_T, DWORD);
BOOL WINAPI VirtualProtect(void *, SIZE_T, DWORD, DWORD *);
void *WINAPI GetModuleHandleW(const void *);
void WINAPI __attribute__((noreturn)) ExitThread(DWORD);
void k32_fls_destroy_data(PVOID *);
#endif
