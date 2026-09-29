/* SPDX-License-Identifier: GPL-2.0-only
 * Host compatibility shim so the REAL ntdll/unwind.c compiles and runs natively on Linux for the unwind host test
 * (win64/tests/test_unwind.c). It provides the documented x64 exception-handling types and macros and stub prototypes
 * for the OS primitives; the test never reaches those stubs because every PC it unwinds is covered by a dynamically
 * registered function table (so RtlPcToFileHeader / shz_peb are not consulted). Nothing here is copied from Windows
 * headers; the layouts are the public x64 UNWIND_INFO / CONTEXT / RUNTIME_FUNCTION definitions.
 *
 * This header shadows shizukudos/win64/include/nt.h only for the host test build (compiled with -I on this directory).
 */
#ifndef SHZ_HOSTSHIM_NT_H
#define SHZ_HOSTSHIM_NT_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef uint32_t ULONG;
typedef uint64_t DWORD64, ULONG64, ULONG_PTR;
typedef uint64_t *PDWORD64;
typedef int BOOLEAN;
typedef void *PVOID;
typedef const void *PCVOID;
typedef LONG NTSTATUS;
typedef uint16_t WCHAR;
typedef const WCHAR *PCWSTR;
#define TRUE 1
#define FALSE 0
#define NTAPI
#ifndef __cdecl
#define __cdecl
#endif
#define SHZ_EXPORT
#define VOID void

typedef struct { uint64_t Low; int64_t High; } M128A;

typedef struct {
    DWORD ContextFlags;
    DWORD EFlags;
    DWORD64 Rip;
    /* integer register file in the order RtlVirtualUnwind's reg_slot() indexes: Rax,Rcx,Rdx,Rbx,Rsp,Rbp,Rsi,Rdi,R8..R15 */
    DWORD64 Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15;
    struct { DWORD MxCsr; M128A XmmRegisters[16]; } FltSave;
} CONTEXT, *PCONTEXT;
#define CONTEXT_FULL 0x10000bu

typedef struct { DWORD BeginAddress, EndAddress, UnwindData; } RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

typedef struct _EXCEPTION_RECORD {
    DWORD ExceptionCode, ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

typedef struct { PEXCEPTION_RECORD ExceptionRecord; PCONTEXT ContextRecord; } EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

typedef enum { ExceptionContinueExecution, ExceptionContinueSearch, ExceptionNestedException, ExceptionCollidedUnwind } EXCEPTION_DISPOSITION;

typedef EXCEPTION_DISPOSITION (*PEXCEPTION_ROUTINE)(PEXCEPTION_RECORD, PVOID, PCONTEXT, PVOID);
typedef LONG (*PVECTORED_EXCEPTION_HANDLER)(EXCEPTION_POINTERS *);
typedef LONG (*PTOP_LEVEL_EXCEPTION_FILTER)(EXCEPTION_POINTERS *);
typedef PRUNTIME_FUNCTION (*PGET_RUNTIME_FUNCTION_CALLBACK)(DWORD64, PVOID);

typedef struct { PVOID FloatingContext[16], IntegerContext[16]; } KNONVOLATILE_CONTEXT_POINTERS, *PKNONVOLATILE_CONTEXT_POINTERS;
typedef struct { DWORD Count; BYTE b[8]; PVOID Entry[12]; } UNWIND_HISTORY_TABLE, *PUNWIND_HISTORY_TABLE;

typedef struct {
    ULONG_PTR ControlPc, ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
    ULONG_PTR EstablisherFrame, TargetIp;
    PCONTEXT ContextRecord;
    PEXCEPTION_ROUTINE LanguageHandler;
    PVOID HandlerData;
    PUNWIND_HISTORY_TABLE HistoryTable;
    ULONG ScopeIndex, Fill0;
} DISPATCHER_CONTEXT, *PDISPATCHER_CONTEXT;

#define UNW_FLAG_EHANDLER 1
#define UNW_FLAG_UHANDLER 2
#define UNW_FLAG_CHAININFO 4

#define EXCEPTION_NONCONTINUABLE 0x1
#define EXCEPTION_UNWINDING 0x2
#define EXCEPTION_EXIT_UNWIND 0x4
#define EXCEPTION_TARGET_UNWIND 0x20
#define EXCEPTION_CONTINUE_EXECUTION (-1)
#define EXCEPTION_CONTINUE_SEARCH 0
#define EXCEPTION_EXECUTE_HANDLER 1
#define STATUS_UNWIND ((NTSTATUS)0xC0000027)

typedef struct { WORD e_magic; BYTE pad[0x3a]; LONG e_lfanew; } IMAGE_DOS_HEADER;
typedef struct { DWORD VirtualAddress, Size; } IMAGE_DATA_DIRECTORY;
typedef struct { DWORD pad[30]; IMAGE_DATA_DIRECTORY DataDirectory[16]; } IMAGE_OPTIONAL_HEADER64;
typedef struct { DWORD Signature; BYTE pad[20]; IMAGE_OPTIONAL_HEADER64 OptionalHeader; } IMAGE_NT_HEADERS64;
#define IMAGE_DOS_SIGNATURE 0x5a4d
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3

typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink, *Blink; } LIST_ENTRY;
typedef struct { LIST_ENTRY InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList; } SHZ_PEB_LDR_DATA;
typedef struct { LIST_ENTRY InLoadOrderLinks, InMemoryOrderLinks, InInitializationOrderLinks; PVOID DllBase; DWORD SizeOfImage; } SHZ_LDR_ENTRY;
#define CONTAINING_RECORD(a, t, f) ((t *)((char *)(a) - offsetof(t, f)))
#define PEB_LDR(peb) ((SHZ_PEB_LDR_DATA *)(peb))
/* The host test provides an (initially empty) loader database so RtlPcToFileHeader walks a real, terminated list
 * instead of a %gs-based PEB that does not exist on Linux. */
extern SHZ_PEB_LDR_DATA shz_host_ldr;
static inline uint64_t shz_peb(void) { return (uint64_t)(uintptr_t)&shz_host_ldr; }

#define CURRENT_PROCESS ((PVOID)(intptr_t)-1)
#define CURRENT_THREAD ((PVOID)(intptr_t)-2)

/* OS primitives unwind.c links against; provided by the test driver (test_unwind.c). */
NTSTATUS NTAPI NtYieldExecution(void);
PVOID NTAPI RtlAllocateHeap(PVOID, ULONG, size_t);
BOOLEAN NTAPI RtlFreeHeap(PVOID, ULONG, PVOID);
PVOID ShzProcessHeap(void);
NTSTATUS NTAPI NtContinue(PCONTEXT, BOOLEAN);
NTSTATUS NTAPI NtRaiseException(PEXCEPTION_RECORD, PCONTEXT, BOOLEAN);
NTSTATUS NTAPI NtTerminateProcess(PVOID, NTSTATUS);
VOID NTAPI RtlExitUserProcess(NTSTATUS);
void RtlCaptureContext(PCONTEXT);
#endif
