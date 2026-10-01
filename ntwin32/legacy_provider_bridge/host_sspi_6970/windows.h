/* SPDX-License-Identifier: GPL-2.0-only
 * Host-only Win32 boundaries for test_native_sspi_6970.c.
 * These PE32 layouts use fixed-width fields; host pointers are not SSPI32 slots.
 */
#ifndef NTWP_HOST_SSPI_6970_WINDOWS_H
#define NTWP_HOST_SSPI_6970_WINDOWS_H
#include <stddef.h>
#include <stdint.h>

#define WINAPI
#define __cdecl
#define __stdcall
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define HEAP_ZERO_MEMORY 0x00000008u
#define ERROR_NOT_ENOUGH_MEMORY 8u
#define ERROR_BAD_EXE_FORMAT 193u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_MOD_NOT_FOUND 126u
#define ERROR_PROC_NOT_FOUND 127u
#define ERROR_FILENAME_EXCED_RANGE 206u
#define IMAGE_DOS_SIGNATURE 0x5a4du
#define IMAGE_NT_SIGNATURE 0x00004550u
#define IMAGE_FILE_MACHINE_I386 0x014cu
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x010bu
#define IMAGE_SCN_MEM_EXECUTE 0x20000000u
#define IMAGE_SCN_MEM_READ 0x40000000u
#define IMAGE_SCN_MEM_WRITE 0x80000000u

typedef int BOOL;
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef uintptr_t UINT_PTR;
typedef size_t SIZE_T;
typedef void *HANDLE;
typedef void *HMODULE;
typedef HMODULE HINSTANCE;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef const char *LPCSTR;
typedef void (*FARPROC)(void);
typedef struct { unsigned initialized, held; } CRITICAL_SECTION;

typedef struct {
    WORD e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
    WORD e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    WORD e_res[4], e_oemid, e_oeminfo, e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER;
typedef struct {
    WORD Machine, NumberOfSections;
    DWORD TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    WORD SizeOfOptionalHeader, Characteristics;
} IMAGE_FILE_HEADER;
typedef struct { DWORD VirtualAddress, Size; } IMAGE_DATA_DIRECTORY;
typedef struct {
    WORD Magic;
    BYTE MajorLinkerVersion, MinorLinkerVersion;
    DWORD SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    DWORD AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase;
    DWORD SectionAlignment, FileAlignment;
    WORD MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    WORD MajorImageVersion, MinorImageVersion;
    WORD MajorSubsystemVersion, MinorSubsystemVersion;
    DWORD Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    WORD Subsystem, DllCharacteristics;
    DWORD SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    DWORD LoaderFlags, NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32;
typedef struct {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;
typedef struct {
    BYTE Name[8];
    union { DWORD PhysicalAddress, VirtualSize; } Misc;
    DWORD VirtualAddress, SizeOfRawData, PointerToRawData;
    DWORD PointerToRelocations, PointerToLinenumbers;
    WORD NumberOfRelocations, NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER;

_Static_assert(sizeof(IMAGE_DOS_HEADER) == 64, "PE32 DOS header");
_Static_assert(offsetof(IMAGE_DOS_HEADER, e_lfanew) == 60, "PE32 lfanew");
_Static_assert(sizeof(IMAGE_FILE_HEADER) == 20, "PE32 file header");
_Static_assert(sizeof(IMAGE_OPTIONAL_HEADER32) == 224, "PE32 optional header");
_Static_assert(sizeof(IMAGE_NT_HEADERS32) == 248, "PE32 NT headers");
_Static_assert(sizeof(IMAGE_SECTION_HEADER) == 40, "PE32 section header");

HANDLE GetCurrentProcess(void);
BOOL ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
HMODULE LoadLibraryA(LPCSTR);
BOOL FreeLibrary(HMODULE);
FARPROC GetProcAddress(HMODULE, LPCSTR);
void SetLastError(DWORD);
DWORD GetLastError(void);
HANDLE GetProcessHeap(void);
LPVOID HeapAlloc(HANDLE, DWORD, SIZE_T);
BOOL HeapFree(HANDLE, DWORD, LPVOID);
char *lstrcpyA(char *, const char *);
char *lstrcatA(char *, const char *);
void InitializeCriticalSection(CRITICAL_SECTION *);
void EnterCriticalSection(CRITICAL_SECTION *);
void LeaveCriticalSection(CRITICAL_SECTION *);
void DeleteCriticalSection(CRITICAL_SECTION *);
#endif
