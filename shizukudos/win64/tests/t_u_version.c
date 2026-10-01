/* SPDX-License-Identifier: GPL-2.0-only
 * version.dll: GetFileVersionInfoSizeW / GetFileVersionInfoW / VerQueryValueW.
 * The fixture is this program's own image: tests/t_u_version.rc was compiled by mingw windres (an independent producer of
 * the VS_VERSIONINFO format) and linked into t_u_version.exe; every expected value below is what that .rc says.
 * As a second, independent path the test also walks its own *in-memory* resource tree and demands that the bytes the
 * file-based reader returns are identical (this catches file-offset arithmetic errors). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winver.h>
#include "u_check.h"

#define SELF L"C:\\SHZ\\TESTS\\T_U_VERSION.EXE"

/* --- independent in-memory locator of RT_VERSION / 1 / first language, by the documented resource directory layout --- */
static const unsigned char *mem_dir_find(const unsigned char *rsrc, DWORD dir_off, DWORD id, int any, DWORD *out_off, int *is_dir)
{
    const unsigned short *hdr = (const unsigned short *)(rsrc + dir_off);
    unsigned named = hdr[6], ids = hdr[7], i;
    const unsigned char *e = rsrc + dir_off + 16 + named * 8;
    for (i = 0; i < ids; ++i, e += 8) {
        DWORD name = *(const DWORD *)e, off = *(const DWORD *)(e + 4);
        if (any || name == id) { *out_off = off & 0x7fffffff; *is_dir = (off >> 31) & 1; return e; }
    }
    return 0;
}

static const unsigned char *memory_version_block(DWORD *size)
{
    const unsigned char *base = (const unsigned char *)GetModuleHandleW(0);
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(base + ((const IMAGE_DOS_HEADER *)base)->e_lfanew);
    const IMAGE_DATA_DIRECTORY *dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    const unsigned char *rsrc = base + dd->VirtualAddress;
    DWORD off = 0;
    int isdir = 0;
    if (!dd->VirtualAddress) return 0;
    if (!mem_dir_find(rsrc, 0, 16, 0, &off, &isdir) || !isdir) return 0;
    if (!mem_dir_find(rsrc, off, 1, 0, &off, &isdir) || !isdir) return 0;
    if (!mem_dir_find(rsrc, off, 0, 1, &off, &isdir) || isdir) return 0;
    {
        const DWORD *de = (const DWORD *)(rsrc + off);
        *size = de[1];
        return base + de[0];
    }
}

int main(void)
{
    static unsigned char buf[4096];
    DWORD handle = 0xdeadbeef, size, err, error_size;
    VS_FIXEDFILEINFO *ffi = 0;
    LPVOID p = 0;
    UINT len = 0;
    WCHAR path[MAX_PATH];
    BOOL ok;

    size = GetFileVersionInfoSizeW(SELF, &handle);
    U_CHECKF("GetFileVersionInfoSizeW(self) returns a size", size > 100 && size < sizeof buf, "size=%u err=%u", (unsigned)size, (unsigned)GetLastError());
    U_CHECK("...and zeroes the handle out-parameter", handle == 0);
    U_CHECK("GetFileVersionInfoSizeW accepts a NULL handle pointer", GetFileVersionInfoSizeW(SELF, 0) == size);

    memset(buf, 0xee, sizeof buf);
    ok = GetFileVersionInfoW(SELF, 0, size, buf);
    U_CHECKF("GetFileVersionInfoW fills the buffer", ok, "err=%u", (unsigned)GetLastError());
    U_CHECK("the block starts with wLength = size and the key VS_VERSION_INFO",
            *(unsigned short *)buf == size && u_ascii_eq_w((unsigned short *)(buf + 6), "VS_VERSION_INFO"));
    {
        DWORD msize = 0;
        const unsigned char *mem = memory_version_block(&msize);
        U_CHECKF("file-read version block is byte-identical to the resource in the loaded image", mem && msize >= size && !memcmp(mem, buf, size),
                 "mem=%p msize=%u", (void *)mem, (unsigned)msize);
    }
    U_CHECKF("GetFileVersionInfoW with a buffer one byte too small fails", !GetFileVersionInfoW(SELF, 0, size - 1, buf) && GetLastError() == ERROR_INSUFFICIENT_BUFFER,
             "err=%u", (unsigned)GetLastError());
    U_CHECK("GetFileVersionInfoW(NULL buffer) fails", !GetFileVersionInfoW(SELF, 0, size, 0));

    /* ---- VS_FIXEDFILEINFO ---- */
    ok = VerQueryValueW(buf, L"\\", (LPVOID *)&ffi, &len);
    U_CHECK("VerQueryValue(\"\\\") succeeds with the 52-byte VS_FIXEDFILEINFO", ok && ffi && len == sizeof(VS_FIXEDFILEINFO) && sizeof(VS_FIXEDFILEINFO) == 52);
    if (ok && ffi) {
        U_CHECKF("dwSignature = 0xFEEF04BD", ffi->dwSignature == 0xFEEF04BDu, "sig=%x", (unsigned)ffi->dwSignature);
        U_CHECKF("FILEVERSION 1,2,3,4 -> MS 0x00010002 LS 0x00030004", ffi->dwFileVersionMS == 0x00010002 && ffi->dwFileVersionLS == 0x00030004, "%x %x",
                 (unsigned)ffi->dwFileVersionMS, (unsigned)ffi->dwFileVersionLS);
        U_CHECKF("PRODUCTVERSION 5,6,7,8 -> MS 0x00050006 LS 0x00070008", ffi->dwProductVersionMS == 0x00050006 && ffi->dwProductVersionLS == 0x00070008, "%x %x",
                 (unsigned)ffi->dwProductVersionMS, (unsigned)ffi->dwProductVersionLS);
        U_CHECK("FILEFLAGSMASK 0x3f, FILEFLAGS 0, FILEOS 0x40004 (VOS_NT_WINDOWS32), FILETYPE 1 (VFT_APP), subtype 0",
                ffi->dwFileFlagsMask == 0x3f && ffi->dwFileFlags == 0 && ffi->dwFileOS == 0x40004 && ffi->dwFileType == VFT_APP && ffi->dwFileSubtype == 0);
    }
    ok = VerQueryValueW(buf, L"", (LPVOID *)&ffi, &len);
    U_CHECK("VerQueryValue with an empty sub-block also yields the root value", ok && len == 52);

    /* ---- VarFileInfo\Translation ---- */
    ok = VerQueryValueW(buf, L"\\VarFileInfo\\Translation", &p, &len);
    U_CHECKF("Translation: 8 bytes (two LANGID/codepage pairs)", ok && p && len == 8, "ok=%d len=%u", ok, len);
    if (ok && p) {
        const unsigned short *t = p;
        U_CHECKF("pairs are (0x0409, 0x04b0) and (0x0c0a, 0x04b0)", t[0] == 0x0409 && t[1] == 0x04b0 && t[2] == 0x0c0a && t[3] == 0x04b0, "%x %x %x %x", t[0], t[1], t[2], t[3]);
    }

    /* ---- StringFileInfo ---- */
    {
        static const struct { const WCHAR *sub; const WCHAR *value; const char *name; } sv[] = {
            { L"\\StringFileInfo\\040904b0\\CompanyName", L"Shizuku Test Company", "CompanyName (en-US)" },
            { L"\\StringFileInfo\\040904b0\\FileDescription", L"version.dll self-check fixture", "FileDescription (en-US)" },
            { L"\\StringFileInfo\\040904b0\\FileVersion", L"1.2.3.4", "FileVersion (en-US)" },
            { L"\\StringFileInfo\\040904b0\\InternalName", L"t_u_version", "InternalName (en-US)" },
            { L"\\StringFileInfo\\040904b0\\OriginalFilename", L"T_U_VERSION.EXE", "OriginalFilename (en-US)" },
            { L"\\StringFileInfo\\040904b0\\ProductName", L"Shizuku Win64 Runtime Tests", "ProductName (en-US)" },
            { L"\\StringFileInfo\\040904b0\\ProductVersion", L"5.6.7.8", "ProductVersion (en-US)" },
            { L"\\StringFileInfo\\040904b0\\LegalCopyright", L"Copyright (C) The Shizuku Authors \x00a9 2026", "LegalCopyright with a non-ASCII character (U+00A9)" },
            { L"\\StringFileInfo\\0c0a04b0\\CompanyName", L"Empresa de Pruebas Shizuku", "CompanyName (es-ES, second language block)" },
            { L"\\StringFileInfo\\0c0a04b0\\FileDescription", L"Fixture de autoverificaci\x00f3n", "FileDescription with U+00F3 (es-ES)" },
            { L"\\StringFileInfo\\0c0a04b0\\ProductName", L"Pruebas de Shizuku", "ProductName (es-ES)" },
            { L"\\stringfileinfo\\040904B0\\companyname", L"Shizuku Test Company", "keys are matched case-insensitively" },
        };
        unsigned i;
        for (i = 0; i < sizeof sv / sizeof sv[0]; ++i) {
            unsigned n = 0;
            while (sv[i].value[n]) ++n;
            p = 0; len = 0;
            ok = VerQueryValueW(buf, sv[i].sub, &p, &len);
            U_CHECKF(sv[i].name, ok && p && u_wide_eq(p, (const unsigned short *)sv[i].value) && len == n + 1, "ok=%d len=%u expect=%u", ok, len, n + 1);
        }
    }
    p = (LPVOID)1; len = 77;
    ok = VerQueryValueW(buf, L"\\StringFileInfo\\040904b0\\Comments", &p, &len);
    U_CHECK("an empty string value is found (length 1 = just the NUL)", ok && p && *(unsigned short *)p == 0 && len == 1);
    p = (LPVOID)1; len = 77;
    ok = VerQueryValueW(buf, L"\\StringFileInfo\\040904b0\\NoSuchName", &p, &len);
    U_CHECK("a missing string name fails and clears the outputs", !ok && p == 0 && len == 0);
    ok = VerQueryValueW(buf, L"\\StringFileInfo\\0c0a04b0\\FileVersion", &p, &len);
    U_CHECK("a name that exists only in the other language block fails", !ok);
    ok = VerQueryValueW(buf, L"\\StringFileInfo\\ffff04b0\\CompanyName", &p, &len);
    U_CHECK("a missing language block fails", !ok);
    ok = VerQueryValueW(buf, L"\\NoSuchBlock", &p, &len);
    U_CHECK("a missing top-level block fails", !ok);
    U_CHECK("VerQueryValue(NULL block) fails", !VerQueryValueW(0, L"\\", &p, &len));
    U_CHECK("VerQueryValue(NULL sub-block) fails", !VerQueryValueW(buf, 0, &p, &len));

    /* ---- every image the tree builds carries a VS_VERSIONINFO (build.py + tools/verres.py): the system DLLs report
     * the OS version the loader puts in the PEB (10.0.22631, kernel64/ldr.c), which is what a program derives the Windows
     * version from when it reads kernel32.dll's file version (Chromium's base::win::OSInfo does exactly that) ---- */
    {
        static const struct { const WCHAR *name; const char *label; DWORD type; } imgs[] = {
            { L"kernel32.dll", "kernel32.dll by bare name (DLL search order: the system directory)", VFT_DLL },
            { L"C:\\SHZ\\SYS64\\kernel32.dll", "kernel32.dll by full path", VFT_DLL },
            { L"ntdll.dll", "ntdll.dll", VFT_DLL },
            { L"version.dll", "version.dll (this DLL)", VFT_DLL },
            { L"advapi32", "advapi32 without an extension (.dll appended as LoadLibrary does)", VFT_DLL },
            { L"user32.dll", "user32.dll", VFT_DLL },
            { L"crypt32.dll", "crypt32.dll (Wine port, Wine's own version.rc)", VFT_DLL },
            { L"dwrite.dll", "dwrite.dll (Wine port without a Wine version.rc: generated resource)", VFT_DLL },
            { L"C:\\SHZ\\TESTS\\T_HELLO.EXE", "T_HELLO.EXE (an application without its own .rc)", VFT_APP },
        };
        unsigned i;
        for (i = 0; i < sizeof imgs / sizeof imgs[0]; ++i) {
            static unsigned char vb[4096];
            char nm[200];
            DWORD sz = GetFileVersionInfoSizeW(imgs[i].name, 0);
            VS_FIXEDFILEINFO *f = 0;
            UINT l = 0;
            BOOL got = sz && sz <= sizeof vb && GetFileVersionInfoW(imgs[i].name, 0, sz, vb) && VerQueryValueW(vb, L"\\", (LPVOID *)&f, &l) && l == 52;
            snprintf(nm, sizeof nm, "version resource of %s", imgs[i].label);
            U_CHECKF(nm, got, "size=%u err=%u", (unsigned)sz, (unsigned)GetLastError());
            if (!got) continue;
            snprintf(nm, sizeof nm, "...FILETYPE %s and a file version", imgs[i].type == VFT_DLL ? "VFT_DLL" : "VFT_APP");
            U_CHECKF(nm, f->dwFileType == imgs[i].type && (f->dwFileVersionMS | f->dwFileVersionLS), "type=%u ms=%x", (unsigned)f->dwFileType, (unsigned)f->dwFileVersionMS);
            if (imgs[i].name[0] != 'c' && imgs[i].name[0] != 'C') {     /* crypt32 keeps Wine's version; the others carry the OS version */
                LPVOID sv = 0;
                UINT sl = 0;
                snprintf(nm, sizeof nm, "...file version 10.0.22631.1 (the PEB OS version)");
                U_CHECKF(nm, f->dwFileVersionMS == 0x000a0000 && f->dwFileVersionLS == (22631u << 16 | 1), "%x.%x", (unsigned)f->dwFileVersionMS, (unsigned)f->dwFileVersionLS);
                U_CHECK("...StringFileInfo\\040904b0\\FileVersion begins with \"10.0.22631.1\" (kernel32/ntdll add \" (ShizukuDOS Win64 runtime)\", as Windows appends its build tag)",
                        VerQueryValueW(vb, L"\\StringFileInfo\\040904b0\\FileVersion", &sv, &sl) && sv && sl >= 12 && !memcmp(sv, L"10.0.22631.1", 24) && (((WCHAR *)sv)[12] == 0 || ((WCHAR *)sv)[12] == ' '));
            }
        }
        U_CHECK("GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, kernel32.dll) returns the same size",
                GetFileVersionInfoSizeExW(0x2, L"kernel32.dll", 0) == GetFileVersionInfoSizeW(L"kernel32.dll", 0));
        U_CHECK("GetFileVersionInfoSizeExW with an unknown flag fails with ERROR_INVALID_PARAMETER",
                !GetFileVersionInfoSizeExW(0x100, L"kernel32.dll", 0) && GetLastError() == ERROR_INVALID_PARAMETER);
        U_CHECK("a bare name that no directory has fails with ERROR_FILE_NOT_FOUND",
                !GetFileVersionInfoSizeW(L"no_such_module_xyz.dll", 0) && GetLastError() == ERROR_FILE_NOT_FOUND);
    }

    /* ---- files without usable version data: every image the build produces has a version resource now, so the PE
     * without a resource directory is a fixture this program writes itself (a minimal PE32+ image: DOS header, NT headers
     * with an empty data directory, one section) ---- */
    {
        static unsigned char pe[1024];
        HANDLE hf;
        DWORD wr = 0;
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)pe;
        IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(pe + 0x80);
        IMAGE_SECTION_HEADER *sh = (IMAGE_SECTION_HEADER *)(nt + 1);
        memset(pe, 0, sizeof pe);
        dos->e_magic = IMAGE_DOS_SIGNATURE;
        dos->e_lfanew = 0x80;
        nt->Signature = IMAGE_NT_SIGNATURE;
        nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt->FileHeader.NumberOfSections = 1;
        nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL;
        nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt->OptionalHeader.SectionAlignment = 0x1000;
        nt->OptionalHeader.FileAlignment = 0x200;
        nt->OptionalHeader.SizeOfImage = 0x2000;
        nt->OptionalHeader.SizeOfHeaders = 0x200;
        nt->OptionalHeader.NumberOfRvaAndSizes = 16;
        memcpy(sh->Name, ".text", 5);
        sh->Misc.VirtualSize = 0x10; sh->VirtualAddress = 0x1000; sh->SizeOfRawData = 0x200; sh->PointerToRawData = 0x200;
        sh->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        hf = CreateFileW(L"C:\\SHZ\\TESTS\\NORSRC.DLL", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
        U_CHECK("the no-resource PE fixture can be written", hf != INVALID_HANDLE_VALUE && WriteFile(hf, pe, 0x400, &wr, 0) && wr == 0x400 && CloseHandle(hf));
    }
    SetLastError(0);
    /* Capture the API result and error before U_CHECK prints through WriteFile,
     * which may change the calling thread's last-error value. */
    error_size = GetFileVersionInfoSizeW(L"C:\\SHZ\\TESTS\\NORSRC.DLL", 0);
    err = GetLastError();
    U_CHECK("a PE without a resource directory (NORSRC.DLL fixture): size 0", error_size == 0);
    U_CHECKF("...with ERROR_RESOURCE_DATA_NOT_FOUND", err == ERROR_RESOURCE_DATA_NOT_FOUND, "err=%u", (unsigned)err);
    U_CHECK("GetFileVersionInfoW of it fails", !GetFileVersionInfoW(L"C:\\SHZ\\TESTS\\NORSRC.DLL", 0, sizeof buf, buf));
    DeleteFileW(L"C:\\SHZ\\TESTS\\NORSRC.DLL");
    SetLastError(0);
    error_size = GetFileVersionInfoSizeW(L"C:\\SHZ\\TESTS\\NO_SUCH_FILE.DLL", 0);
    err = GetLastError();
    U_CHECK("a nonexistent file: size 0", error_size == 0);
    U_CHECKF("...with ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND", err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND, "err=%u", (unsigned)err);
    SetLastError(0);
    error_size = GetFileVersionInfoSizeW(L"C:\\SHZ\\TESTS\\NOTPE.TXT", 0);
    err = GetLastError();
    U_CHECK("a text file that is not a PE image: size 0", error_size == 0);
    U_CHECKF("...with ERROR_BAD_EXE_FORMAT", err == ERROR_BAD_EXE_FORMAT, "err=%u", (unsigned)err);
    U_CHECK("NULL file name: size 0", GetFileVersionInfoSizeW(0, 0) == 0);
    U_CHECK("empty file name: size 0", GetFileVersionInfoSizeW(L"", 0) == 0);

    /* the module path the loader reports names the same file */
    {
        DWORD n = GetModuleFileNameW(0, path, MAX_PATH);
        U_CHECKF("GetModuleFileNameW(NULL) names a file whose version info can be read", n > 0 && GetFileVersionInfoSizeW(path, 0) == size, "n=%u size=%u",
                 (unsigned)n, (unsigned)GetFileVersionInfoSizeW(path, 0));
    }
    return u_finish("t_u_version");
}
