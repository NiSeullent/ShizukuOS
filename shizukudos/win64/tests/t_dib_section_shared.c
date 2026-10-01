/* SPDX-License-Identifier: GPL-2.0-only
 * Actual shared DIB pixels, GDI raster drawing, cross-process visibility and
 * mapping lifetime. No display is needed for the memory-DC contract.
 */
#include <limits.h>
#include "k32test.h"

#define SHARED_BYTES 131072u
#define PIXEL_OFFSET 65540u
static void bitmap_info(BITMAPINFO *info)
{
    memset(info, 0, sizeof *info);
    info->bmiHeader.biSize = sizeof info->bmiHeader;
    info->bmiHeader.biWidth = 4; info->bmiHeader.biHeight = -3;
    info->bmiHeader.biPlanes = 1; info->bmiHeader.biBitCount = 32;
}

static int child(const char *name)
{
    HANDLE section = OpenFileMappingA(FILE_MAP_WRITE | FILE_MAP_READ, FALSE, name);
    BITMAPINFO info;
    HDC dc = CreateCompatibleDC(NULL);
    HBITMAP bitmap = NULL, old = NULL;
    DWORD *bits = NULL;
    bitmap_info(&info);
    CHECK(section && dc, "child opens actual shared mapping and memory DC");
    if (section && dc) bitmap = CreateDIBSection(dc, &info, DIB_RGB_COLORS, (void **)&bits, section, PIXEL_OFFSET);
    CHECK(bitmap && bits, "child maps its own section-backed DIB view");
    if (bitmap && bits) {
        old = SelectObject(dc, bitmap);
        CHECK(old != NULL, "child selects real DIB into GDI DC");
        CHECK(SetPixel(dc, 0, 0, RGB(0x12, 0x34, 0x56)) == RGB(0x12, 0x34, 0x56), "child GDI raster writes real shared pixel");
        bits[1] = 0xfedcba98u;
        CHECK(GdiFlush(), "child synchronizes GDI drawing");
        if (old) SelectObject(dc, old);
        CHECK(DeleteObject(bitmap), "child deletes its bitmap view");
    }
    if (dc) DeleteDC(dc);
    if (section) CHECK(CloseHandle(section), "child closes caller-owned section handle");
    return k32t_finish("T_DIB_SHARED_CHILD");
}

int main(int argc, char **argv)
{
    HANDLE section = NULL, readonly = NULL, duplicate = NULL, event = NULL;
    DWORD *mapping = NULL, *bits = NULL, *copy_bits = NULL;
    BITMAPINFO info;
    DIBSECTION metadata;
    MEMORY_BASIC_INFORMATION memory = {0};
    BITMAPV5HEADER extended;
    void *owned_view = NULL;
    HDC dc = NULL, target = NULL;
    HBITMAP bitmap = NULL, copy = NULL, old = NULL, target_old = NULL, temporary;
    char name[96], executable[512] = {0}, command[768];
    PROCESS_INFORMATION process;
    STARTUPINFOA startup;
    DWORD exit_code = 1, before;
    unsigned i;
    if (argc == 3 && !strcmp(argv[1], "--child")) return child(argv[2]);
    snprintf(name, sizeof name, "Local\\SHZ-DIB-%lu", (unsigned long)GetCurrentProcessId());
    section = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SHARED_BYTES, name);
    CHECK(section != NULL, "real named read-write section created");
    if (!section) return 1;
    mapping = MapViewOfFile(section, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, SHARED_BYTES);
    CHECK(mapping != NULL, "independent view maps actual section pages");
    if (!mapping) goto done;
    for (i = 0; i < SHARED_BYTES / 4; ++i) mapping[i] = 0xaabbccddu;
    bitmap_info(&info);
    dc = CreateCompatibleDC(NULL); target = CreateCompatibleDC(NULL);
    CHECK(dc && target, "two real memory DCs created");
    if (!dc || !target) goto done;
    bitmap = CreateDIBSection(dc, &info, DIB_RGB_COLORS, (void **)&bits, section, PIXEL_OFFSET);
    CHECK(bitmap && bits, "DWORD-aligned interior offset maps with separate 64KiB owned base");
    if (!bitmap || !bits) goto done;
    CHECK(bits[0] == 0xaabbccddu && bits[11] == 0xaabbccddu, "creation preserves preexisting section pixels");
    CHECK(GetObjectW(bitmap, sizeof metadata, &metadata) == sizeof metadata &&
          metadata.dshSection == section && metadata.dsOffset == PIXEL_OFFSET && metadata.dsBm.bmBits == bits &&
          metadata.dsBm.bmWidthBytes == 16 && metadata.dsBmih.biHeight == -3 && metadata.dsBmih.biSizeImage == 48,
          "DIBSECTION metadata describes actual shared view and offset");
    CHECK(VirtualQuery(bits, &memory, sizeof memory) == sizeof memory && memory.State == MEM_COMMIT && memory.Type == MEM_MAPPED,
          "bitmap pixels occupy genuine mapped section pages");
    owned_view = memory.AllocationBase;
    old = SelectObject(dc, bitmap);
    CHECK(old != NULL, "parent selects real shared bitmap");
    CHECK(SetPixel(dc, 2, 1, RGB(0x11, 0x22, 0x33)) == RGB(0x11, 0x22, 0x33) && GdiFlush(), "parent GDI draws into shared backing");
    CHECK(mapping[PIXEL_OFFSET / 4 + 6] == 0x112233u, "independent mapped view sees GDI write without a copied allocation");
    mapping[PIXEL_OFFSET / 4 + 7] = 0x445566u;
    CHECK(GetPixel(dc, 3, 1) == RGB(0x44, 0x55, 0x66), "GDI sees writes from independent section view");
    memset(&startup, 0, sizeof startup); startup.cb = sizeof startup;
    memset(&process, 0, sizeof process);
    CHECK(GetModuleFileNameA(NULL, executable, sizeof executable) != 0, "actual guest executable path discovered");
    snprintf(command, sizeof command, "\"%s\" --child %s", executable, name);
    CHECK(CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process), "real child process starts shared GDI drawing");
    if (process.hProcess) {
        CHECK(WaitForSingleObject(process.hProcess, 15000) == WAIT_OBJECT_0, "shared drawing child completes");
        CHECK(GetExitCodeProcess(process.hProcess, &exit_code) && exit_code == 0, "child's genuine GDI checks pass");
        if (exit_code == STILL_ACTIVE) { TerminateProcess(process.hProcess, 1); WaitForSingleObject(process.hProcess, 5000); }
        CloseHandle(process.hThread); CloseHandle(process.hProcess);
        CHECK(bits[0] == 0x123456u && bits[1] == 0xfedcba98u, "parent bitmap sees actual cross-process shared writes");
    }
    copy = CreateDIBSection(target, &info, DIB_RGB_COLORS, (void **)&copy_bits, NULL, 123);
    CHECK(copy && copy_bits, "ordinary private DIB ignores offset when no section is supplied");
    if (copy && copy_bits) {
        target_old = SelectObject(target, copy);
        CHECK(BitBlt(target, 0, 0, 4, 3, dc, 0, 0, SRCCOPY), "real raster BitBlt reads shared bitmap pixels");
        CHECK(copy_bits[0] == bits[0] && copy_bits[1] == bits[1] && copy_bits[6] == 0x112233u,
              "software presentation copy preserves real RGB and alpha bytes");
        CHECK(GetObjectW(copy, sizeof metadata, &metadata) == sizeof metadata && !metadata.dshSection && !metadata.dsOffset,
              "ordinary private DIB metadata reports no section or offset");
    }
    CHECK(!DeleteObject(bitmap), "selected shared bitmap cannot release a live DC's view");
    SelectObject(dc, old); old = NULL;
    CHECK(DeleteObject(bitmap), "unselected bitmap unmaps exactly its owned base"); bitmap = NULL;
    CHECK(owned_view && VirtualQuery(owned_view, &memory, sizeof memory) == sizeof memory && memory.State == MEM_FREE,
          "bitmap deletion releases its mapped view rather than leaking its interior allocation");
    CHECK(mapping[PIXEL_OFFSET / 4] == 0x123456u && mapping[PIXEL_OFFSET / 4 - 1] == 0xaabbccddu &&
          mapping[PIXEL_OFFSET / 4 + 12] == 0xaabbccddu, "deletion preserves independent view and neighboring bytes");
    temporary = CreateDIBSection(dc, &info, DIB_RGB_COLORS, (void **)&bits, section, 4);
    CHECK(temporary && bits && bits[0] == 0xaabbccddu, "small interior offset uses genuine section contents");
    if (temporary) CHECK(DeleteObject(temporary), "small-offset owned mapping releases");
    memset(&extended, 0, sizeof extended);
    extended.bV5Size = sizeof extended; extended.bV5Width = 4; extended.bV5Height = -3;
    extended.bV5Planes = 1; extended.bV5BitCount = 32; extended.bV5Compression = BI_BITFIELDS;
    extended.bV5RedMask = 0x00ff0000u; extended.bV5GreenMask = 0x0000ff00u; extended.bV5BlueMask = 0x000000ffu;
    temporary = CreateDIBSection(dc, (BITMAPINFO *)&extended, DIB_RGB_COLORS, (void **)&bits, section, 4);
    CHECK(temporary && bits && GetObjectW(temporary, sizeof metadata, &metadata) == sizeof metadata &&
          metadata.dsBitfields[0] == 0x00ff0000u && metadata.dsBitfields[1] == 0x0000ff00u && metadata.dsBitfields[2] == 0x000000ffu,
          "extended-header BITFIELDS masks describe actual mapped RGB pixels");
    if (temporary) CHECK(DeleteObject(temporary), "extended-header bitmap owned view releases");
    CHECK(DuplicateHandle(GetCurrentProcess(), section, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS),
          "caller duplicates real section handle");
    if (duplicate) {
        temporary = CreateDIBSection(dc, &info, DIB_RGB_COLORS, (void **)&bits, duplicate, 4);
        CHECK(temporary && bits, "bitmap owns view independently of caller's duplicate handle");
        CloseHandle(duplicate); duplicate = NULL;
        if (temporary) {
            bits[0] = 0x102030u;
            CHECK(mapping[1] == 0x102030u, "view survives closing caller's section handle");
            CHECK(DeleteObject(temporary), "deletion releases view without closing caller handles again");
        }
    }
    readonly = OpenFileMappingA(FILE_MAP_READ, FALSE, name);
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    before = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
    bits = (void *)1;
    CHECK(!CreateDIBSection(dc, &info, DIB_RGB_COLORS, (void **)&bits, section, 2) && !bits, "unaligned pixel offset fails with NULL output");
    bits = (void *)1;
    CHECK(!CreateDIBSection(dc, &info, DIB_RGB_COLORS, (void **)&bits, section, SHARED_BYTES - 4) && !bits,
          "pixel extent beyond actual section fails without a bitmap");
    bits = (void *)1;
    CHECK(readonly && !CreateDIBSection(dc, &info, DIB_RGB_COLORS, (void **)&bits, readonly, 0) && !bits,
          "read-only handle cannot supply writable DIB pixels");
    bits = (void *)1;
    CHECK(event && !CreateDIBSection(dc, &info, DIB_RGB_COLORS, (void **)&bits, event, 0) && !bits,
          "non-section object fails with NULL output");
    info.bmiHeader.biHeight = LONG_MIN;
    bits = (void *)1;
    CHECK(!CreateDIBSection(dc, &info, DIB_RGB_COLORS, (void **)&bits, section, 0) && !bits, "minimum signed height fails without overflow");
    info.bmiHeader.biWidth = LONG_MAX; info.bmiHeader.biHeight = LONG_MAX;
    bits = (void *)1;
    CHECK(!CreateDIBSection(dc, &info, DIB_RGB_COLORS, (void **)&bits, section, 0) && !bits, "excessive dimensions fail before mapping");
    CHECK(GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS) == before, "failed mapping/dimension calls do not leak GDI handles");
 done:
    if (old && dc) SelectObject(dc, old);
    if (target_old && target) SelectObject(target, target_old);
    if (bitmap) DeleteObject(bitmap);
    if (copy) DeleteObject(copy);
    if (dc) DeleteDC(dc);
    if (target) DeleteDC(target);
    if (mapping) CHECK(UnmapViewOfFile(mapping), "independent caller view releases");
    if (readonly) CloseHandle(readonly);
    if (event) CloseHandle(event);
    if (duplicate) CloseHandle(duplicate);
    if (section) CHECK(CloseHandle(section), "caller retains and closes original section handle");
    return k32t_finish("T_DIB_SECTION_SHARED");
}
