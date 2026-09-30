/* SPDX-License-Identifier: GPL-2.0-only
 * GPU 2D path from user mode (shzgpu.dll + user32/gdi32). Works on both display backends; the host runner
 * (tests/run_k64_gui.py) verifies the pixels of both scenes and, on virtio-gpu, the device traffic QEMU recorded.
 *
 *  1. ShzGpuQuery: backend, features, device-reported mode, EDID summary, capsets -> "GPU-INFO:" line.
 *  2. A window "GPU 2D" at (300,200)-(700,500): white client with a blue rectangle [20,120)x[20,80). Scene gpu2d-a.
 *  3. Counters, InvalidateRect of the 32x16 client rectangle [40,72)x[40,56), UpdateWindow (WM_PAINT fills exactly that
 *     rectangle yellow), counters again -> "GPU-2D-DELTA:" line. The update must reach the display as a small rectangle:
 *     at most 2 presents of at most 2 x 512 pixels, and on virtio-gpu at most 2 TRANSFER_TO_HOST_2D of 4 bytes per pixel
 *     with as many RESOURCE_FLUSH (never a full frame: 786432 pixels). Scene gpu2d-b.
 *  4. Hardware cursor: define a 64x64 arrow at (700,300), move it to (720,310), hide it -> "GPU-CURSOR:" line. On the
 *     BGA backend these calls must fail with STATUS_NOT_SUPPORTED.
 * Without a display it reports SKIP and exits 0 (the plain standalone runner has none).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"
#include "shzgpu.h"

static int bad, g_phase, g_paints;
#define CHECK(cond, name) do { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s (line %d)\n", name, __LINE__); ++bad; } } while (0)
#define NT_NOT_SUPPORTED ((int32_t)0xC00000BB)
#define NT_NO_SUCH_DEVICE ((int32_t)0xC000000E)

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        RECT r;
        HBRUSH b;
        if (g_phase == 0) {                         /* first paint: the blue rectangle on the white class background */
            r.left = 20; r.top = 20; r.right = 120; r.bottom = 80;
            b = CreateSolidBrush(RGB(0, 0, 255));
        } else {                                    /* second paint: exactly the invalidated rectangle, yellow */
            r.left = 40; r.top = 40; r.right = 72; r.bottom = 56;
            b = CreateSolidBrush(RGB(255, 255, 0));
        }
        FillRect(dc, &r, b);
        DeleteObject(b);
        EndPaint(h, &ps);
        ++g_paints;
        return 0;
    }
    if (m == WM_TIMER) { KillTimer(h, w); PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, m, w, l);
}

static void pump_for(HWND h, UINT ms)                /* lets the host take its screendump */
{
    MSG msg;
    SetTimer(h, 1, ms, 0);
    while (GetMessageW(&msg, 0, 0, 0) > 0) DispatchMessageW(&msg);
}

static void cursor_image(uint32_t *img)             /* opaque black-outlined white arrow, transparent elsewhere */
{
    int x, y;
    for (y = 0; y < 64; ++y)
        for (x = 0; x < 64; ++x) {
            uint32_t c = 0;
            if (y < 32 && x <= y / 2) c = (x == 0 || x == y / 2 || y == 31) ? 0xff000000u : 0xffffffffu;
            img[y * 64 + x] = c;
        }
}

int main(void)
{
    shz_gpu_info_t info, s0, s1;
    WNDCLASSEXW wc;
    HWND hwnd;
    RECT r;
    int32_t st, c1, c2, c3;
    static uint32_t img[64 * 64];
    uint8_t edid[256];
    uint32_t elen = 0;
    HINSTANCE inst = GetModuleHandleW(0);
    st = ShzGpuQuery(&info);
    if (st == NT_NO_SUCH_DEVICE) { printf("SKIP: no display device (%08x)\n", (unsigned)st); return 0; }
    CHECK(st >= 0, "ShzGpuQuery");
    if (st < 0) return 1;
    printf("GPU-INFO: backend=%u features=%x mode=%ux%u host=%ux%u scanouts=%u edid=%u vendor=%s pref=%ux%u capsets=%u "
           "pci=%x:%x devfeat=%llx drvfeat=%llx\n", info.backend, info.features, info.width, info.height, info.host_width,
           info.host_height, info.num_scanouts, info.edid_size, info.edid_size ? info.edid_vendor : "-", info.edid_pref_width,
           info.edid_pref_height, info.num_capsets, info.pci_vendor, info.pci_device, (unsigned long long)info.device_features,
           (unsigned long long)info.driver_features);
    CHECK(info.width >= 640 && info.height >= 480 && info.pitch == info.width * 4 &&
          (info.backend == SHZ_GPU_BACKEND_GOP || (info.width == 1024 && info.height == 768)),
          "desktop mode: 1024x768x32 (the firmware's mode on the UEFI GOP backend)");
    CHECK(info.backend == SHZ_GPU_BACKEND_BGA || info.backend == SHZ_GPU_BACKEND_VIRTIO || info.backend == SHZ_GPU_BACKEND_GOP,
          "a known display backend");
    if (info.backend == SHZ_GPU_BACKEND_VIRTIO) {
        CHECK((info.features & (SHZ_GPU_FEAT_2D | SHZ_GPU_FEAT_CURSOR)) == (SHZ_GPU_FEAT_2D | SHZ_GPU_FEAT_CURSOR), "virtio-gpu: 2D and cursor");
        CHECK(info.pci_vendor == 0x1af4 && info.pci_device == 0x1050, "virtio-gpu: modern PCI id 1af4:1050");
        CHECK(info.driver_features >> 32 & 1, "virtio-gpu: VIRTIO_F_VERSION_1 accepted");
        CHECK(info.num_scanouts >= 1 && info.host_width && info.host_height, "virtio-gpu: display info reports scanout 0");
        if (info.features & SHZ_GPU_FEAT_EDID) {
            st = ShzGpuGetEdid(edid, sizeof edid, &elen);
            CHECK(st >= 0 && elen >= 128 && elen == info.edid_size && edid[0] == 0 && edid[1] == 0xff && edid[7] == 0,
                  "virtio-gpu: EDID block with a valid header");
        }
        CHECK(info.stats.transfers_2d >= 1 && info.stats.flushes == info.stats.transfers_2d,
              "virtio-gpu: the desktop reached the host through TRANSFER_TO_HOST_2D + RESOURCE_FLUSH");
    } else {
        CHECK(ShzGpuGetEdid(edid, sizeof edid, &elen) == NT_NOT_SUPPORTED, "BGA/GOP: no EDID (STATUS_NOT_SUPPORTED)");
        CHECK(info.features == 0, "BGA/GOP: no accelerated features");
    }

    memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ShzGpu2D";
    CHECK(RegisterClassExW(&wc) != 0, "RegisterClassExW");
    hwnd = CreateWindowExW(0, L"ShzGpu2D", L"GPU 2D", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 300, 200, 400, 300, 0, 0, inst, 0);
    CHECK(hwnd != 0, "CreateWindowExW");
    if (!hwnd) return 1;
    UpdateWindow(hwnd);
    CHECK(g_paints == 1, "first WM_PAINT");
    printf("GUI-READY: gpu2d-a\n");
    pump_for(hwnd, 1500);

    CHECK(ShzGpuQuery(&s0) >= 0, "counters before the small update");
    g_phase = 1;
    r.left = 40; r.top = 40; r.right = 72; r.bottom = 56;
    InvalidateRect(hwnd, &r, TRUE);
    UpdateWindow(hwnd);
    CHECK(ShzGpuQuery(&s1) >= 0, "counters after the small update");
    CHECK(g_paints == 2, "the invalidation was painted");
    {
        const unsigned long long dp = s1.stats.presents - s0.stats.presents, dpx = s1.stats.present_pixels - s0.stats.present_pixels,
                                 dt = s1.stats.transfers_2d - s0.stats.transfers_2d, db = s1.stats.transfer_bytes - s0.stats.transfer_bytes,
                                 df = s1.stats.flushes - s0.stats.flushes;
        printf("GPU-2D-DELTA: presents=%llu pixels=%llu transfers=%llu bytes=%llu flushes=%llu\n", dp, dpx, dt, db, df);
        CHECK(dp >= 1 && dp <= 2 && dpx >= 512 && dpx <= 2 * 512, "a 32x16 invalidation is presented as at most 2 small rectangles");
        if (info.backend == SHZ_GPU_BACKEND_VIRTIO)
            CHECK(dt == dp && df == dp && db == 4 * dpx, "virtio-gpu: one TRANSFER_TO_HOST_2D + RESOURCE_FLUSH per rectangle, 4 bytes per pixel");
        else
            CHECK(dt == 0 && db == 0 && df == 0, "BGA/GOP: no virtio commands");
    }
    printf("GUI-READY: gpu2d-b\n");
    pump_for(hwnd, 1500);

    cursor_image(img);
    c1 = ShzGpuSetCursor(img, 0, 0, 700, 300);
    c2 = ShzGpuMoveCursor(720, 310);
    c3 = ShzGpuHideCursor();
    printf("GPU-CURSOR: shape=%08x move=%08x hide=%08x\n", (unsigned)c1, (unsigned)c2, (unsigned)c3);
    if (info.backend == SHZ_GPU_BACKEND_VIRTIO) {
        CHECK(c1 >= 0 && c2 >= 0 && c3 >= 0, "virtio-gpu: cursor define, move, hide");
        CHECK(ShzGpuSetCursor(img, 64, 0, 0, 0) < 0, "a hot spot outside the 64x64 image is refused");
        CHECK(ShzGpuQuery(&s1) >= 0 && s1.stats.cursor_cmds >= 3, "virtio-gpu: cursor queue commands were answered");
    } else {
        CHECK(c1 == NT_NOT_SUPPORTED && c2 == NT_NOT_SUPPORTED && c3 == NT_NOT_SUPPORTED, "BGA/GOP: no cursor plane (STATUS_NOT_SUPPORTED)");
    }
    CHECK(DestroyWindow(hwnd), "DestroyWindow");
    UnregisterClassW(L"ShzGpu2D", inst);
    printf("%s: GPU 2D test\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
