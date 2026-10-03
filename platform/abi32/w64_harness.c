/* SPDX-License-Identifier: GPL-2.0-only
 * WIN64 subsystem end-to-end harness (driven by w64_e2e.py).
 *
 * What executes for real (x86 machine code on the host CPU, static Linux ELF32, no libc):
 *   - NTW32.DLL, the MinGW-built PE32 image, mapped at its preferred base: the WIN64 client (ntw64.c).
 *   - NTW64RUN.EXE, the MinGW-built PE32 console tool, mapped at 0x00400000 and bound to NTW32.DLL's exports.
 *   - NTWRAP9X.VXD's bridge logic (ntwrapper/vxd/bridge.c + core.c, compiled here for i486 freestanding):
 *     DeviceIoControl is routed into ntwv_dioc_ex() exactly as the VxD's control procedure would route it.
 *   - The channel: a real shz_channel_init() region; the VxD pushes/pops the real rings with shz_ipc.h.
 * What is modeled:
 *   - KERNEL32 imports (bounded mocks below), the VMM page services (identity page model), the Supervisor
 *     hypercalls (ABI version, channel info, NOTIFY, DOORBELL_ACK) and the physical mapping.
 *   - Kernel64: every frame the VxD puts on the Win98->Kernel64 ring is popped here with shz_ring_pop() and sent
 *     over fd 1 to k64model.py, which decodes it with shizukudos/abi/test_abi.py's independent decoder and
 *     answers with slots encoded by test_abi.py's encoder. Those slots are checked here against the C library
 *     (CRC and byte identity with shz_ring_push()) and placed on the Kernel64->Win98 ring.
 * Nothing here is Windows 98, the VMM, the Supervisor or the real Kernel64. */
#include <stdint.h>
#include <stddef.h>
#include "pe_config.h"
#include "exe_config.h"
#include "../../ntwrapper/vxd/bridge.h"
#include "../../ntwin32/win64/ntw64.h"
#include "../../shizukudos/abi/shz_ipc.h"

#define STDCALL __attribute__((stdcall))
#define KERNEL_HANDLE UINT32_C(0x12340000)
#define VXD_HANDLE UINT32_C(0x0000d10c)
#define INVALID_HANDLE UINT32_C(0xffffffff)
#define STD_IN UINT32_C(0x100)
#define STD_OUT UINT32_C(0x101)
#define STD_ERR UINT32_C(0x102)
#define CHANNEL_GPA (SHZ_IPC_GPA_BASE + 2u * SHZ_IPC_REGION_SIZE)
#define ALIAS_BASE UINT32_C(0x80000000)

_Static_assert(sizeof(void *) == 4, "Must execute genuine 32-bit code");

/* ---------------------------------------------------------------- freestanding runtime */
void *memcpy(void *d, const void *s, size_t n);
void *memmove(void *d, const void *s, size_t n);
void *memset(void *d, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
void *memcpy(void *d, const void *s, size_t n) { uint8_t *a = d; const uint8_t *b = s; while (n--) *a++ = *b++; return d; }
void *memmove(void *d, const void *s, size_t n)
{
    uint8_t *a = d; const uint8_t *b = s;
    if (a < b) while (n--) *a++ = *b++;
    else while (n--) a[n] = b[n];
    return d;
}
void *memset(void *d, int c, size_t n) { uint8_t *a = d; while (n--) *a++ = (uint8_t)c; return d; }
int memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *x = a, *y = b;
    for (; n; --n, ++x, ++y) if (*x != *y) return *x < *y ? -1 : 1;
    return 0;
}

static int32_t sys3(uint32_t nr, uint32_t a, uint32_t b, uint32_t c)
{
    int32_t r;
    __asm__ volatile("int $0x80" : "=a"(r) : "a"(nr), "b"(a), "c"(b), "d"(c) : "memory");
    return r;
}
__attribute__((noreturn)) static void sys_exit(uint32_t code)
{
    __asm__ volatile("int $0x80" : : "a"(1), "b"(code) : "memory");
    for (;;) { }
}
static uint32_t slen(const char *s) { uint32_t n = 0; while (s[n]) ++n; return n; }
static void log_bytes(const char *s, uint32_t n) { (void)sys3(4, 2, (uint32_t)(uintptr_t)s, n); }
static void log_str(const char *s) { log_bytes(s, slen(s)); }
static void log_num(uint32_t v)
{
    char d[10];
    uint32_t n = 0;
    do { d[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (n) log_bytes(&d[--n], 1);
}

static uint32_t checks, pe_calls, exe_runs;
static const char *scenario = "startup";
__attribute__((noreturn)) static void fail(const char *what, uint32_t line)
{
    log_str("FAIL w64_harness line "); log_num(line); log_str(" ["); log_str(scenario); log_str("]: ");
    log_str(what); log_str("\n");
    sys_exit(1);
}
#define CHECK(x) do { ++checks; if (!(x)) fail(#x, __LINE__); } while (0)

/* ---------------------------------------------------------------- model link (fd 0 in, fd 1 out) */
enum { MSG_FRAME = 1, MSG_TICK = 2, MSG_DONE = 3, MSG_NOTE = 4 };
static void write_all(const void *p, uint32_t n)
{
    const uint8_t *b = p;
    while (n) {
        const int32_t w = sys3(4, 1, (uint32_t)(uintptr_t)b, n);
        if (w <= 0) fail("model pipe write", __LINE__);
        b += w; n -= (uint32_t)w;
    }
}
static void read_all(void *p, uint32_t n)
{
    uint8_t *b = p;
    while (n) {
        const int32_t r = sys3(3, 0, (uint32_t)(uintptr_t)b, n);
        if (r <= 0) fail("model pipe read", __LINE__);
        b += r; n -= (uint32_t)r;
    }
}

#define BACKLOG 512u
static uint8_t backlog[BACKLOG][SHZ_MSG_SLOT_SIZE] __attribute__((aligned(64)));
static uint32_t backlog_head, backlog_tail, model_slots, crc_agreements, byte_identical, raw_corrupt;

static void model_exchange(uint32_t type, const void *a, uint32_t an, const void *b, uint32_t bn)
{
    uint32_t hdr[2] = { type, an + bn }, count, i;
    write_all(hdr, sizeof hdr);
    if (an) write_all(a, an);
    if (bn) write_all(b, bn);
    read_all(&count, 4);
    CHECK(count <= BACKLOG);
    for (i = 0; i < count; ++i) {
        CHECK(backlog_head - backlog_tail < BACKLOG);
        read_all(backlog[backlog_head % BACKLOG], SHZ_MSG_SLOT_SIZE);
        ++backlog_head;
        ++model_slots;
    }
}
static void note(const char *text)
{
    scenario = text;
    model_exchange(MSG_NOTE, text, slen(text), 0, 0);
}

/* ---------------------------------------------------------------- channel (the Supervisor-created region) */
static uint8_t channel[SHZ_IPC_REGION_SIZE] __attribute__((aligned(4096)));
static shz_channel_hdr_t *chdr(void) { return (shz_channel_hdr_t *)channel; }
static shz_ring_hdr_t *k64_rx(void) { return shz_channel_ring_rx(channel, chdr(), SHZ_DOM_KERNEL64); }
static shz_ring_hdr_t *k64_tx(void) { return shz_channel_ring_tx(channel, chdr(), SHZ_DOM_KERNEL64); }

/* Kernel64 side of the transport, part 1: model slots onto the Kernel64->Win98 ring. A slot whose CRC the C
 * library accepts must also be byte-identical to what shz_ring_push() writes for the same header and payload;
 * slots the model corrupted on purpose go onto the ring raw, as a faulty peer would put them. */
static void flush_backlog(void)
{
    static uint8_t scratch_ring[sizeof(shz_ring_hdr_t) + 2u * SHZ_MSG_SLOT_SIZE] __attribute__((aligned(64)));
    while (backlog_head != backlog_tail) {
        shz_ring_hdr_t *tx = k64_tx();
        const uint8_t *s = backlog[backlog_tail % BACKLOG];
        shz_msg_hdr_t h;
        uint32_t head;
        if (tx->head - __atomic_load_n(&tx->tail, __ATOMIC_ACQUIRE) >= tx->slot_count)
            return;                                         /* ring full: the client drains it first */
        memcpy(&h, s, sizeof h);
        if (h.message_size >= sizeof h && h.message_size <= SHZ_MSG_SLOT_SIZE &&
            h.payload_length <= SHZ_MSG_MAX_INLINE && shz_msg_checksum((const shz_msg_hdr_t *)s) == h.checksum) {
            shz_ring_hdr_t *scratch = (shz_ring_hdr_t *)scratch_ring;
            shz_msg_hdr_t copy = h;
            ++crc_agreements;
            CHECK(shz_ring_init(scratch_ring, sizeof scratch_ring, 2) == SHZ_OK);
            CHECK(shz_ring_push(scratch, &copy, s + sizeof h) == SHZ_OK);
            CHECK(memcmp(shz_ring_slot(scratch, 0), s, SHZ_MSG_SLOT_SIZE) == 0);
            ++byte_identical;
        } else {
            ++raw_corrupt;
        }
        head = tx->head;
        memcpy(shz_ring_slot(tx, head), s, SHZ_MSG_SLOT_SIZE);
        __atomic_store_n(&tx->head, head + 1, __ATOMIC_RELEASE);
        ++backlog_tail;
    }
}

/* Kernel64 side of the transport, part 2 (doorbell): every frame the VxD pushed, popped with the C library
 * and handed to the model as the raw slot plus, for SHZ_MSGF_BUFFER, the pool block and its owner map. */
static uint32_t frames_to_model, pool_frames;
static void k64_service(void)
{
    shz_ring_hdr_t *rx = k64_rx();
    while (shz_ring_count(rx)) {
        static uint8_t extra[24 + 64 + NTWV_W64_SEND_MAX];
        uint8_t raw[SHZ_MSG_SLOT_SIZE], pl[SHZ_MSG_MAX_INLINE];
        shz_msg_hdr_t h;
        uint32_t result[2], n = 0;
        int reason = 0, rc;
        memcpy(raw, shz_ring_slot(rx, rx->tail), sizeof raw);
        rc = shz_ring_pop(rx, &h, pl, sizeof pl, &reason);
        result[0] = (uint32_t)rc;
        result[1] = (uint32_t)reason;
        memcpy(extra, result, sizeof result);
        n = sizeof result;
        if (rc == SHZ_OK && (h.flags & SHZ_MSGF_BUFFER)) {
            const uint64_t first = (h.buffer_offset - chdr()->pool_offset) / SHZ_POOL_BLOCK;
            const uint32_t blocks = (uint32_t)(((h.buffer_offset - chdr()->pool_offset) % SHZ_POOL_BLOCK +
                                               h.buffer_length + SHZ_POOL_BLOCK - 1) / SHZ_POOL_BLOCK);
            const uint32_t meta[4] = { (uint32_t)chdr()->pool_offset, (uint32_t)chdr()->pool_size, (uint32_t)first, blocks };
            uint32_t i;
            CHECK(shz_pool_check(channel, chdr(), &h, SHZ_DOM_WIN98) == SHZ_OK);   /* what Kernel64 runs first */
            CHECK(h.buffer_length <= NTWV_W64_SEND_MAX && blocks <= 64);
            memcpy(extra + n, meta, sizeof meta);
            n += sizeof meta;
            for (i = 0; i < blocks; ++i)
                extra[n++] = shz_pool_owner_table(channel)[first + i];
            memcpy(extra + n, channel + h.buffer_offset, h.buffer_length);
            n += h.buffer_length;
            ++pool_frames;
        }
        ++frames_to_model;
        model_exchange(MSG_FRAME, raw, sizeof raw, extra, n);
    }
    flush_backlog();
}

/* ---------------------------------------------------------------- VMM page services (identity model) */
extern uint8_t __harness_start[], __harness_end[];
static uint32_t protected_now, locked_ranges, page_checks;
static int mapped(uint32_t page, uint32_t count)
{
    const uint32_t lo = page << 12, hi = (page + count) << 12;
    return (lo >= EXE_BASE && hi <= EXE_BASE + EXE_IMAGE_SIZE) ||
           (lo >= (uint32_t)(uintptr_t)__harness_start && hi <= (((uint32_t)(uintptr_t)__harness_end + 4095u) & ~4095u)) ||
           (lo >= PE_BASE && hi <= PE_BASE + PE_IMAGE_SIZE);
}
static uint32_t page_check(uint32_t page, uint32_t count, uint32_t flags)
{
    CHECK(!protected_now && flags == 0 && count >= 1 && count <= 2);
    ++page_checks;
    return mapped(page, count) ? count : 0;
}
static uint32_t page_lock(uint32_t page, uint32_t count, uint32_t flags)
{
    CHECK(!protected_now && flags == NTWV_MAP_GLOBAL && mapped(page, count));
    ++locked_ranges;
    return ALIAS_BASE + (page << 12);
}
static uint32_t page_unlock(uint32_t page, uint32_t count, uint32_t flags)
{
    CHECK(!protected_now && flags == NTWV_MAP_GLOBAL && page >= (ALIAS_BASE >> 12) && count >= 1 && locked_ranges);
    --locked_ranges;
    return 1;
}
static uint32_t page_ptes(uint32_t page, uint32_t count, uint32_t *out, uint32_t flags)
{
    uint32_t i;
    CHECK(protected_now && flags == 0 && count >= 1 && count <= 2);
    for (i = 0; i < count; ++i) {
        const uint32_t p = page + i;
        out[i] = p >= (ALIAS_BASE >> 12) ? ((p - (ALIAS_BASE >> 12)) << 12) | 3u : (p << 12) | 7u;
    }
    return 1;
}
static uintptr_t irq_enter(void *opaque) { (void)opaque; CHECK(!protected_now); protected_now = 1; return 0x202; }
static void irq_leave(void *opaque, uintptr_t saved) { (void)opaque; CHECK(protected_now && saved == 0x202); protected_now = 0; }
static void alias_write(uint32_t alias, const void *src, uint32_t bytes)
{
    CHECK(protected_now && alias >= ALIAS_BASE);
    memcpy((void *)(uintptr_t)(alias - ALIAS_BASE), src, bytes);
}
static void alias_read(void *dst, uint32_t alias, uint32_t bytes)
{
    CHECK(protected_now && alias >= ALIAS_BASE);
    memcpy(dst, (const void *)(uintptr_t)(alias - ALIAS_BASE), bytes);
}
static const struct ntwv_pages pages = { page_check, page_lock, page_unlock, page_ptes, irq_enter, irq_leave,
                                         alias_write, alias_read };

/* ---------------------------------------------------------------- Supervisor model */
static uint32_t hv_present = 1, channel_announced = 1, notifies, doorbell_acks, abi_queries;
static int hypervisor_present(void) { return (int)hv_present; }
static int32_t hcall(uint32_t op, uint32_t a, uint32_t b, uint32_t *ebx, uint32_t *ecx)
{
    CHECK(!protected_now);
    switch (op) {
    case SHZ_HC_ABI_VERSION: ++abi_queries; if (ebx) *ebx = (SHZ_ABI_MAJOR << 16) | SHZ_ABI_MINOR; return SHZ_OK;
    case SHZ_HC_CHANNEL_INFO:
        if (!channel_announced || a != 2) return SHZ_E_NOENT;
        if (ebx) *ebx = CHANNEL_GPA;
        if (ecx) *ecx = SHZ_DOM_KERNEL64;
        return SHZ_OK;
    case SHZ_HC_NOTIFY:
        CHECK(a == SHZ_DOM_KERNEL64 && b == 1);
        ++notifies;
        k64_service();
        return SHZ_OK;
    case SHZ_HC_DOORBELL_ACK: ++doorbell_acks; if (ebx) *ebx = 0; return SHZ_OK;
    default: return SHZ_E_UNSUPPORTED;
    }
}
static void *map_phys(uint32_t phys, uint32_t bytes)
{
    CHECK(phys == CHANNEL_GPA && bytes == SHZ_IPC_REGION_SIZE);
    return channel;
}
static const struct ntwv_hv hv = { hypervisor_present, hcall, map_phys };

/* ---------------------------------------------------------------- KERNEL32 mocks */
static uint32_t last_error, sim_ms, sleeps, vxd_loadable = 1, vxd_loaded, device_open, create_file_calls, dioc_calls;
static void STDCALL mock_SetLastError(uint32_t e) { last_error = e; }
static uint32_t STDCALL mock_GetLastError(void) { return last_error; }
static uint32_t STDCALL mock_GetTickCount(void) { return sim_ms; }
static void STDCALL mock_Sleep(uint32_t ms)
{
    uint32_t t = ms ? ms : 1;
    CHECK(ms != UINT32_MAX && ++sleeps < 400000);
    sim_ms += t;
    model_exchange(MSG_TICK, &t, sizeof t, 0, 0);
    flush_backlog();
}
static int same(const char *a, const char *b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }
/* KERNEL32 is present; KernelEx (KERNELEX.DLL, KEXBASES.DLL, KEXBASEN.DLL), which NTW32's routing policy probes
 * for at attach, is not: this models a stock Windows 98 SE process. */
static uintptr_t STDCALL mock_GetModuleHandleA(const char *name)
{
    if (same(name, "KERNEL32.DLL")) return KERNEL_HANDLE;
    CHECK(same(name, "KERNELEX.DLL") || same(name, "KEXBASES.DLL") || same(name, "KEXBASEN.DLL"));
    last_error = 126;
    return 0;
}
/* None of the routed names is native to Windows 98 KERNEL32 in this model, so every route stays with NTW32's
 * own implementation (the routing policy itself is tested by harness.c and ntwin32/tests). */
static uintptr_t STDCALL mock_GetProcAddress(uintptr_t module, const char *name)
{
    CHECK(module == KERNEL_HANDLE);
    (void)name;
    last_error = 127;
    return 0;
}
/* Routing configuration at attach: no NTW32_ROUTING variable and no NTW32.INI beside the DLL (defaults). */
static uint32_t ini_lookups, debug_lines;
static uint32_t STDCALL mock_GetEnvironmentVariableA(const char *name, char *buffer, uint32_t size)
{
    CHECK(same(name, "NTW32_ROUTING") && buffer && size);
    last_error = 203;
    return 0;
}
static uint32_t STDCALL mock_GetModuleFileNameA(uintptr_t module, char *buffer, uint32_t size)
{
    static const char path[] = "C:\\SHIZUKU\\NTW32.DLL";
    CHECK(module == PE_BASE && size >= sizeof path);
    memcpy(buffer, path, sizeof path);
    return sizeof path - 1;
}
static uint32_t STDCALL mock_CloseHandle(uintptr_t handle) { (void)handle; fail("unexpected CloseHandle", __LINE__); }
/* Clock calls run with the typed page model in harness.c at both PE bases.
 * This separate W64 conversation must never start a clock query implicitly. */
static uint32_t STDCALL mock_VirtualQuery(const void *address, void *information, uint32_t bytes)
{
    (void)address; (void)information; (void)bytes;
    fail("unexpected VirtualQuery in W64 conversation", __LINE__);
}
static void STDCALL mock_OutputDebugStringA(const char *text) { CHECK(text && slen(text) < 512); ++debug_lines; }
static int STDCALL mock_MultiByteToWideChar(uint32_t page, uint32_t flags, const char *src, int len, uint16_t *dst, int cap)
{
    int i;
    CHECK(page == 0 && flags == 0 && len > 0 && src);                /* CP_ACP: NTW64RUN's argument conversion */
    if (cap == 0) return len;
    if (cap < len) { last_error = 122; return 0; }
    for (i = 0; i < len; ++i) {
        CHECK((uint8_t)src[i] < 0x80);                               /* the tests use ASCII command lines */
        dst[i] = (uint8_t)src[i];
    }
    return len;
}
static int STDCALL mock_WideCharToMultiByte(uint32_t page, uint32_t flags, const uint16_t *src, int len, char *dst,
                                            int cap, const char *def, int *used)
{
    (void)page; (void)flags; (void)src; (void)len; (void)dst; (void)cap; (void)def; (void)used;
    fail("unexpected WideCharToMultiByte", __LINE__);
}

static uint32_t dioc(uint32_t code, uint32_t in, uint32_t in_bytes, uint32_t out, uint32_t out_bytes, uint32_t returned)
{
    struct ntwv_dioc request;
    memset(&request, 0, sizeof request);
    request.code = code;
    request.input = in; request.input_bytes = in_bytes;
    request.output = out; request.output_bytes = out_bytes;
    request.returned = returned;
    return ntwv_dioc_ex(&request, &pages, &hv);
}

/* CreateFile("\\.\NTWRAP9X.VXD"): VWIN32 loads the dynamic VxD (Sys_Dynamic_Device_Init -> ntwv_native_init)
 * and sends DIOC_OPEN (code 0). `vxd_loadable = 0` reproduces the recorded guest result: error 2. */
static uintptr_t STDCALL mock_CreateFileA(const char *name, uint32_t access, uint32_t share, void *security,
                                          uint32_t disposition, uint32_t flags, uintptr_t template_file)
{
    static const char vxd[] = "\\\\.\\NTWRAP9X.VXD";
    static const struct ntw_lock_ops locks = { irq_enter, irq_leave, 0 };
    if (same(name, "C:\\SHIZUKU\\NTW32.INI")) {                        /* routing policy: absent, defaults */
        CHECK(access == 0x80000000u && share == 1 && !security && disposition == 3 && flags == 0x80u && !template_file);
        ++ini_lookups;
        last_error = 2;
        return INVALID_HANDLE;
    }
    ++create_file_calls;
    CHECK(memcmp(name, vxd, sizeof vxd) == 0 && access == 0 && share == 0 && !security && disposition == 3 &&
          flags == 0x04000000u && !template_file);
    if (!vxd_loadable) { last_error = 2; return INVALID_HANDLE; }
    if (!vxd_loaded) { CHECK(ntwv_initialize(&locks)); vxd_loaded = 1; }
    CHECK(dioc(0, 0, 0, 0, 0, 0) == 0);
    ++device_open;
    return VXD_HANDLE;
}
static uint32_t STDCALL mock_DeviceIoControl(uintptr_t device, uint32_t code, void *input, uint32_t input_bytes,
    void *output, uint32_t output_bytes, uint32_t *returned, void *overlapped)
{
    uint32_t result;
    CHECK(device == VXD_HANDLE && device_open && !overlapped);
    ++dioc_calls;
    flush_backlog();
    result = dioc(code, (uint32_t)(uintptr_t)input, input_bytes, (uint32_t)(uintptr_t)output, output_bytes,
                  (uint32_t)(uintptr_t)returned);
    CHECK(!protected_now && !locked_ranges);                          /* every pinned range released */
    flush_backlog();
    if (result) { last_error = result; return 0; }
    return 1;
}

/* NTW64RUN.EXE's own KERNEL32 imports */
static const char *exe_cmdline, *exe_stdin;
static uint32_t exe_stdin_pos;
static char exe_out[65536], exe_err[4096];
static uint32_t exe_out_len, exe_err_len;
extern uint32_t exe_call(uintptr_t entry, uint32_t *exited);
__attribute__((noreturn)) extern void exe_exit(uint32_t code);
static const char *STDCALL mock_GetCommandLineA(void) { return exe_cmdline; }
static uintptr_t STDCALL mock_GetStdHandle(uint32_t which)
{
    CHECK(which == (uint32_t)-10 || which == (uint32_t)-11 || which == (uint32_t)-12);
    return which == (uint32_t)-10 ? STD_IN : which == (uint32_t)-11 ? STD_OUT : STD_ERR;
}
static uint32_t STDCALL mock_WriteFile(uintptr_t h, const void *data, uint32_t n, uint32_t *written, void *ov)
{
    CHECK((h == STD_OUT || h == STD_ERR) && written && !ov);
    if (h == STD_OUT) { CHECK(exe_out_len + n <= sizeof exe_out); memcpy(exe_out + exe_out_len, data, n); exe_out_len += n; }
    else { CHECK(exe_err_len + n <= sizeof exe_err); memcpy(exe_err + exe_err_len, data, n); exe_err_len += n; }
    *written = n;
    return 1;
}
static uint32_t STDCALL mock_ReadFile(uintptr_t h, void *data, uint32_t n, uint32_t *got, void *ov)
{
    uint32_t avail;
    CHECK(h == STD_IN && got && !ov && exe_stdin);
    avail = slen(exe_stdin) - exe_stdin_pos;
    if (avail > n) avail = n;
    memcpy(data, exe_stdin + exe_stdin_pos, avail);
    exe_stdin_pos += avail;
    *got = avail;
    return 1;
}
__attribute__((noreturn)) static void STDCALL mock_ExitProcess(uint32_t code) { exe_exit(code); }

/* ---------------------------------------------------------------- PE images */
static uint8_t dll_pristine[PE_IMAGE_SIZE], exe_pristine[EXE_IMAGE_SIZE];
static void patch_dll(void)
{
#include "pe_imports.inc"
}
static void patch_exe(void)
{
#include "exe_imports.inc"
}

struct call_result { uint32_t low, high, stack_ok; };
extern void abi_call(uintptr_t target, const uint32_t *arguments, uint32_t count, struct call_result *result);
static uint32_t invoke(uint32_t target, uint32_t count, const uint32_t *args)
{
    struct call_result r;
    abi_call(target, args, count, &r);
    ++pe_calls;
    CHECK(r.stack_ok == 1);
    return r.low;
}
static uint32_t call1(uint32_t rva, uintptr_t a) { uint32_t v[] = { a }; return invoke(PE_BASE + rva, 1, v); }
static uint32_t call2(uint32_t rva, uintptr_t a, uintptr_t b) { uint32_t v[] = { a, b }; return invoke(PE_BASE + rva, 2, v); }
static uint32_t call3(uint32_t rva, uintptr_t a, uintptr_t b, uintptr_t c) { uint32_t v[] = { a, b, c }; return invoke(PE_BASE + rva, 3, v); }
static uint32_t call4(uint32_t rva, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{ uint32_t v[] = { a, b, c, d }; return invoke(PE_BASE + rva, 4, v); }

/* A process start: fresh images (data sections as on disk), bound imports, DllMain(PROCESS_ATTACH). */
static void process_start(void)
{
    static const char start[] = "process-start";
    model_exchange(MSG_NOTE, start, sizeof start - 1, 0, 0);          /* request ids restart with the DLL */
    memcpy((void *)(uintptr_t)PE_BASE, dll_pristine, PE_IMAGE_SIZE);
    memcpy((void *)(uintptr_t)EXE_BASE, exe_pristine, EXE_IMAGE_SIZE);
    patch_dll();
    patch_exe();
    const uint32_t lookups = ini_lookups;
    CHECK(call3(PE_ENTRY, PE_BASE, 1, 0) == 1);
    CHECK(ini_lookups == lookups + 1);                                    /* the routing policy ran at attach */
}
/* Process end: DllMain(PROCESS_DETACH), VWIN32 closes the device (DIOC_CLOSEHANDLE) and, the handle being the
 * last FILE_FLAG_DELETE_ON_CLOSE one, unloads the dynamic VxD (ntwv_native_exit: forget the channel, stop). */
static void process_end(void)
{
    CHECK(call3(PE_ENTRY, PE_BASE, 0, 0) == 1);
    if (device_open) {
        CHECK(dioc(UINT32_MAX, 0, 0, 0, 0, 0) == 1);
        device_open = 0;
        ntwv_w64_reset();
        CHECK(ntwv_shutdown());
        vxd_loaded = 0;
    }
}

/* ---------------------------------------------------------------- DLL API helpers */
static ntw64_info_t info;
static uint32_t query(void) { return call1(RVA_NtwQuerySubsystem64, (uintptr_t)&info); }
static uint32_t create(const uint16_t *path, const uint16_t *cmd, const uint16_t *cwd, uintptr_t *h)
{ return call4(RVA_NtwCreateProcess64W, (uintptr_t)path, (uintptr_t)cmd, (uintptr_t)cwd, (uintptr_t)h); }
static uint32_t read_con(uintptr_t h, void *buf, uint32_t cap, uint32_t *got)
{ return call4(RVA_NtwReadConsole64, h, (uintptr_t)buf, cap, (uintptr_t)got); }
static uint32_t write_con(uintptr_t h, const void *buf, uint32_t n, uint32_t *written)
{ return call4(RVA_NtwWriteConsole64, h, (uintptr_t)buf, n, (uintptr_t)written); }
static uint32_t close_con(uintptr_t h) { return call1(RVA_NtwCloseConsole64, h); }
static uint32_t wait_proc(uintptr_t h, uint32_t ms, uint32_t *code) { return call3(RVA_NtwWaitProcess64, h, ms, (uintptr_t)code); }
static uint32_t kill_proc(uintptr_t h, uint32_t code) { return call2(RVA_NtwKillProcess64, h, code); }
static uint32_t close_proc(uintptr_t h) { return call1(RVA_NtwCloseProcess64, h); }

static char out[65536];
static uint32_t read_all_output(uintptr_t h, uint32_t chunk)
{
    uint32_t n = 0, got = 0;
    while (read_con(h, out + n, chunk, &got)) {
        CHECK(got >= 1 && got <= chunk && n + got < sizeof out);
        n += got;
    }
    CHECK(last_error == NTW64_ERROR_HANDLE_EOF && got == 0);
    out[n] = 0;
    return n;
}
static int starts_with(const char *s, const char *prefix) { return memcmp(s, prefix, slen(prefix)) == 0; }
static int ends_with(const char *s, uint32_t n, const char *suffix)
{ const uint32_t k = slen(suffix); return n >= k && memcmp(s + n - k, suffix, k) == 0; }
static const char *find(const char *s, uint32_t n, const char *needle)
{
    const uint32_t k = slen(needle);
    uint32_t i;
    for (i = 0; i + k <= n; ++i) if (memcmp(s + i, needle, k) == 0) return s + i;
    return 0;
}
/* Removes the one stderr marker line (stdout and stderr share the console relay) and returns the new length. */
static uint32_t strip_once(char *s, uint32_t n, const char *needle)
{
    const char *at = find(s, n, needle);
    const uint32_t k = slen(needle);
    CHECK(at != 0);
    memmove((char *)at, at + k, (uint32_t)(s + n - (at + k)));
    CHECK(!find(s, n - k, needle));
    s[n - k] = 0;
    return n - k;
}
/* T_W64CON.EXE's 3,000-byte stdout block, generated like shizukudos/win64/tests/t_w64con.c does. */
static uint32_t w64con_block(char *dst)
{
    uint32_t i, k, n = 0;
    for (i = 0; i < 30; ++i) {
        const char head[8] = { 'l', 'i', 'n', 'e', ' ', (char)('0' + i / 10), (char)('0' + i % 10), ' ' };
        memcpy(dst + n, head, 8);
        for (k = 8; k < 99; ++k) dst[n + k] = (char)('a' + (i + k) % 26);
        dst[n + 99] = '\n';
        n += 100;
    }
    return n;
}
static uint32_t append(char *dst, uint32_t n, const char *s) { const uint32_t k = slen(s); memcpy(dst + n, s, k); dst[n + k] = 0; return n + k; }

static const uint16_t T_HELLO[] = u"\\SHZ\\TESTS\\T_HELLO.EXE";
static const uint16_t T_CON[] = u"\\SHZ\\TESTS\\T_W64CON.EXE";
static const uint16_t NOPE[] = u"\\SHZ\\TESTS\\NOPE.EXE";
static const uint16_t HANG[] = u"T_W64CON.EXE hang";
#define HELLO_TAIL "PROCESSOR_ARCHITECTURE=AMD64 (5 chars)\n"

static uintptr_t start_hang(void)
{
    uintptr_t h = 0;
    uint32_t got = 0;
    static char line[64];
    CHECK(create(T_CON, HANG, 0, &h) == 1 && h);
    CHECK(read_con(h, line, 31, &got) == 1 && got == 31 && memcmp(line, "t_w64con: hanging until killed\n", 31) == 0);
    return h;
}

/* ---------------------------------------------------------------- scenarios against the DLL exports */
static void dll_scenarios(void)
{
    static uint16_t longpath[262], longcmd[2100];
    static char expect[8192];
    uintptr_t h = 0, h2 = 0, hs[5];
    uint32_t code = 0, got = 0, n, i, sent_before;

    note("query: argument check before any transport");
    CHECK(call1(RVA_NtwQuerySubsystem64, 0) == 0 && last_error == 87 && create_file_calls == 0);

    note("query: VxD cannot be loaded (the recorded Win98 guest result, error 2)");
    vxd_loadable = 0;
    CHECK(query() == 0 && last_error == 2 && create_file_calls == 1 && !device_open);
    vxd_loadable = 1;

    note("query: no Shizuku Supervisor (VMCALL never executed)");
    hv_present = 0;
    CHECK(query() == 0 && last_error == NTWV_ERROR_NOT_SUPPORTED && device_open == 1 && abi_queries == 0);
    hv_present = 1;

    note("query: Supervisor without a Kernel64 channel");
    channel_announced = 0;
    CHECK(query() == 0 && last_error == NTWV_ERROR_DEV_NOT_EXIST && abi_queries == 1);
    channel_announced = 1;

    note("query: served by Kernel64");
    CHECK(query() == 1);
    CHECK(info.size == NTW64_INFO_SIZE && info.abi_major == 1 && info.abi_minor == 1 && info.subsystem_version == 0x10000u);
    CHECK(info.capabilities == 0x1fu && info.max_processes == 4 && info.active_processes == 0);
    CHECK(info.console_window == 8 && info.console_chunk == 176 && info.channel_id == 2 && info.generation == 1);
    CHECK(info.vxd_sent == 1 && info.vxd_received == 1 && info.vxd_proto_errors == 0 && create_file_calls == 2);

    note("create: argument validation sends nothing");
    sent_before = frames_to_model;
    for (i = 0; i < 261; ++i) longpath[i] = 'P';
    for (i = 0; i < 1987; ++i) longcmd[i] = 'x';                                  /* 22 + 1987 = 2009 units */
    longcmd[1987] = 0;
    CHECK(create(T_HELLO, 0, 0, 0) == 0 && last_error == 87);
    CHECK(create(0, 0, 0, &h) == 0 && last_error == 87 && h == 0);
    CHECK(create(u"", 0, 0, &h) == 0 && last_error == 87);
    CHECK(create(longpath, 0, 0, &h) == 0 && last_error == 87);                  /* 261 units */
    CHECK(create(T_HELLO, longcmd, 0, &h) == 0 && last_error == 87);
    CHECK(frames_to_model == sent_before);

    note("create: missing image -> FAILED event -> ERROR_FILE_NOT_FOUND");
    CHECK(create(NOPE, u"NOPE.EXE", 0, &h) == 0 && last_error == 2 && h == 0);

    note("T_HELLO.EXE: start, ordered output, exit code 7, release");
    CHECK(create(T_HELLO, u"T_HELLO.EXE first", 0, &h) == 1 && (h & 0xffff0000u) == 0x57340000u);
    n = read_all_output(h, 64);
    CHECK(starts_with(out, "hello from Win64 PE32+: argc=2 argv1=first image=0000000140000000 pid="));
    CHECK(ends_with(out, n, HELLO_TAIL));
    CHECK(read_con(h, out, 64, &got) == 0 && last_error == NTW64_ERROR_HANDLE_EOF);
    CHECK(wait_proc(h, 0, &code) == 1 && code == 7);
    CHECK(kill_proc(h, 5) == 1);                                                   /* already exited: idempotent */
    CHECK(close_proc(h) == 1);
    CHECK(wait_proc(h, 0, &code) == 0 && last_error == NTW64_ERROR_INVALID_HANDLE);

    note("invalid handles");
    CHECK(read_con(0, out, 4, &got) == 0 && last_error == 6);
    CHECK(write_con(0x57340001u, "x", 1, &got) == 0 && last_error == 6);
    CHECK(wait_proc(0x12345678u, 0, &code) == 0 && last_error == 6);
    CHECK(kill_proc(h, 1) == 0 && last_error == 6);
    CHECK(close_con(h) == 0 && last_error == 6);
    CHECK(close_proc(h) == 0 && last_error == 6);

    note("T_W64CON.EXE: stdin relay, EOF, stderr stream, output larger than the credit window");
    CHECK(create(T_CON, u"T_W64CON.EXE", 0, &h) == 1);
    CHECK(write_con(h, "hello bridge\n", 13, &got) == 1 && got == 13);
    CHECK(close_con(h) == 1 && close_con(h) == 1);
    CHECK(write_con(h, "late", 4, &got) == 0 && last_error == 87 && got == 0);
    n = read_all_output(h, 100);                                                  /* a slow, small-buffer reader */
    n = strip_once(out, n, "t_w64con: stderr marker\n");
    i = w64con_block(expect);
    i = append(expect, i, "t_w64con: cmdline=12 chars argc=1\necho:hello bridge\nt_w64con: stdin closed after 13 bytes\n");
    CHECK(n == i && memcmp(out, expect, n) == 0);
    CHECK(wait_proc(h, 1000, &code) == 1 && code == 0 && close_proc(h) == 1);

    note("T_W64CON.EXE: 263-character command line through the shared pool");
    for (i = 0; i < 13; ++i) longcmd[i] = (uint16_t)"T_W64CON.EXE "[i];
    for (i = 13; i < 263; ++i) longcmd[i] = (uint16_t)('a' + i % 26);
    longcmd[263] = 0;
    CHECK(create(T_CON, longcmd, 0, &h) == 1 && close_con(h) == 1);
    n = strip_once(out, read_all_output(h, 4096), "t_w64con: stderr marker\n");
    CHECK(find(out, n, "t_w64con: cmdline=263 chars argc=2\n") && ends_with(out, n, "stdin closed after 0 bytes\n"));
    CHECK(wait_proc(h, 1000, &code) == 1 && code == 0 && close_proc(h) == 1);

    note("create: the largest argument block (4,016 bytes, one full VxD SEND)");
    for (i = 13; i < 1985; ++i) longcmd[i] = 'z';                                 /* 23 + 1985 = 2008 units */
    longcmd[1985] = 0;
    CHECK(create(T_CON, longcmd, u"\\SHZ", &h) == 0 && last_error == 87);         /* + 4 cwd units: over */
    CHECK(create(T_CON, longcmd, 0, &h) == 1 && close_con(h) == 1);
    n = strip_once(out, read_all_output(h, 4096), "t_w64con: stderr marker\n");
    CHECK(find(out, n, "t_w64con: cmdline=1985 chars argc=2\n"));
    CHECK(wait_proc(h, 1000, &code) == 1 && code == 0 && close_proc(h) == 1);

    note("create: working directory is carried");
    CHECK(create(T_HELLO, u"T_HELLO.EXE cwd", u"\\SHZ\\TESTS", &h) == 1);
    n = read_all_output(h, 512);
    CHECK(starts_with(out, "hello from Win64 PE32+: argc=2 argv1=cwd ") && ends_with(out, n, HELLO_TAIL));
    CHECK(wait_proc(h, 1000, &code) == 1 && code == 7 && close_proc(h) == 1);

    note("KILL_PROCESS: exit code reported, output ends");
    h = start_hang();
    CHECK(kill_proc(h, 0x77) == 1);
    CHECK(wait_proc(h, 1000, &code) == 1 && code == 0x77);
    CHECK(read_con(h, out, 16, &got) == 0 && last_error == NTW64_ERROR_HANDLE_EOF);
    CHECK(write_con(h, "x", 1, &got) == 0 && last_error == 109);                  /* ERROR_BROKEN_PIPE */
    CHECK(close_proc(h) == 1);

    note("wait timeout on simulated time");
    h = start_hang();
    code = sim_ms;
    CHECK(wait_proc(h, 25, &got) == 0 && last_error == NTW64_ERROR_TIMEOUT && sim_ms - code >= 25);
    CHECK(kill_proc(h, 1) == 1 && wait_proc(h, 0xffffffffu, &code) == 1 && code == 1 && close_proc(h) == 1);

    note("closing a running process: released by the DLL once it exits");
    CHECK(create(T_HELLO, u"T_HELLO.EXE orphan", 0, &h) == 1);
    CHECK(close_proc(h) == 1 && wait_proc(h, 0, &code) == 0 && last_error == 6);
    for (i = 0; i < 3; ++i) CHECK(query() == 1);                                  /* pumps; the next entry releases */

    note("capacity: four Kernel64 slots, the fifth CREATE is NOMEM");
    for (i = 0; i < 4; ++i) hs[i] = start_hang();
    CHECK(create(T_HELLO, u"T_HELLO.EXE", 0, &hs[4]) == 0 && last_error == 8 && hs[4] == 0);
    CHECK(query() == 1 && info.active_processes == 4);
    for (i = 0; i < 4; ++i) CHECK(kill_proc(hs[i], 0x100 + i) == 1);
    for (i = 0; i < 4; ++i) CHECK(wait_proc(hs[i], 1000, &code) == 1 && code == 0x100 + i && close_proc(hs[i]) == 1);
    CHECK(query() == 1 && info.active_processes == 0);

    note("two processes at once, interleaved readers");
    CHECK(create(T_CON, u"T_W64CON.EXE a", 0, &h) == 1 && create(T_HELLO, u"T_HELLO.EXE b", 0, &h2) == 1 && h != h2);
    CHECK(close_con(h) == 1);
    n = read_all_output(h2, 7);
    CHECK(starts_with(out, "hello from Win64 PE32+: argc=2 argv1=b ") && ends_with(out, n, HELLO_TAIL));
    n = strip_once(out, read_all_output(h, 333), "t_w64con: stderr marker\n");
    i = w64con_block(expect);
    i = append(expect, i, "t_w64con: cmdline=14 chars argc=2\nt_w64con: stdin closed after 0 bytes\n");
    CHECK(n == i && memcmp(out, expect, n) == 0);
    CHECK(wait_proc(h, 0, &code) == 1 && code == 0 && wait_proc(h2, 0, &code) == 1 && code == 7);
    CHECK(close_proc(h) == 1 && close_proc(h2) == 1);

    note("a corrupted Kernel64 slot is dropped by the VxD and counted");
    CHECK(query() == 1 && info.vxd_proto_errors == 0);
    note("corrupt-next-reply");
    CHECK(query() == 1 && info.vxd_proto_errors == 1 && info.active_processes == 0);

    note("mute-next-request");
    code = sim_ms;
    CHECK(query() == 0 && last_error == NTW64_ERROR_TIMEOUT && sim_ms - code >= 5000);
    note("service answers again after a lost reply");
    CHECK(query() == 1 && info.abi_minor == 1);
}

/* ---------------------------------------------------------------- NTW64RUN.EXE runs */
static uint32_t run_exe(const char *cmdline, const char *stdin_text)
{
    uint32_t exited = 0, code;
    exe_cmdline = cmdline;
    exe_stdin = stdin_text ? stdin_text : "";
    exe_stdin_pos = 0;
    exe_out_len = exe_err_len = 0;
    process_start();
    code = exe_call(EXE_BASE + EXE_ENTRY, &exited);
    CHECK(exited == 1);                                                           /* ended through ExitProcess */
    process_end();
    exe_out[exe_out_len] = 0;
    exe_err[exe_err_len] = 0;
    ++exe_runs;
    return code;
}

static void exe_scenarios(void)
{
    static char expect[8192];
    uint32_t n;

    note("NTW64RUN: T_HELLO.EXE, exit code passed through");
    CHECK(run_exe("NTW64RUN.EXE \\SHZ\\TESTS\\T_HELLO.EXE first", 0) == 7);
    CHECK(starts_with(exe_out, "hello from Win64 PE32+: argc=2 argv1=first image=0000000140000000 pid="));
    CHECK(ends_with(exe_out, exe_out_len, HELLO_TAIL) && exe_err_len == 0);

    note("NTW64RUN: quoted program and image paths");
    CHECK(run_exe("\"C:\\SHIZUKU\\NTW64RUN.EXE\"  \"\\SHZ\\TESTS\\T_HELLO.EXE\" quoted  ", 0) == 7);
    CHECK(starts_with(exe_out, "hello from Win64 PE32+: argc=2 argv1=quoted ") && exe_err_len == 0);

    note("NTW64RUN /i: stdin forwarded, then EOF");
    CHECK(run_exe("NTW64RUN.EXE /i \\SHZ\\TESTS\\T_W64CON.EXE one two", "typed line\r\n") == 0);
    n = strip_once(exe_out, exe_out_len, "t_w64con: stderr marker\n");
    {
        uint32_t i = w64con_block(expect);
        i = append(expect, i, "t_w64con: cmdline=31 chars argc=3\necho:typed line\r\nt_w64con: stdin closed after 12 bytes\n");
        CHECK(n == i && memcmp(exe_out, expect, n) == 0 && exe_err_len == 0);
    }

    note("NTW64RUN without /i: the process sees EOF at once");
    CHECK(run_exe("NTW64RUN.EXE \\SHZ\\TESTS\\T_W64CON.EXE", "ignored\r\n") == 0);
    n = strip_once(exe_out, exe_out_len, "t_w64con: stderr marker\n");         /* streams merge in pump order */
    CHECK(ends_with(exe_out, n, "t_w64con: stdin closed after 0 bytes\n") && exe_stdin_pos == 0);

    note("NTW64RUN /d: working directory");
    CHECK(run_exe("NTW64RUN.EXE /d:\\SHZ \\SHZ\\TESTS\\T_HELLO.EXE dir", 0) == 7);
    CHECK(starts_with(exe_out, "hello from Win64 PE32+: argc=2 argv1=dir "));

    note("NTW64RUN /q");
    CHECK(run_exe("NTW64RUN.EXE /q", 0) == 0 && exe_err_len == 0);
    n = append(expect, 0, "WIN64 subsystem: ABI 1.1, subsystem 1.0, capabilities 0x1f\r\n"
                          "processes: 0 of 4 active; console window 8 x 176 bytes\r\nchannel 2 generation 1 (VxD: ");
    CHECK(starts_with(exe_out, expect) && ends_with(exe_out, exe_out_len, " received, 0 malformed)\r\n"));

    note("NTW64RUN: missing image");
    CHECK(run_exe("NTW64RUN.EXE \\SHZ\\TESTS\\NOPE.EXE", 0) == 255 && exe_out_len == 0);
    CHECK(starts_with(exe_err, "NTW64RUN: NtwCreateProcess64W failed, Win32 error 2 "));

    note("NTW64RUN: usage");
    CHECK(run_exe("NTW64RUN.EXE", 0) == 255 && starts_with(exe_err, "usage: NTW64RUN"));
    CHECK(run_exe("NTW64RUN.EXE /x \\SHZ\\TESTS\\T_HELLO.EXE", 0) == 255 && starts_with(exe_err, "usage: NTW64RUN"));

    note("NTW64RUN: VxD not loadable (the recorded guest failure) is reported, not hidden");
    vxd_loadable = 0;
    CHECK(run_exe("NTW64RUN.EXE /q", 0) == 255 && exe_out_len == 0);
    n = append(expect, 0, "NTW64RUN: NtwQuerySubsystem64 failed, Win32 error 2 (not found: NTWRAP9X.VXD");
    CHECK(starts_with(exe_err, expect));
    vxd_loadable = 1;

    note("NTW64RUN: no Supervisor");
    hv_present = 0;
    CHECK(run_exe("NTW64RUN.EXE \\SHZ\\TESTS\\T_HELLO.EXE", 0) == 255);
    CHECK(starts_with(exe_err, "NTW64RUN: NtwCreateProcess64W failed, Win32 error 50 (no ShizukuDOS Supervisor"));
    hv_present = 1;
}

int harness_main(void)
{
    CHECK(shz_channel_init(channel, sizeof channel, 2, SHZ_DOM_KERNEL64, SHZ_DOM_WIN98, 32, 1) == SHZ_OK);
    memcpy(dll_pristine, (const void *)(uintptr_t)PE_BASE, PE_IMAGE_SIZE);
    memcpy(exe_pristine, (const void *)(uintptr_t)EXE_BASE, EXE_IMAGE_SIZE);
    note("process 1: the harness calls NTW32.DLL's exports directly");
    process_start();
    dll_scenarios();
    process_end();
    exe_scenarios();
    note("done");
    CHECK(backlog_head == backlog_tail && shz_ring_count(k64_rx()) == 0 && shz_ring_count(k64_tx()) == 0);
    model_exchange(MSG_DONE, 0, 0, 0, 0);
    log_str("PASS NTW32 WIN64 end-to-end: "); log_num(checks); log_str(" checks; "); log_num(pe_calls);
    log_str(" DLL export calls and "); log_num(exe_runs); log_str(" NTW64RUN.EXE runs with verified ESP; ");
    log_num(frames_to_model); log_str(" VxD frames to the Kernel64 model ("); log_num(pool_frames);
    log_str(" pool-carried), "); log_num(model_slots); log_str(" model slots ("); log_num(byte_identical);
    log_str(" byte-identical to shz_ring_push, "); log_num(raw_corrupt); log_str(" corrupt on purpose), ");
    log_num(notifies); log_str(" doorbells, "); log_num(dioc_calls); log_str(" DeviceIoControl calls, ");
    log_num(sleeps); log_str(" Sleep ticks; Windows 98, VMM, Supervisor and Kernel64 modeled.\n");
    return 0;
}
