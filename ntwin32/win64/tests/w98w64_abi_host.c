/* SPDX-License-Identifier: GPL-2.0-only
 * Host negative checks of the Win98 -> Shizuku64 GUI request/response ABI, compiled against the REAL headers
 * (shizukudos/abi/shz_w64_gui.h) and the REAL VxD owner stamper (ntwrapper/vxd/w64_owner.c). Not a runtime proof. */
#include <stdio.h>
#include <string.h>
#include "../../../shizukudos/abi/shz_w64_gui.h"
#include "../../../ntwrapper/vxd/w64_owner.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("FAIL: %s\n", m); ++fails; } } while (0)

static uintptr_t model_enter(void *opaque) { (void)opaque; return 0; }
static void model_leave(void *opaque, uintptr_t saved) { (void)opaque; (void)saved; }

int main(void)
{
    uint32_t op, cap = 0, cap2 = 0, bytes;
    shz_msg_hdr_t h;
    uint8_t pkt[24];
    uint32_t pid = 0x11223344u;

    /* sizes: every GUI opcode has an exact request/reply size, neighbours are not GUI */
    for (op = SHZ_OP_W64_GUI_FIRST; op <= SHZ_OP_W64_GUI_LAST; ++op)
        CHECK(shz_w64_gui_request_size(op) >= 24 && shz_w64_gui_reply_size(op) >= 48, "gui opcode sizes");
    CHECK(!shz_w64_gui_request_size(0x208u) && !shz_w64_gui_request_size(0x23fu) && !shz_w64_gui_request_size(0x246u),
          "non-gui opcodes have no gui size");
    CHECK(shz_w64_gui_reply_size(SHZ_OP_W64_GUI_FRAME_READ) == 192u, "chunk reply is one max inline frame");

    /* selector pid: short payload yields 0, never reads beyond length */
    memset(pkt, 0, sizeof pkt);
    memcpy(pkt + 8, &pid, 4);
    CHECK(shz_w64_gui_selector_pid(pkt, 12) == pid, "selector pid at offset 8");
    CHECK(shz_w64_gui_selector_pid(pkt, 11) == 0 && !shz_w64_gui_selector_pid(0, 24), "short/null payload");

    /* FRAME_READ bounds */
    bytes = 4096;
    CHECK(shz_w64_gui_read_bounds(bytes, 0, 128) == 0 && shz_w64_gui_read_bounds(bytes, bytes - 128, 128) == 0, "read ok");
    CHECK(shz_w64_gui_read_bounds(bytes, 0, 0) < 0, "zero length");
    CHECK(shz_w64_gui_read_bounds(bytes, 0, 132) < 0, "over chunk");
    CHECK(shz_w64_gui_read_bounds(bytes, 2, 4) < 0 && shz_w64_gui_read_bounds(bytes, 0, 6) < 0, "unaligned");
    CHECK(shz_w64_gui_read_bounds(bytes, bytes - 4, 8) < 0, "past end");
    CHECK(shz_w64_gui_read_bounds(bytes, bytes + 4, 4) < 0, "offset past end");
    CHECK(shz_w64_gui_read_bounds(bytes, 0xfffffffcu, 128) < 0, "offset wrap");
    CHECK(shz_w64_gui_read_bounds(4098, 0, 4) < 0, "unaligned image length");

    /* frame geometry */
    CHECK(shz_w64_gui_frame_bytes(1024, 768) == SHZ_W64_GUI_MAX_FRAME_BYTES, "max frame");
    CHECK(!shz_w64_gui_frame_bytes(0, 1) && !shz_w64_gui_frame_bytes(1025, 1) && !shz_w64_gui_frame_bytes(1, 769) &&
          !shz_w64_gui_frame_bytes(0xffffffffu, 0xffffffffu), "bad geometry");

    /* CRC-32 known vector */
    CHECK(shz_w64_gui_crc32(0, "123456789", 9) == 0xCBF43926u, "crc32 check value");

    /* owner authority: spoofed / mismatched / non-derived identities are refused */
    CHECK(!shz_w64_gui_subject_authorized(0x80000005u, 0x80000006u, 1), "different derived token");
    CHECK(!shz_w64_gui_subject_authorized(5u, 5u, 1), "equal but not VxD-derived");
    CHECK(!shz_w64_gui_subject_authorized(0x80000000u, 0x80000000u, 1), "derived bit with zero token");
    CHECK(shz_w64_gui_subject_authorized(0x80000005u, 0x80000005u, 1), "same derived token");

    /* real VxD stamper: the application-supplied capability_id is never forwarded */
    memset(&h, 0, sizeof h);
    h.capability_id = 0x80000063u;                      /* app tries to claim another process's derived token */
    ntwv_w64_owner_stamp(&h, 1, 0u);                    /* no derived identity available -> zero, not the forged value */
    CHECK(h.capability_id == 0u, "forged cap dropped when stamping without identity");
    ntwv_w64_owner_stamp(&h, 1, 0x80000007u);
    CHECK(h.capability_id == 0x80000007u, "stamp installs derived cap");
    h.capability_id = 0x80000063u;
    ntwv_w64_owner_stamp(&h, 0, 0u);                    /* trusted in-VxD send clears the DERIVED bit */
    CHECK(!(h.capability_id & SHZ_W64_OWNER_CAP_DERIVED), "trusted send clears derived bit");

    /* real derive: unbound system VM denies; distinct processes get distinct tokens, never the same twice */
    CHECK(ntwv_w64_owner_derive(1, 100, 1, &cap) != 0 && cap == 0, "unbound system VM denies");
    ntwv_w64_owner_bind_system_vm(1);
    ntwv_w64_owner_bind_lock(model_enter, model_leave);
    CHECK(ntwv_w64_owner_derive(1, 100, 1, &cap) != 0, "derive without a recorded open handle denied");
    CHECK(ntwv_w64_owner_handle_open(1, 100) == 0 && ntwv_w64_owner_handle_open(1, 200) == 0, "handles recorded");
    CHECK(ntwv_w64_owner_derive(1, 100, 1, &cap) == 0 && shz_w64_owner_cap_derived(cap), "derive ok");
    CHECK(ntwv_w64_owner_derive(1, 200, 1, &cap2) == 0 && cap2 != cap, "distinct process distinct token");
    CHECK(ntwv_w64_owner_derive(2, 100, 1, &cap2) != 0, "non-system VM refused");
    ntwv_w64_owner_reset_locked();
    if (ntwv_w64_owner_handles(100) == 0) (void)ntwv_w64_owner_handle_open(1, 100);
    CHECK(ntwv_w64_owner_derive(1, 100, 2, &cap2) == 0 && cap2 != cap, "token not reissued after reset");
    CHECK(!shz_w64_gui_subject_authorized(cap, cap2, 1), "stale token vs new token denied");

    puts(fails ? "W98W64 ABI HOST FAIL" : "W98W64 ABI HOST PASS");
    return fails ? 1 : 0;
}
