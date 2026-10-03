/* SPDX-License-Identifier: GPL-2.0-only
 * Host protocol control for abi/shz_w64_gui.h: sizes, selector, READ bounds, frame geometry limits and CRC
 * agreement with the szwin client (the presenter checks the server CRC with szwin_crc32). Host-only evidence. */
#include <stdio.h>
#include <string.h>
#include "../../../abi/shz_w64_gui.h"
#include "../szwin.h"
static int fails, checks;
#define CHECK(c) do { ++checks; if (!(c)) { ++fails; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)
int main(void)
{
    shz_w64_gui_read_t r;
    uint8_t px[4096];
    unsigned i;
    CHECK(shz_w64_gui_request_size(SHZ_OP_W64_GUI_QUERY_VIEW) == 24 && shz_w64_gui_reply_size(SHZ_OP_W64_GUI_QUERY_VIEW) == 64);
    CHECK(shz_w64_gui_request_size(SHZ_OP_W64_GUI_FRAME_ACQUIRE) == 64 && shz_w64_gui_reply_size(SHZ_OP_W64_GUI_FRAME_ACQUIRE) == 80);
    CHECK(shz_w64_gui_request_size(SHZ_OP_W64_GUI_FRAME_READ) == 64 && shz_w64_gui_reply_size(SHZ_OP_W64_GUI_FRAME_READ) == 192);
    CHECK(shz_w64_gui_request_size(SHZ_OP_W64_GUI_INPUT) == 80 && shz_w64_gui_reply_size(SHZ_OP_W64_GUI_INPUT) == 48);
    CHECK(shz_w64_gui_request_size(SHZ_OP_W64_GUI_FRAME_RELEASE) == 48 && shz_w64_gui_request_size(SHZ_OP_W64_GUI_CLOSE_VIEW) == 48);
    CHECK(shz_w64_gui_request_size(0x208) == 0 && shz_w64_gui_request_size(0x246) == 0 && shz_w64_gui_request_size(0x23f) == 0);
    memset(&r, 0, sizeof r); r.p.pid = 0x1234;
    CHECK(shz_w64_gui_selector_pid(&r, sizeof r) == 0x1234 && shz_w64_gui_selector_pid(&r, 11) == 0);
    CHECK(shz_w64_gui_read_bounds(640, 0, 128) == 0 && shz_w64_gui_read_bounds(640, 512, 128) == 0);
    CHECK(shz_w64_gui_read_bounds(640, 516, 128) != 0 && shz_w64_gui_read_bounds(640, 0, 0) != 0);
    CHECK(shz_w64_gui_read_bounds(640, 0, 132) != 0 && shz_w64_gui_read_bounds(640, 2, 4) != 0);
    CHECK(shz_w64_gui_read_bounds(640, 0, 6) != 0 && shz_w64_gui_read_bounds(640, 640, 4) != 0);
    CHECK(shz_w64_gui_read_bounds(0xfffffffcu, 0xfffffff8u, 128) != 0);   /* no offset+length overflow */
    CHECK(shz_w64_gui_frame_bytes(160, 96) == 61440 && shz_w64_gui_frame_bytes(1024, 768) == 3145728);
    CHECK(shz_w64_gui_frame_bytes(1025, 1) == 0 && shz_w64_gui_frame_bytes(1, 769) == 0 && shz_w64_gui_frame_bytes(0, 5) == 0);
    for (i = 0; i < sizeof px; ++i) px[i] = (uint8_t)(i * 131u + 7u);
    CHECK(shz_w64_gui_crc32(0, "123456789", 9) == 0xCBF43926u);
    CHECK(shz_w64_gui_crc32(0, px, sizeof px) == szwin_crc32(0, px, sizeof px));
    CHECK(shz_w64_gui_crc32(shz_w64_gui_crc32(0, px, 1000), px + 1000, sizeof px - 1000) == szwin_crc32(0, px, sizeof px));
    CHECK(SHZ_W64_CAP_GUI == 0x20u && !(SHZ_W64_CAP_GUI & 0x1fu));
    CHECK((int)SHZ_W64_GUI_IN_MOVE == (int)SZWIN_EV_MOVE && (int)SHZ_W64_GUI_IN_CLOSE == (int)SZWIN_EV_CLOSE);
    printf("test_w64_gui_abi: %d checks, %d failures\n", checks, fails);
    return fails != 0;
}
