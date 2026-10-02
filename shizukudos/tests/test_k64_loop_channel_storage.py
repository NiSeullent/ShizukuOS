# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the standalone channel's real storage helpers with a checked heap."""
import pathlib
import subprocess
import tempfile
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "kernel64/subsys64.c"


class LoopChannelStorage(unittest.TestCase):
    def test_failure_alignment_capacity_and_release(self):
        source = SOURCE.read_text()
        helpers = source.split("/* LOOPBACK_STORAGE_BEGIN:", 1)[1].split("*/", 1)[1]
        helpers = helpers.split("/* LOOPBACK_STORAGE_END */", 1)[0]
        harness = r"""
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static void *owned;
static int fail, allocations, releases;
static size_t requested;
static void *kmalloc(size_t n) {
    if (fail) return 0;
    assert(!owned);
    owned = malloc(n + 16);
    assert(owned);
    requested = n;
    ++allocations;
    return (uint8_t *)owned + 16;
}
static void kfree(void *p) {
    if (!p) return;
    assert(p == (uint8_t *)owned + 16);
    free(owned);
    owned = 0;
    ++releases;
}
""" + helpers + r"""
int main(void) {
    fail = 1;
    assert(!loop_channel_allocate());
    assert(!loop_chan && !loop_chan_storage && !allocations);
    fail = 0;
    for (int i = 0; i < 8; ++i) {
        assert(loop_channel_allocate());
        assert(!((uintptr_t)loop_chan & 4095));
        assert((uint8_t *)loop_chan >= (uint8_t *)loop_chan_storage);
        assert(loop_chan + LOOP_CHAN_BYTES <= (uint8_t *)loop_chan_storage + requested);
        memset(loop_chan, 0xa5, LOOP_CHAN_BYTES);
        assert(!loop_channel_allocate()); /* cannot overwrite/leak a live owner */
        loop_channel_release();
        assert(!loop_chan && !loop_chan_storage && !owned);
        loop_channel_release(); /* repeated cleanup is harmless */
        assert(allocations == releases);
    }
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as d:
            c = pathlib.Path(d) / "storage.c"
            exe = pathlib.Path(d) / "storage"
            c.write_text(harness)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            str(c), "-o", str(exe)], check=True)
            subprocess.run([str(exe)], check=True)


if __name__ == "__main__":
    unittest.main()
