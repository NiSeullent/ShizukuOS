# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the evidence gate against spoofed/stale/partial real guest records."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("private_theme_trial_test", ROOT / "tools/win64_theme_probe_trial.py")
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)
NONCE = "1234567890abcdef1234567890abcdef"


def serial_fixture():
    names = ["frozen_provider_defaults_modern", "gdi_and_dib_memory_agree", "actual_dib_renderer", "all_interior_pixels",
             "all_border_pixels", "clip_state_restored_after_draw", "amd64_upper_handle_bits_rejected", "stale_cookie_rejected",
             "independent_gradient_endpoints", "delete_dib", "delete_memory_dc", "destroy_visible_window", "unload_theme_provider"]
    names += ["extra_" + str(i) for i in range(80 - len(names))]
    lines = ["K64 autorun: starting D:\\themeprobe\\THEMEP64.EXE (cwd D:\\themeprobe, timeout 30 s)",
             "K64 autorun: started pid 60"]
    prefix = "[win64 THEMEP64.EXE pid 60] "
    lines += [prefix + "TP64 BEGIN " + NONCE]
    lines += [prefix + "TP64 PASS " + name for name in names]
    lines += [prefix + "TP64 COUNTS checks=80 failures=0 paints=1", prefix + "TP64 FINAL PASS " + NONCE,
              "K64 autorun: result exited exit=0 faulted=0 reaped=0 after 5000 ms"]
    return "\n".join(lines) + "\n"


class Acceptance(unittest.TestCase):
    def test_complete_normal_exit(self):
        result = trial.parse_acceptance(serial_fixture(), NONCE)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["pid"], 60)
        self.assertTrue(result["kernel_child_reaped"])

    def rejected(self, original, replacement):
        with self.assertRaises(ValueError):
            trial.parse_acceptance(serial_fixture().replace(original, replacement), NONCE)

    def test_wrong_nonce(self):
        self.rejected("TP64 BEGIN " + NONCE, "TP64 BEGIN " + "0" * 32)

    def test_duplicated_begin(self):
        line = "[win64 THEMEP64.EXE pid 60] TP64 BEGIN " + NONCE
        self.rejected(line, line + "\n" + line)

    def test_wrong_pid(self):
        self.rejected("THEMEP64.EXE pid 60", "THEMEP64.EXE pid 61")

    def test_wrong_executable(self):
        self.rejected("[win64 THEMEP64.EXE", "[win64 OTHER.EXE")

    def test_unprefixed_markers(self):
        self.rejected("[win64 THEMEP64.EXE pid 60] ", "")

    def test_no_kernel_exit(self):
        self.rejected("K64 autorun: result exited exit=0 faulted=0 reaped=0 after 5000 ms", "SHZEXIT=0")

    def test_timeout(self):
        self.rejected("result exited", "result timeout")

    def test_nonzero_exit(self):
        self.rejected("exit=0", "exit=1")

    def test_faulted(self):
        self.rejected("faulted=0", "faulted=1")

    def test_not_reaped(self):
        self.rejected("reaped=0", "reaped=-1")

    def test_early_live_thread_branch(self):
        self.rejected("reaped=0 after", "reaped=0 (1 thread(s) still alive) after")

    def test_duplicate_exit(self):
        line = "K64 autorun: result exited exit=0 faulted=0 reaped=0 after 5000 ms"
        self.rejected(line, line + "\n" + line)

    def test_failure_assertion(self):
        self.rejected("TP64 PASS delete_dib", "TP64 FAIL delete_dib")

    def test_wrong_counts(self):
        self.rejected("checks=80", "checks=81")

    def test_missing_paint(self):
        self.rejected("paints=1", "paints=0")

    def test_incomplete_cleanup(self):
        self.rejected("TP64 PASS unload_theme_provider", "TP64 PASS skipped_cleanup")

    def test_loader_failure(self):
        self.rejected("K64 autorun: result", "K64 ldr: theme dependency failed\nK64 autorun: result")

    def test_wrong_autorun(self):
        self.rejected("D:\\themeprobe\\THEMEP64.EXE", "D:\\other\\THEMEP64.EXE")

    def test_extra_autorun(self):
        line = "K64 autorun: starting D:\\themeprobe\\THEMEP64.EXE"
        self.rejected(line, line + "\n" + line)

    def test_nonce_bound(self):
        for value in ("", "A" * 32, "g" * 32, "0" * 31, "0" * 33):
            self.assertFalse(trial.nonce_ok(value))


class Framebuffer(unittest.TestCase):
    def image(self, directory):
        from PIL import Image
        image = Image.new("RGB", (1024,768), (255,255,255))
        for left, fill, border in ((124,(192,192,192),(128,128,128)), (314,(240,240,240),(0,120,215))):
            for y in range(153,213):
                for x in range(left,left+140):
                    image.putpixel((x,y), border if x in (left,left+139) or y in (153,212) else fill)
        path=Path(directory)/"capture.ppm"
        image.save(path)
        return path

    def test_every_visible_pixel(self):
        with tempfile.TemporaryDirectory() as directory:
            result=trial.screenshot_pixels(self.image(directory))
            self.assertEqual(sum(row["checked_pixels"] for row in result["rectangles"]),16800)
            self.assertTrue(Path(result["preview"]).exists())

    def test_one_corrupt_visible_pixel(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as directory:
            path=self.image(directory)
            with Image.open(path) as image:
                image.putpixel((200,180),(1,2,3));image.save(path)
            with self.assertRaises(ValueError):
                trial.screenshot_pixels(path)

    def test_wrong_screen_mode(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"capture.ppm"
            Image.new("RGB",(640,480)).save(path)
            with self.assertRaises(ValueError):
                trial.screenshot_pixels(path)


if __name__ == "__main__":
    unittest.main()
