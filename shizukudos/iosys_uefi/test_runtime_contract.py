"""Native-run failure propagation and the actual firmware capsule parser.

The C regression compiles the parser extracted from the reviewed source patch,
without firmware emulation or executable Windows bytes.
"""
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from boot import aggregate_exit_code


class NativeAcceptance(unittest.TestCase):
    def test_passing_entry_preserves_failed_file_save_exit(self):
        self.assertEqual(aggregate_exit_code(True, 1, "FAIL"), 1)
        self.assertEqual(aggregate_exit_code(True, 0, "FAIL"), 1)

    def test_unverified_or_failed_entry_cannot_become_overall_success(self):
        self.assertEqual(aggregate_exit_code(False, 0, "NEEDS-VISUAL-REVIEW"), 1)
        self.assertEqual(aggregate_exit_code(True, 0, None), 1)
        self.assertEqual(aggregate_exit_code(True, 2, "NEEDS-VISUAL-REVIEW"), 2)
        self.assertEqual(aggregate_exit_code(True, 0, "NEEDS-VISUAL-REVIEW"), 0)


class FirmwareCapsuleBounds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc")
        if not compiler:
            raise unittest.SkipTest("host C compiler is required for actual firmware parser regression")
        cls.temporary = tempfile.TemporaryDirectory(prefix="iosys-capsule-c-")
        cls.folder = Path(cls.temporary.name)
        patch = (Path(__file__).parent / "patches/0001-direct-iosys.patch").read_text()
        addition = patch.split("+++ b/src/iosys_uefi.c\n", 1)[1].split("diff --git", 1)[0]
        source = "\n".join(line[1:] for line in addition.splitlines()
                           if line.startswith("+") and not line.startswith("+++"))
        constants = source[source.index("#define CAPSULE_BYTES"):source.index("static unsigned char capsule")]
        parser = source[source.index("static uint16_t le16"):source.index("static void read_capsule")]
        program = ("#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n"
                   "#include <stdio.h>\n#include <stdlib.h>\n" + constants +
                   "\nstatic unsigned char capsule[CAPSULE_BYTES];\n"
                   "static _Noreturn void panic(const char *reason) { fputs(reason, stderr); exit(42); }\n" +
                   parser + "\nint main(int argc,char **argv) { if(argc!=2)return 3; "
                   "FILE *f=fopen(argv[1],\"rb\"); if(!f)return 4; "
                   "if(fread(capsule,1,sizeof capsule,f)!=sizeof capsule)return 5; "
                   "if(fgetc(f)!=EOF)return 6; fclose(f); validate_capsule(); return 0; }\n")
        c_file = cls.folder / "actual-parser.c"
        c_file.write_text(program)
        cls.executable = cls.folder / "actual-parser"
        compiled = subprocess.run([compiler, "-std=c11", "-O0", str(c_file), "-o", str(cls.executable)],
                                  capture_output=True, timeout=30)
        if compiled.returncode:
            cls.temporary.cleanup()
            raise AssertionError(compiled.stderr.decode(errors="replace"))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def capsule(self, start):
        capsule = bytearray(2688)
        capsule[:8] = b"SHZIO98\0"
        struct.pack_into("<HH", capsule, 8, 1, 128)
        for offset, value in {12:2688, 20:3, 24:start, 28:start+4128,
                              32:2, 36:224150, 40:start+4128, 44:2048, 48:512}.items():
            struct.pack_into("<I", capsule, offset, value)
        capsule[120:123] = bytes((0x80, 0x0e, 0x0c))
        vbr = 128
        capsule[vbr] = 0xeb
        capsule[vbr+2] = 0x90
        struct.pack_into("<H", capsule, vbr+11, 512)
        capsule[vbr+13] = 4
        struct.pack_into("<H", capsule, vbr+14, 32)
        capsule[vbr+16] = 2
        for offset, value in ((28,start), (32,300000), (36,2048), (44,2)):
            struct.pack_into("<I", capsule, vbr+offset, value)
        capsule[vbr+64] = 0x80
        capsule[vbr+510:vbr+512] = b"\x55\xaa"
        capsule[640:642] = b"MZ"
        capsule[640+0x200:640+0x208] = b"\x42\x4a\x8b\x46\xfc\x8b\x56\xfe"
        capsule[-2:] = b"MS"
        struct.pack_into("<I", capsule, 16, -sum(struct.unpack("<672I", capsule)) & 0xffffffff)
        return bytes(capsule)

    def validate(self, start):
        fixture = self.folder / (str(start) + ".bin")
        fixture.write_bytes(self.capsule(start))
        return subprocess.run([str(self.executable), str(fixture)], capture_output=True, timeout=5)

    def test_valid_fat32_geometry_and_exact_lba_limit_are_accepted(self):
        self.assertEqual(self.validate(63).returncode, 0)
        self.assertEqual(self.validate(0x100000000-300000).returncode, 0)

    def test_volume_end_overflow_is_rejected_even_when_io_prefix_fits(self):
        for start in (0xffff0000, 0x100000000-300000+1):
            with self.subTest(start=start):
                result = self.validate(start)
                self.assertEqual(result.returncode, 42)
                self.assertIn(b"geometry/entry ABI mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
