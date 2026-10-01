# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).resolve().parent / 'reproduce.py'
SPEC = importlib.util.spec_from_file_location('lifetime_reproducer', PATH)
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


class ReproducerBinding(unittest.TestCase):
    def test_reading_own_tool_does_not_invalidate_its_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            tool=Path(directory)/'compiler';tool.write_bytes(b'fixture executable bytes\n');tool.chmod(0o700)
            st=tool.stat();os.utime(tool,ns=(st.st_mtime_ns-(172800*10**9),st.st_mtime_ns))
            binding=R.tool_binding(tool)
            R.verify_tool(binding)

    def test_alias_retarget_and_target_changes_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);one=root/'one';two=root/'two';alias=root/'alias'
            for p in (one,two):p.write_bytes(b'fixture compiler\n');p.chmod(0o700)
            alias.symlink_to(one);binding=R.tool_binding(alias)
            alias.unlink();alias.symlink_to(two)
            with self.assertRaises(ValueError):R.verify_tool(binding)
            binding=R.tool_binding(alias);two.write_bytes(b'changed compiler bytes\n')
            with self.assertRaises(ValueError):R.verify_tool(binding)


if __name__=='__main__':unittest.main()
