#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise offline pinned-source guards using temporary local git fixtures."""
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().with_name("build.py")
MODULE_SPEC = importlib.util.spec_from_file_location("ios_gop_profile_build", SCRIPT)
build = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(build)


class CachedSourceGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name) / "csmwrap"
        self.source.mkdir()
        self.command(self.source, "init", "-q")
        self.command(self.source, "config", "user.name", "Local Test")
        self.command(self.source, "config", "user.email", "test@example.invalid")
        (self.source / "source.c").write_text("int version = 1;\n")
        self.command(self.source, "add", "source.c")
        self.command(self.source, "commit", "-qm", "Initial fixture")
        self.sub = self.source / "seabios"
        self.sub.mkdir()
        self.command(self.sub, "init", "-q")
        self.command(self.sub, "config", "user.name", "Local Test")
        self.command(self.sub, "config", "user.email", "test@example.invalid")
        (self.sub / "source.c").write_text("int bios_version = 1;\n")
        self.command(self.sub, "add", "source.c")
        self.command(self.sub, "commit", "-qm", "Initial submodule fixture")
        sub_commit = self.command(self.sub, "rev-parse", "HEAD")
        self.command(self.source, "update-index", "--add", "--cacheinfo",
                     f"160000,{sub_commit},seabios")
        self.command(self.source, "commit", "-qm", "Pinned gitlink")
        self.pin = {"commit": self.command(self.source, "rev-parse", "HEAD"),
                    "submodules": {"seabios": {"commit": sub_commit}}}

    @staticmethod
    def command(path, *args):
        return subprocess.run(["git", "-C", str(path), *args], check=True,
                              capture_output=True, text=True, timeout=10).stdout.strip()

    def test_accepts_clean_exact_commits_without_fetching(self):
        build.check_cached_sources(self.source, self.pin)

    def test_rejects_dirty_superproject_source(self):
        (self.source / "source.c").write_text("int version = 2;\n")
        with self.assertRaisesRegex(RuntimeError, "Cached source check failed"):
            build.check_cached_sources(self.source, self.pin)

    def test_rejects_dirty_submodule_source(self):
        (self.sub / "source.c").write_text("int bios_version = 2;\n")
        with self.assertRaisesRegex(RuntimeError, "Cached source check failed"):
            build.check_cached_sources(self.source, self.pin)

    def test_rejects_drifted_submodule_checkout(self):
        (self.sub / "source.c").write_text("int bios_version = 2;\n")
        self.command(self.sub, "add", "source.c")
        self.command(self.sub, "commit", "-qm", "Unpinned commit")
        with self.assertRaisesRegex(RuntimeError, "submodule commit drift"):
            build.check_cached_sources(self.source, self.pin)

    def test_rejects_manifest_gitlink_mismatch(self):
        pin = {"commit": self.pin["commit"],
               "submodules": {"seabios": {"commit": "0" * 40}}}
        with self.assertRaisesRegex(RuntimeError, "gitlink drift"):
            build.check_cached_sources(self.source, pin)

    def test_archives_pinned_objects_without_later_or_generated_source(self):
        # Simulate edits after the initial guard and generated build sources.
        # The archive must still read the chosen commit, never the checkout.
        (self.source / "source.c").write_text("int version = 99;\n")
        self.command(self.source, "add", "source.c")
        self.command(self.source, "commit", "-qm", "Concurrent later commit")
        (self.sub / "source.c").write_text("int bios_version = 99;\n")
        for source in (self.source, self.sub):
            (source / "untracked.c").write_text("int must_not_compile = 1;\n")
            (source / ".git" / "info" / "exclude").write_text("generated.c\n")
            (source / "generated.c").write_text("int also_must_not_compile = 1;\n")
        destination = Path(self.tmp.name) / "immutable-build"
        build.archive_commit(self.source, self.pin["commit"], destination)
        build.archive_commit(self.sub, self.pin["submodules"]["seabios"]["commit"],
                             destination / "seabios")
        self.assertEqual((destination / "source.c").read_text(), "int version = 1;\n")
        self.assertEqual((destination / "seabios" / "source.c").read_text(),
                         "int bios_version = 1;\n")
        self.assertEqual({str(path.relative_to(destination)) for path in destination.rglob("*")
                          if path.is_file()}, {"source.c", "seabios/source.c"})


if __name__ == "__main__":
    unittest.main()
