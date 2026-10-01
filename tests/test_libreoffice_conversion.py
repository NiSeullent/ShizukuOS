# SPDX-License-Identifier: GPL-2.0-only
"""Host format/receipt gates only; these tests never run LibreOffice or QEMU."""
import importlib.util
import io
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("office_conversion", ROOT / "tools/run_libreoffice_conversion.py")
conversion = importlib.util.module_from_spec(spec)
spec.loader.exec_module(conversion)


def sample_odt(content=None, extra=None, compression=zipfile.ZIP_STORED):
    """A parser unit fixture, never substituted for guest output."""
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("mimetype", conversion.MIME, compress_type=compression)
        archive.writestr("content.xml", content or conversion.fixture().replace(b"office:document", b"office:document-content"))
        manifest = (f'<manifest:manifest xmlns:manifest="{conversion.MANIFEST}">'
                    f'<manifest:file-entry manifest:full-path="/" manifest:media-type="{conversion.MIME.decode()}"/>'
                    '<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>'
                    '</manifest:manifest>')
        archive.writestr("META-INF/manifest.xml", manifest)
        if extra:
            archive.writestr(*extra)
    return target.getvalue()


def completed_log(result="exited exit=0 faulted=0", flush="0", before=""):
    return (before + "K64 autorun: starting D:\\libreoffice\\program\\soffice.com\n"
            "[win64 stdout pid 3] convert known.fodt using writer8\n"
            f"K64 autorun: result {result} reaped=3 after 200 ms\n"
            f"K64 disk: flush ahci0: rc {flush}; ahci0: 10 sectors read, 5 written, 1 cache flush(es); D: 2 write(s)\n"
            "K64: done, 0 self-test failure(s)\n")


class ConversionGates(unittest.TestCase):
    def test_fixture_has_exact_unicode_and_escaped_paragraphs(self):
        self.assertEqual(conversion.xml_paragraphs(conversion.fixture()), list(conversion.LINES))
        self.assertIn(b"&amp; &lt; &gt;", conversion.fixture())

    def test_valid_odt_requires_xml_content_and_manifest(self):
        parsed = conversion.validate_odt(sample_odt())
        self.assertEqual(parsed["paragraphs"], list(conversion.LINES))
        self.assertEqual(parsed["members"], 3)

    def test_literal_marker_without_valid_container_fails(self):
        with self.assertRaises(zipfile.BadZipFile):
            conversion.validate_odt("\n".join(conversion.LINES).encode())

    def test_corrupt_or_changed_xml_fails(self):
        for data in (conversion.fixture().replace(b"42.", b"43."), b"<broken>",
                     b'<!DOCTYPE x [<!ENTITY x "hello">]>' + conversion.fixture()):
            with self.subTest(data=data[:30]), self.assertRaises((ValueError, conversion.ET.ParseError)):
                conversion.validate_odt(sample_odt(content=data))

    def test_unsafe_zip_member_and_compressed_mimetype_fail(self):
        for data in (sample_odt(extra=("../secret", b"x")),
                     sample_odt(extra=("/absolute", b"x")),
                     sample_odt(compression=zipfile.ZIP_DEFLATED)):
            with self.assertRaises(ValueError):
                conversion.validate_odt(data)

    def test_flat_xml_disguised_as_odt_content_fails(self):
        with self.assertRaises(ValueError):
            conversion.validate_odt(sample_odt(content=conversion.fixture()))

    def test_crc_corruption_is_not_accepted(self):
        data = sample_odt()
        data = data.replace(b"Win98 Modern", b"Sin98 Modern", 1)
        with self.assertRaises(zipfile.BadZipFile):
            conversion.validate_odt(data)

    def test_text_roundtrip_accepts_bom_and_crlf_but_not_changed_content(self):
        data = ("\ufeff" + "\r\n".join(conversion.LINES) + "\r\n").encode()
        self.assertEqual(conversion.validate_text(data)["paragraphs"], list(conversion.LINES))
        for bad in (data.replace(b"42.", b"43."), data + b"extra", b"\xff"):
            with self.assertRaises((ValueError, UnicodeDecodeError)):
                conversion.validate_text(bad)

    def test_clean_exit_and_real_device_flush_are_both_required(self):
        self.assertEqual(conversion.exited_cleanly(completed_log())["exit_code"], 0)
        for result, flush in (("timeout exit=0 faulted=0", "0"), ("exited exit=1 faulted=0", "0"),
                              ("exited exit=0 faulted=1", "0"), ("exited exit=0 faulted=0", "-1")):
            with self.subTest(result=result, flush=flush), self.assertRaises(ValueError):
                conversion.exited_cleanly(completed_log(result, flush))
        with self.assertRaises(ValueError):
            conversion.exited_cleanly(completed_log().replace("K64 disk:", "not a disk:"))

    def test_late_loader_failure_cannot_be_overridden_by_exit(self):
        data = completed_log().replace("K64 autorun: result", "K64 ldr: mergedlo.dll imports missing.dll\nK64 autorun: result")
        with self.assertRaises(ValueError):
            conversion.exited_cleanly(data)

    def test_boot_marker_is_not_conversion_evidence(self):
        with self.assertRaises(ValueError):
            conversion.exited_cleanly("\n".join(conversion.LINES) + "\nK64: done, 0 self-test failure(s)\n")

    def test_stage_commands_are_fixed_bounded_and_reopen_actual_written_odt(self):
        cases = conversion.stages("all", "LO0123456789")
        self.assertEqual([case["kind"] for case in cases], ["odt", "text", "pdf"])
        self.assertIn("D:\\LO0123456789\\ODT\\known.odt", cases[1]["command"])
        for case in cases:
            self.assertLessEqual(len(case["command"]), 511)
            self.assertNotIn("--version", case["command"])
            self.assertIn("-env:UserInstallation=file:///D:/LO0123456789/PROFILE", case["command"])

    @unittest.skipUnless(shutil.which("pdfinfo") and shutil.which("pdftotext"), "existing Poppler tools unavailable")
    def test_raw_pdf_marker_without_pdf_structure_fails_real_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            pdf = folder / "fake.pdf"
            pdf.write_bytes(b"%PDF-1.7\n" + "\n".join(conversion.LINES).encode())
            with self.assertRaises(conversion.subprocess.SubprocessError):
                conversion.validate_pdf(pdf, folder)
            self.assertFalse((folder / "parsed-pdf.txt").exists())


if __name__ == "__main__":
    unittest.main()
