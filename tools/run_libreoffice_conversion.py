#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run fixed LibreOffice conversions on a fresh disposable copy of its FAT image.

No publisher file, prepared image, runtime, kernel or installed Windows 98 image
is writable. Actual guest output must survive a normal flush and be read back
from the task-owned disk. ODT/XML, UTF-8 roundtrip and Poppler PDF text parsing
are separate gates; an exit code or console message alone cannot pass.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shizukudos/tests"))
import run_k64_productivity as productivity

OFFICE = "urn:oasis:names:tc:opendocument:xmlns:office:1.0"
TEXT = "urn:oasis:names:tc:opendocument:xmlns:text:1.0"
MANIFEST = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
MIME = b"application/vnd.oasis.opendocument.text"
LINES = ("Win98 Modern Office conversion 6 x 7 = 42.",
         "한국어 문서 저장 확인.", 'XML characters: & < > " remain intact.')
MAX_OUTPUT = 16 * 1024 * 1024
PRIMARY_DOCS = (
    "https://help.libreoffice.org/latest/en-US/text/shared/guide/start_parameters.html",
    "https://help.libreoffice.org/latest/en-US/text/shared/guide/convertfilters.html",
)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fixture() -> bytes:
    from xml.sax.saxutils import escape
    paragraphs = "".join("<text:p>" + escape(line) + "</text:p>" for line in LINES)
    return (f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<office:document xmlns:office="{OFFICE}" xmlns:text="{TEXT}" '
            'office:version="1.3" office:mimetype="application/vnd.oasis.opendocument.text">'
            f'<office:body><office:text>{paragraphs}</office:text></office:body>'
            '</office:document>').encode("utf-8")


def xml_paragraphs(data: bytes, required_root: str | None = None) -> list[str]:
    if len(data) > MAX_OUTPUT or re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", data, re.I):
        raise ValueError("oversized XML or unsupported DTD/entity declaration")
    root = ET.fromstring(data)
    if root.tag not in (f"{{{OFFICE}}}document", f"{{{OFFICE}}}document-content"):
        raise ValueError("not an OpenDocument XML root")
    if required_root and root.tag != f"{{{OFFICE}}}{required_root}":
        raise ValueError("wrong XML root for the requested OpenDocument container")
    body = root.find(f"{{{OFFICE}}}body/{{{OFFICE}}}text")
    if body is None:
        raise ValueError("Writer text body absent")
    result = []
    for paragraph in body.iter(f"{{{TEXT}}}p"):
        # Preserve the XML's actual text, including spans. This fixture does not
        # contain repeated-space, tab or line-break control elements.
        result.append("".join(paragraph.itertext()))
    if result != list(LINES):
        raise ValueError("actual paragraph content differs from the known input")
    return result


def validate_odt(data: bytes) -> dict:
    if len(data) > MAX_OUTPUT:
        raise ValueError("ODT exceeds bounded output size")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        names = [member.filename for member in members]
        if not members or len(members) > 512 or len(set(names)) != len(names):
            raise ValueError("empty, excessive or duplicate ZIP members")
        if members[0].filename != "mimetype" or members[0].compress_type != zipfile.ZIP_STORED:
            raise ValueError("ODT mimetype must be first and uncompressed")
        total = 0
        for member in members:
            path = PurePosixPath(member.filename)
            if path.is_absolute() or ".." in path.parts or "\\" in member.filename or member.flag_bits & 1:
                raise ValueError("unsafe or encrypted ODT member")
            if member.file_size > MAX_OUTPUT:
                raise ValueError("oversized decompressed ODT member")
            total += member.file_size
            if total > 2 * MAX_OUTPUT:
                raise ValueError("ODT decompression exceeds bound")
        if archive.read("mimetype") != MIME:
            raise ValueError("wrong ODT mimetype")
        manifest = archive.read("META-INF/manifest.xml")
        if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", manifest, re.I):
            raise ValueError("unsupported manifest DTD/entity")
        manifest_root = ET.fromstring(manifest)
        if manifest_root.tag != f"{{{MANIFEST}}}manifest":
            raise ValueError("wrong manifest root")
        entries = manifest_root.findall(f"{{{MANIFEST}}}file-entry")
        if not any(entry.get(f"{{{MANIFEST}}}full-path") == "/" and
                   entry.get(f"{{{MANIFEST}}}media-type") == MIME.decode() for entry in entries):
            raise ValueError("ODT manifest does not declare a text document")
        if not any(entry.get(f"{{{MANIFEST}}}full-path") == "content.xml" and
                   entry.get(f"{{{MANIFEST}}}media-type") == "text/xml" for entry in entries):
            raise ValueError("ODT manifest does not declare content.xml")
        paragraphs = xml_paragraphs(archive.read("content.xml"), "document-content")
        # testzip reads all bounded members and verifies their CRCs.
        if archive.testzip() is not None:
            raise ValueError("ODT ZIP CRC check failed")
    return {"parser": "Python ZIP CRC and ElementTree OpenDocument XML",
            "members": len(members), "paragraphs": paragraphs}


def validate_text(data: bytes) -> dict:
    if len(data) > MAX_OUTPUT:
        raise ValueError("text output exceeds bound")
    text = data.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
    if text.rstrip("\n").split("\n") != list(LINES):
        raise ValueError("Office reopened ODT text differs from the original paragraphs")
    return {"parser": "strict UTF-8 roundtrip", "paragraphs": list(LINES)}


def validate_pdf(path: Path, work: Path) -> dict:
    if path.stat().st_size > MAX_OUTPUT or not path.read_bytes().startswith(b"%PDF-"):
        raise ValueError("not a bounded PDF document")
    info = subprocess.run(["pdfinfo", str(path)], capture_output=True, text=True, timeout=20, check=True)
    match = re.search(r"^Pages:\s*(\d+)\s*$", info.stdout, re.M)
    if not match or not 1 <= int(match[1]) <= 8:
        raise ValueError("PDF page count is absent or outside fixture bounds")
    extracted = work / "parsed-pdf.txt"
    subprocess.run(["pdftotext", "-enc", "UTF-8", "-nopgbrk", str(path), str(extracted)],
                   capture_output=True, timeout=20, check=True)
    if extracted.stat().st_size > MAX_OUTPUT:
        raise ValueError("parsed PDF text exceeds bound")
    text = extracted.read_text(encoding="utf-8")
    # PDF layout can wrap a paragraph. Check the parsed Unicode text in order;
    # bytes in raw streams or console output are never accepted as PDF content.
    normalized = " ".join(text.split())
    expected = " ".join(" ".join(LINES).split())
    if normalized != expected:
        raise ValueError("actual Poppler PDF text differs from the known document")
    return {"parser": "Poppler pdfinfo and pdftotext", "pages": int(match[1]),
            "text": text, "parsed_text_sha256": digest(extracted), "pdfinfo": info.stdout}


def stages(scenario: str, case: str) -> list[dict]:
    prefix = ("program\\soffice.com --headless --nologo --nodefault --norestore "
              f"-env:UserInstallation=file:///D:/{case}/PROFILE")
    common = {"cwd": "D:\\libreoffice", "image": "D:\\libreoffice\\program\\soffice.com"}
    result = []
    if scenario in ("writer-roundtrip", "all"):
        result += [dict(common, name="writer-odt", output=f"{case}/ODT/known.odt", kind="odt",
                        command=f'{prefix} --convert-to odt:writer8 --outdir D:\\{case}\\ODT D:\\{case}\\known.fodt'),
                   dict(common, name="writer-reopen-text", output=f"{case}/TEXT/known.txt", kind="text",
                        command=f'{prefix} --convert-to "txt:Text (encoded):UTF8" --outdir D:\\{case}\\TEXT D:\\{case}\\ODT\\known.odt')]
    if scenario in ("writer-pdf", "all"):
        result.append(dict(common, name="writer-pdf", output=f"{case}/PDF/known.pdf", kind="pdf",
                           command=f'{prefix} --convert-to pdf:writer_pdf_Export --outdir D:\\{case}\\PDF D:\\{case}\\known.fodt'))
    for stage in result:
        if len(stage["command"]) > 511:
            raise ValueError("fixed command exceeds native autorun capacity")
    return result


def exited_cleanly(serial: str) -> dict:
    details = productivity.classify_product(serial, None, productivity.runner.classify)
    if details["ended_by"] != "exited" or details["exit_code"] != 0 or details["faulted"] or details["exceptions"]:
        raise ValueError("LibreOffice did not exit normally without a fault: " + details["furthest"])
    # A clean process exit must also commit the real writable FAT volume.
    flushes = re.findall(r"^K64 disk: flush [^\n]*?: rc (-?\d+);[^\n]*; D:", serial, re.M)
    if not flushes or flushes[-1] != "0":
        raise ValueError("normal shutdown did not report a successful D: volume flush")
    if not re.search(r"K64.*done, 0 self-test failure\(s\)", serial):
        raise ValueError("kernel completion/self-test result absent or failed")
    return details


def run_guest(stage: dict, args, image: Path, folder: Path) -> dict:
    folder.mkdir()
    control = (f"image={stage['image']}\r\ncmdline={stage['command']}\r\ncwd={stage['cwd']}\r\n"
               f"timeout={args.guest_timeout}\r\n").encode("ascii")
    productivity.runner.put_file(image, control, "K64RUN.TXT", folder)
    serial_path = folder / "serial.log"
    kernel = args.kernel / "KERNEL64S.BIN"
    boot = args.kernel / "boot.elf"
    runtime = args.runtime / "WIN64.IMG"
    command = [args.qemu, "-machine", "pc", "-accel", args.accel, "-cpu", "max", "-m", "3072",
               "-nodefaults", "-display", "none", "-vga", "std", "-kernel", str(boot),
               "-initrd", f"{kernel},{runtime}", "-append",
               "shz.noapps shz.autorun=D:\\K64RUN.TXT shz.k32trace shz.exctrace shz.systrace",
               "-serial", f"file:{serial_path}", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
               "-no-reboot", "-device", "ahci,id=ahci0", "-drive",
               f"if=none,id=d0,file={image},format=raw,cache=writeback", "-device", "ide-hd,drive=d0,bus=ahci0.0"]
    start = time.monotonic()
    with (folder / "qemu.log").open("wb") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            try:
                process.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                raise ValueError("bounded guest run timed out; disk output is not accepted")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    details = productivity.classify_product(serial, None, productivity.runner.classify)
    trial = dict(stage, qemu_command=command, qemu_returncode=process.returncode,
                 elapsed_seconds=round(time.monotonic() - start, 2), classification=details)
    (folder / "trial.json").write_text(json.dumps(trial, indent=2) + "\n")
    if process.returncode != 1:  # isa-debug-exit: successful shz_exit(0) -> (0 << 1) | 1
        raise ValueError(f"QEMU did not report normal kernel success: {process.returncode}")
    exited_cleanly(serial)
    fsck = subprocess.run(["fsck.fat", "-n", str(image)], capture_output=True, text=True, timeout=30)
    (folder / "fsck.txt").write_text(fsck.stdout + fsck.stderr)
    if fsck.returncode:
        raise ValueError("guest-written FAT image failed read-only filesystem checking")
    output = folder / Path(stage["output"]).name
    listing = subprocess.run(["mdir", "-i", str(image), "::" + stage["output"]],
                             env=productivity.runner.mtools_env(), capture_output=True, text=True, timeout=20, check=True)
    suffix = output.suffix[1:]
    sizes = re.findall(r"^known\s+" + suffix + r"\s+(\d+)\s+", listing.stdout, re.M | re.I)
    if len(sizes) != 1 or not 0 < int(sizes[0]) <= MAX_OUTPUT:
        raise ValueError("guest output size is absent or outside readback bounds")
    (folder / "output-directory.txt").write_text(listing.stdout)
    subprocess.run(["mcopy", "-n", "-i", str(image), "::" + stage["output"], str(output)],
                   env=productivity.runner.mtools_env(), capture_output=True, timeout=30, check=True)
    if not output.is_file() or output.stat().st_size != int(sizes[0]):
        raise ValueError("actual guest output is absent, empty or oversized")
    if stage["kind"] == "odt":
        parsed = validate_odt(output.read_bytes())
    elif stage["kind"] == "text":
        parsed = validate_text(output.read_bytes())
    else:
        parsed = validate_pdf(output, folder)
    trial.update(status="PASS", output_host=str(output), output_sha256=digest(output), parsed=parsed)
    (folder / "trial.json").write_text(json.dumps(trial, indent=2) + "\n")
    return trial


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--publisher-image", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--scenario", choices=("writer-roundtrip", "writer-pdf", "all"), default="all")
    parser.add_argument("--qemu", default=productivity.runner.qemu.DEFAULT_QEMU)
    parser.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    parser.add_argument("--timeout", type=int, default=150)
    parser.add_argument("--guest-timeout", type=int, default=120)
    args = parser.parse_args(argv)
    if not 5 <= args.guest_timeout < args.timeout <= 900:
        parser.error("require 5 <= guest-timeout < timeout <= 900")
    for name in ("tree", "publisher_image", "kernel", "runtime"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    out = args.out.resolve()
    protected = [args.publisher_image, args.kernel / "KERNEL64S.BIN", args.kernel / "boot.elf", args.runtime / "WIN64.IMG"]
    if out.exists() or any(out == path or out.is_relative_to(path) for path in protected) or any(
            out.is_relative_to(path) for path in (args.tree, args.kernel, args.runtime)):
        parser.error("output must be new and outside all immutable inputs and the publisher tree")
    for tool in ("cp", "mcopy", "mmd", "mdir", "fsck.fat", args.qemu, *(["pdfinfo", "pdftotext"] if args.scenario != "writer-roundtrip" else [])):
        if not shutil.which(tool):
            parser.error("required existing tool missing: " + tool)
    exe, host_exe = productivity.find_product_exe(args.tree, ("program/soffice.com",))
    if exe != "program\\soffice.com" or productivity.pe_machine(host_exe) != 0x8664:
        parser.error("actual publisher AMD64 program/soffice.com is required")
    tree_hash = productivity.tree_fingerprint(args.tree)
    stamp = Path(str(args.publisher_image) + ".json")
    if json.loads(stamp.read_text()).get("productivity_content_sha256") != tree_hash:
        parser.error("publisher image content receipt does not match the supplied immutable tree")
    inputs = {str(path): digest(path) for path in protected}
    inputs[str(host_exe)] = digest(host_exe)
    out.mkdir(parents=True)
    image = out / "WORK.IMG"
    case = "LO" + uuid.uuid4().hex[:10].upper()
    record = {"status": "FAIL", "scenario": args.scenario, "inputs": inputs, "package_tree_sha256": tree_hash,
              "case": case, "guest_os": "ShizukuDOS Kernel64 standalone", "network_attached": False,
              "windows98_execution_verified": False, "app_functionality_verified": False,
              "document_roundtrip_verified": False, "pdf_text_verified": False,
              "primary_contracts": list(PRIMARY_DOCS), "trials": [],
              "runner_source_sha256": digest(Path(__file__)),
              "writable_disk": str(image), "disk_mode": "task-owned fresh copy, raw, snapshot off"}
    try:
        subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--", str(args.publisher_image), str(image)], check=True)
        if digest(image) != inputs[str(args.publisher_image)]:
            raise ValueError("disposable disk copy differs from the protected publisher image")
        env = productivity.runner.mtools_env()
        # No skip/overwrite option: a pre-existing case directory is an error.
        subprocess.run(["mmd", "-i", str(image), "::" + case], env=env, capture_output=True, check=True)
        for directory in ("ODT", "TEXT", "PDF"):
            subprocess.run(["mmd", "-i", str(image), f"::{case}/{directory}"], env=env, capture_output=True, check=True)
        productivity.runner.put_file(image, fixture(), f"{case}/known.fodt", out)
        record["fixture_sha256"] = hashlib.sha256(fixture()).hexdigest()
        for stage in stages(args.scenario, case):
            print("Actual guest conversion:", stage["name"], flush=True)
            record["trials"].append(run_guest(stage, args, image, out / stage["name"]))
        record["document_roundtrip_verified"] = args.scenario in ("writer-roundtrip", "all")
        record["pdf_text_verified"] = args.scenario in ("writer-pdf", "all")
        record["status"] = "PASS"
    except (OSError, ValueError, ET.ParseError, zipfile.BadZipFile, KeyError, subprocess.SubprocessError, RuntimeError) as error:
        record["failure"] = str(error)
        print("Conversion failed:", error, flush=True)
    finally:
        try:
            unchanged = all(Path(path).exists() and digest(Path(path)) == value for path, value in inputs.items())
            unchanged = unchanged and productivity.tree_fingerprint(args.tree) == tree_hash
        except (OSError, ValueError) as error:
            unchanged = False
            record["input_verification_error"] = str(error)
        record["inputs_unchanged"] = unchanged
        if not unchanged:
            record["status"] = "FAIL"
            record["failure"] = "immutable compilation/application inputs changed during run"
            record["document_roundtrip_verified"] = record["pdf_text_verified"] = False
        if image.exists():
            record["disposable_image_sha256"] = digest(image)
        (out / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    print(record["status"], out / "result.json", flush=True)
    return 0 if record["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
