"""Create fresh Office inputs and inspect genuine saved ODF artifacts.

Artifact consistency cannot establish the operating system or process that
created a file. Native execution remains unverified in every result here; the
parent-owned Win98 process/display/exit evidence must be supplied separately.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
import zipfile

from office_steam_preflight import snapshot


NS = {
    "office": "urn:oasis:names:tc:opendocument:xmlns:office:1.0",
    "text": "urn:oasis:names:tc:opendocument:xmlns:text:1.0",
    "table": "urn:oasis:names:tc:opendocument:xmlns:table:1.0",
    "meta": "urn:oasis:names:tc:opendocument:xmlns:meta:1.0",
}
UNICODE = "Unicode=한글 Ω é 😀"
NONCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{15,95}\Z")
MIME = "application/vnd.oasis.opendocument."
VERSION = "26.8.0.3"


def nonce_value(value: str) -> str:
    if not NONCE.fullmatch(value):
        raise ValueError("nonce must contain 16..96 safe ASCII letters, digits, underscores or hyphens")
    return value


def fixture_data(nonce: str) -> tuple[bytes, bytes]:
    nonce_value(nonce)
    declarations = " ".join(f'xmlns:{prefix}="{uri}"' for prefix, uri in NS.items())
    declarations += ' xmlns:of="urn:oasis:names:tc:opendocument:xmlns:of:1.2"'
    wrapper = ('<?xml version="1.0" encoding="UTF-8"?>\n'
               f'<office:document {declarations} office:version="1.3" office:mimetype="{MIME}{{kind}}">'
               '<office:meta><meta:generator>Win98-Modern fresh-input fixture; not application evidence</meta:generator></office:meta>'
               '<office:body>{body}</office:body></office:document>\n')
    writer = ('<office:text><text:p>' + escape("nonce=" + nonce)
              + '</text:p><text:p>' + escape(UNICODE) + '</text:p>'
              '<text:p>Change this line to EDIT-SAVED before saving and reopening in Writer.</text:p></office:text>')
    calc = ('<office:spreadsheet><table:table table:name="FreshCalc">'
            '<table:table-row><table:table-cell office:value-type="float" office:value="19"><text:p>19</text:p></table:table-cell></table:table-row>'
            '<table:table-row><table:table-cell office:value-type="float" office:value="23"><text:p>23</text:p></table:table-cell></table:table-row>'
            '<table:table-row><table:table-cell table:formula="of:=SUM([.A1:.A2])" office:value-type="float" office:value="0"><text:p>0</text:p></table:table-cell></table:table-row>'
            '<table:table-row><table:table-cell office:value-type="string"><text:p>' + escape("nonce=" + nonce)
            + '</text:p></table:table-cell></table:table-row>'
            '<table:table-row><table:table-cell office:value-type="string"><text:p>' + escape(UNICODE)
            + '</text:p></table:table-cell></table:table-row>'
            '</table:table></office:spreadsheet>')
    return (wrapper.format(kind="text", body=writer).encode(),
            wrapper.format(kind="spreadsheet", body=calc).encode())


def create_inputs(out: Path, nonce: str) -> dict:
    writer, calc = fixture_data(nonce)
    # An existing directory is never reused: old outputs cannot be mistaken for
    # this challenge, and no source or other owner's application data is changed.
    if out.is_symlink() or out.exists():
        raise ValueError("fixture output must be a new directory")
    if out.parent.is_symlink() or not out.parent.is_dir():
        raise ValueError("fixture parent must be an existing real directory")
    out.mkdir()
    records = []
    for name, data in (("WRITER.FODT", writer), ("CALC.FODS", calc)):
        path = out / name
        with path.open("xb") as output:
            output.write(data)
        records.append({"file": name, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return {"schema": "win98modern.office-fresh-inputs.v1", "nonce": nonce,
            "files": records, "native_application_executed": False,
            "runtime_compatibility": "unverified"}


def xml(data: bytes) -> ET.Element:
    text = data.decode("utf-8-sig")
    if len(data) > 1024 * 1024 or "\x00" in text or "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("ODF XML is outside the bounded entity-free fixture profile")
    return ET.fromstring(data)


def saved_document(path: Path, kind: str) -> tuple[dict, ET.Element]:
    data = snapshot(path, 16 * 1024 * 1024)
    import io
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        names = [member.filename for member in members]
        if not members or len(members) > 256 or len(set(names)) != len(names):
            raise ValueError("empty, oversized or duplicate-member ODF package")
        if sum(member.file_size for member in members) > 16 * 1024 * 1024:
            raise ValueError("ODF package exceeds uncompressed-size budget")
        for member in members:
            if member.flag_bits & 1 or member.filename.startswith(("/", "\\")) or ".." in Path(member.filename.replace("\\", "/")).parts:
                raise ValueError("encrypted or traversing ODF member")
        if names[0] != "mimetype" or members[0].compress_type != zipfile.ZIP_STORED:
            raise ValueError("ODF mimetype is not the first uncompressed member")
        if archive.read("mimetype") != (MIME + kind).encode():
            raise ValueError("ODF mimetype does not match the requested Office document")
        for required in ("content.xml", "meta.xml"):
            if required not in names or archive.getinfo(required).file_size > 1024 * 1024:
                raise ValueError("missing or oversized required ODF XML")
        content = xml(archive.read("content.xml"))
        metadata = xml(archive.read("meta.xml"))
    if content.tag != "{" + NS["office"] + "}document-content":
        raise ValueError("saved document has the wrong ODF content root")
    generator = metadata.find(".//meta:generator", NS)
    generator_text = "" if generator is None else "".join(generator.itertext())
    if not generator_text.startswith("LibreOffice/" + VERSION + "$"):
        raise ValueError("saved metadata does not identify the pinned LibreOffice version")
    return {"path": str(path), "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "generator_metadata": generator_text,
            "generator_is_self_reported_metadata": True}, content


def inspect_office(writer: Path, calc: Path, nonce: str) -> dict:
    nonce_value(nonce)
    writer_record, writer_xml = saved_document(writer, "text")
    calc_record, calc_xml = saved_document(calc, "spreadsheet")
    if writer.resolve() == calc.resolve() or writer_record["sha256"] == calc_record["sha256"]:
        raise ValueError("Writer and Calc must be different saved documents")
    paragraphs = ["".join(element.itertext()) for element in writer_xml.findall(".//text:p", NS)]
    if "nonce=" + nonce not in paragraphs or UNICODE not in paragraphs or "EDIT-SAVED" not in paragraphs:
        raise ValueError("Writer saved artifact lacks the fresh challenge, Unicode or requested edit")
    tables = calc_xml.findall(".//table:table", NS)
    table = next((item for item in tables if item.get("{" + NS["table"] + "}name") == "FreshCalc"), None)
    if table is None:
        raise ValueError("Calc saved artifact lacks the fresh worksheet")
    rows = table.findall("table:table-row", NS)
    cells = []
    for row in rows[:5]:
        if row.get("{" + NS["table"] + "}number-rows-repeated", "1") != "1":
            raise ValueError("fixture rows must not be repeated")
        items = row.findall("table:table-cell", NS)
        if not items:
            raise ValueError("missing fixture cell")
        cells.append(items[0])
    if len(cells) < 5:
        raise ValueError("Calc saved artifact lacks fixture rows")
    value_key = "{" + NS["office"] + "}value"
    values = [cells[index].get(value_key) for index in range(3)]
    if values != ["19", "23", "42"]:
        raise ValueError("Calc fresh formula result must be 19 + 23 = 42")
    if cells[2].get("{" + NS["table"] + "}formula") != "of:=SUM([.A1:.A2])":
        raise ValueError("Calc formula was removed or replaced")
    texts = ["".join(cell.itertext()) for cell in cells]
    if texts[3] != "nonce=" + nonce or texts[4] != UNICODE:
        raise ValueError("Calc saved artifact lacks the fresh challenge or Unicode")
    return {
        "schema": "win98modern.office-saved-artifact-check.v1", "nonce": nonce,
        "writer": writer_record, "calc": calc_record,
        "saved_artifact_checks_passed": True,
        "observed": ["fresh challenge", "Unicode retained", "Writer requested edit", "Calc formula and recalculated value 42"],
        "save_and_reopen_process_observation": "required separately",
        "native_application_executed": False,
        "native_application_passed": False,
        "runtime_compatibility": "unverified",
        "reason": "Files and generator metadata cannot prove native Win98 process, GUI, save/reopen or clean exit behavior.",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("inputs", help="create fresh FODT/FODS input challenges")
    create.add_argument("--out", required=True, type=Path)
    create.add_argument("--nonce", required=True)
    check = commands.add_parser("office-artifacts", help="inspect saved ODT/ODS without claiming native execution")
    check.add_argument("--writer", required=True, type=Path)
    check.add_argument("--calc", required=True, type=Path)
    check.add_argument("--nonce", required=True)
    args = parser.parse_args(argv)
    try:
        report = (create_inputs(args.out, args.nonce) if args.command == "inputs"
                  else inspect_office(args.writer, args.calc, args.nonce))
    except (OSError, ValueError, KeyError, ET.ParseError, zipfile.BadZipFile) as exc:
        print(f"office_steam_acceptance: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
