# SPDX-License-Identifier: GPL-2.0-only
"""Bounded framing around the unchanged i486 instruction/byte oracle.

This module owns no process, file, compression, download or execution boundary.
The caller binds the actual PE bytes and frozen oracle source, drains both child
streams, hashes/pins tools and retains bounded gzip output.  Passing this parser
proves only the supplied disassembly's shape and executable-byte coverage.

Controls are pure, explicitly invoked by the admitted hosted runner.  Importing
this module does not execute them or invoke an external program.
"""

from __future__ import annotations

import hashlib
import re

MAX_RAW_BYTES = 16 * 1024 * 1024
MAX_EXEC_BYTES = 4 * 1024 * 1024
MAX_LINE_BYTES = 4096  # Includes the physical LF.
MAX_CHUNK_BYTES = 64 * 1024
MAX_CHUNK_TEXT = 256 * 1024
MAX_CHUNKS = 1024
MAX_SECTIONS = 96

CONTROL_NAMES = (
    "positive-whole-equivalence", "positive-feed-fragments",
    "positive-ordered-sections", "negative-boundary-modern",
    "negative-address-gap", "negative-byte-mismatch",
    "negative-duplicate-header", "negative-section-order",
    "negative-outside-row", "negative-malformed-row",
    "negative-truncated-final-row", "negative-line-bound",
    "negative-raw-bound", "negative-incomplete-coverage",
    "negative-unexpected-body", "negative-invalid-oracle-pass",
    "negative-preamble-format",
)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _control_fixture(rows=14000, modern_index=None):
    variants = ((b"\x90", "nop", ""),
                (b"\x31\xc0", "xor", "%eax,%eax"),
                (b"\x8d\x40\x01", "lea", "0x1(%eax),%eax"),
                (b"\xb8\x01\x00\x00\x00", "mov", "$0x1,%eax"))
    lines = [b"\n/synthetic/native.dll:     file format pei-i386\n\n",
             b"Disassembly of section .text:\n\n",
             b"00401000 <_stream_span>:\n"]
    payload, cursor = [], 0x401000
    for index in range(rows):
        raw, mnemonic, operands = variants[index % len(variants)]
        if index == modern_index:
            raw, mnemonic, operands = (b"\x0f\x1f\x40\x00", "nop",
                                      "0x0(%eax) # boundary-control")
        lines.append((f"  {cursor:x}: " + " ".join(f"{byte:02x}" for byte in raw)
                      + "  " + mnemonic + (" " + operands if operands else "")
                      + "\n").encode("ascii"))
        payload.append(raw)
        cursor += len(raw)
    return b"".join(lines), {".text": {"address": 0x401000,
                                        "bytes": b"".join(payload)}}


def run_controls(gate):
    """Explicit hosted-only framing/coverage controls; no external calls.

    Whole-versus-chunk equivalence uses the supplied actual frozen oracle.
    The deliberately invalid PASS wrapper changes only its report, to verify
    that a status string cannot replace the required byte/count contract.
    """
    cases, baseline = [], {}
    raw, sections = _control_fixture()

    def accept(name, callback):
        try:
            callback()
            cases.append({"name": name, "expected": "accept", "result": "PASS"})
        except Exception as error:
            cases.append({"name": name, "expected": "accept", "result": "FAIL",
                          "error": (type(error).__name__ + ": " + str(error))[:240]})

    def reject(name, code, callback, predicate=None):
        try:
            callback()
        except DecodeError as error:
            passed = error.code == code and (predicate is None or predicate(error))
            cases.append({"name": name, "expected": "reject",
                          "result": "PASS" if passed else "FAIL",
                          "expected_error": code, "observed_error": error.code})
        except Exception as error:
            cases.append({"name": name, "expected": "reject", "result": "FAIL",
                          "error": (type(error).__name__ + ": " + str(error))[:240]})
        else:
            cases.append({"name": name, "expected": "reject", "result": "FAIL",
                          "error": "unexpected acceptance"})

    def parse(data, expected, chunks=None, selected_gate=gate):
        decoder = StreamDecoder(selected_gate, expected)
        if chunks is None:
            decoder.feed(data)
        else:
            offset, index = 0, 0
            while offset < len(data):
                size = chunks[index % len(chunks)]
                decoder.feed(data[offset:offset + size])
                offset += size
                index += 1
        return decoder.finish()

    def equivalent(fragmented=False):
        whole = gate.inspect_decode(raw.decode("ascii"), sections)
        report = parse(raw, sections, (1, 7, 4093, 257, 16384) if fragmented else None)
        assert whole["status"] == report["status"] == "PASS"
        assert whole["instructions"] == report["instructions"] == 14000
        assert whole["sections"] == report["sections"]
        assert report["raw_bytes"] == len(raw) and report["raw_sha256"] == _sha(raw)
        assert report["raw_lines"] == raw.count(b"\n")
        assert len(report["chunks"]) >= 2
        assert sum(row["instructions"] for row in report["chunks"]) == 14000
        assert all(row["bytes"] <= MAX_CHUNK_BYTES and
                   row["oracle_text_bytes"] <= MAX_CHUNK_TEXT for row in report["chunks"])
        if fragmented:
            assert report == baseline["report"]
        else:
            baseline["report"] = report

    accept(CONTROL_NAMES[0], equivalent)
    accept(CONTROL_NAMES[1], lambda: equivalent(True))
    ordered = (b"/synthetic/ordered.dll:     file format pei-i386\n\n"
               b"Disassembly of section .text:\n00401000 <_a>:\n  401000: 90  nop\n\n"
               b"Disassembly of section .init:\n00402000 <_b>:\n  402000: 31 c0  xor %eax,%eax\n")
    ordered_sections = {".text": {"address": 0x401000, "bytes": b"\x90"},
                        ".init": {"address": 0x402000, "bytes": b"\x31\xc0"}}

    def ordered_positive():
        report = parse(ordered, ordered_sections, (13, 1, 29))
        whole = gate.inspect_decode(ordered.decode("ascii"), ordered_sections)
        assert report["instructions"] == whole["instructions"] == 2
        assert report["sections"] == whole["sections"]
        assert report["status"] == whole["status"] == "PASS"

    accept(CONTROL_NAMES[2], ordered_positive)

    def boundary_modern():
        index = baseline["report"]["chunks"][0]["instructions"]
        data, expected = _control_fixture(modern_index=index)
        whole = gate.inspect_decode(data.decode("ascii"), expected)
        assert whole["status"] == "FAIL" and whole["non_i486_instruction_count"] == 1
        parse(data, expected, (4093, 31))

    def inherited_symbol(error):
        observation = error.observation
        bad = observation.get("oracle", {}).get("non_i486_instructions", [])
        return (observation["completed_chunks"] >= 1 and len(bad) == 1
                and bad[0]["symbol"] == "_stream_span")

    reject(CONTROL_NAMES[3], "oracle-rejected", boundary_modern, inherited_symbol)
    reject(CONTROL_NAMES[4], "row-address", lambda: parse(
        raw.replace(b"  401000:", b"  401001:", 1), sections))
    reject(CONTROL_NAMES[5], "row-bytes", lambda: parse(
        raw.replace(b"  401000: 90", b"  401000: 91", 1), sections))
    reject(CONTROL_NAMES[6], "section-order", lambda: parse(
        raw + b"Disassembly of section .text:\n", sections))
    reject(CONTROL_NAMES[7], "section-order", lambda: parse(
        ordered.replace(b"Disassembly of section .text:",
                        b"Disassembly of section .init:", 1), ordered_sections))
    reject(CONTROL_NAMES[8], "outside-row", lambda: parse(
        b"/synthetic/native.dll:     file format pei-i386\n  401000: 90  nop\n", sections))
    reject(CONTROL_NAMES[9], "malformed-row", lambda: parse(
        raw.replace(b"  401000: 90  nop\n", b"  401000: 90\n", 1), sections))
    reject(CONTROL_NAMES[10], "truncated-line", lambda: parse(raw[:-1], sections))
    reject(CONTROL_NAMES[11], "line-bound", lambda: parse(b" " * MAX_LINE_BYTES + b"\n", sections))

    def raw_bound():
        decoder = StreamDecoder(gate, sections)
        block = b" " * (MAX_LINE_BYTES - 1) + b"\n"
        for _ in range(MAX_RAW_BYTES // len(block)):
            decoder.feed(block)
        decoder.feed(b"\n")

    reject(CONTROL_NAMES[12], "raw-bound", raw_bound)
    longer = {".text": {"address": sections[".text"]["address"],
                         "bytes": sections[".text"]["bytes"] + b"\x90"}}
    reject(CONTROL_NAMES[13], "section-coverage", lambda: parse(raw, longer))
    reject(CONTROL_NAMES[14], "unexpected-line", lambda: parse(
        raw.replace(b"00401000 <_stream_span>:\n",
                    b"00401000 <_stream_span>:\nnot-an-instruction\n", 1), sections))

    class InvalidPass:
        @staticmethod
        def inspect_decode(text, expected):
            report = dict(gate.inspect_decode(text, expected))
            report["instructions"] = 0
            return report

    reject(CONTROL_NAMES[15], "oracle-contract", lambda: parse(raw, sections, selected_gate=InvalidPass))
    reject(CONTROL_NAMES[16], "unexpected-line", lambda: parse(
        raw.replace(b"file format pei-i386", b"file format elf32-i386", 1), sections))
    failures = sum(row["result"] != "PASS" for row in cases)
    if tuple(row["name"] for row in cases) != CONTROL_NAMES:
        raise ValueError("control name/count contract changed")
    return {"schema": "win98modern.i486-stream-controls.6970.v1",
            "status": "PASS" if not failures else "FAIL", "completed": len(cases),
            "failures": failures, "cases": cases, "native_execution_verified": False}


class DecodeError(ValueError):
    """A bounded parser failure observation, distinct from process evidence."""

    def __init__(self, code, observation):
        super().__init__(code)
        self.code = code
        self.observation = observation


class StreamDecoder:
    """Incremental strict ASCII/LF objdump framing and complete-row chunks."""

    _header = re.compile(r"Disassembly of section ([^ :\t]+):")
    _label = re.compile(r"([0-9a-f]+) <([^<>]+)>:")
    _row = re.compile(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(\S+)(?:[ \t]+(.*))?")
    _row_start = re.compile(r"\s*[0-9a-f]+:")
    _format = re.compile(r"(/[^\t]+):[ \t]+file format pei-i386")

    def __init__(self, gate, sections):
        self._inspect = getattr(gate, "inspect_decode", None)
        if not callable(self._inspect) or not isinstance(sections, dict) or not 0 < len(sections) <= MAX_SECTIONS:
            raise ValueError("actual oracle and bounded ordered sections required")
        self._sections, self._extents = {}, []
        for name, section in sections.items():
            if not isinstance(name, str) or not re.fullmatch(r"[^\s:\x00-\x1f\x7f]{1,8}", name) or not name.isascii():
                raise ValueError("PE section name required")
            if not isinstance(section, dict) or set(section) != {"address", "bytes"}:
                raise ValueError("exact section extent fields required")
            address, raw = section["address"], section["bytes"]
            if type(address) is not int or not 0 <= address <= 0xffffffff or type(raw) is not bytes or \
                    not 0 < len(raw) <= MAX_EXEC_BYTES or address + len(raw) > 0x100000000:
                raise ValueError("bounded PE32 immutable section extent required")
            self._sections[name] = {"address": address, "bytes": raw}
            self._extents.append((address, address + len(raw)))
        ordered_extents = sorted(self._extents)
        if sum(len(row["bytes"]) for row in self._sections.values()) > MAX_EXEC_BYTES or \
                any(a[1] > b[0] for a, b in zip(ordered_extents, ordered_extents[1:])):
            raise ValueError("bounded disjoint executable VirtualSize extents required")
        self._names = tuple(self._sections)
        self._cursors = {name: 0 for name in self._names}
        self._pending = b""
        self._raw_hash = hashlib.sha256()
        self._raw_bytes = self._raw_lines = self._rows = self._instructions = 0
        self._current = None
        self._seen = []
        self._artifact_label = None
        self._symbol = self._symbol_line = None
        self._chunk_lines = []
        self._chunk_start = self._chunk_bytes = self._chunk_text = self._chunk_rows = 0
        self._chunk_inherited_symbol = None
        self._chunks = []
        self._finished = self._failed = False

    def _error(self, code, oracle=None):
        self._failed = True
        observation = {"code": code, "raw_bytes_observed": self._raw_bytes,
                       "raw_sha256_observed": self._raw_hash.hexdigest(),
                       "complete_lines_processed": self._raw_lines,
                       "section": self._current,
                       "section_cursor": self._cursors.get(self._current, 0),
                       "symbol": self._symbol[:160] if self._symbol else None,
                       "completed_chunks": len(self._chunks),
                       "instructions_in_completed_chunks": self._instructions}
        if isinstance(oracle, dict):
            bad = []
            for row in oracle.get("non_i486_instructions", [])[:8]:
                if isinstance(row, dict):
                    bad.append({key: (value[:160] if isinstance(value, str) else value)
                                for key, value in row.items()
                                if key in ("section", "address", "raw", "mnemonic", "operands", "symbol")
                                and (value is None or type(value) in (str, int))})
            errors = oracle.get("coverage_errors", [])
            observation["oracle"] = {"status": str(oracle.get("status"))[:16],
                                      "non_i486_instruction_count": oracle.get("non_i486_instruction_count"),
                                      "non_i486_instructions": bad,
                                      "coverage_errors": [str(value)[:160] for value in errors[:8]]}
        raise DecodeError(code, observation)

    def feed(self, data):
        if self._finished or self._failed:
            raise ValueError("decoder is closed")
        if type(data) is not bytes:
            self._error("input-type")
        if self._raw_bytes + len(data) > MAX_RAW_BYTES:
            self._error("raw-bound")
        self._raw_bytes += len(data)
        self._raw_hash.update(data)
        position = 0
        while position < len(data):
            end = data.find(b"\n", position)
            if end < 0:
                piece = data[position:]
                if len(self._pending) + len(piece) >= MAX_LINE_BYTES:
                    self._error("line-bound")
                self._pending += piece
                break
            piece = data[position:end]
            if len(self._pending) + len(piece) + 1 > MAX_LINE_BYTES:
                self._error("line-bound")
            raw = self._pending + piece
            self._pending = b""
            self._raw_lines += 1
            try:
                line = raw.decode("ascii")
            except UnicodeDecodeError:
                self._error("non-ascii")
            if re.search(r"[^\x09\x20-\x7e]", line):
                self._error("control-character")
            self._line(line)
            position = end + 1

    def _line(self, line):
        if not line.strip(" \t"):
            return
        preamble = self._format.fullmatch(line)
        if preamble:
            if self._artifact_label is not None or self._seen:
                self._error("duplicate-preamble")
            self._artifact_label = preamble[1]
            return
        header = self._header.fullmatch(line)
        if header:
            if self._artifact_label is None:
                self._error("missing-preamble")
            name = header[1]
            if len(self._seen) >= len(self._names) or name != self._names[len(self._seen)]:
                self._error("section-order")
            if self._current is not None:
                self._flush()
                if self._cursors[self._current] != len(self._sections[self._current]["bytes"]):
                    self._error("section-coverage")
            self._current = name
            self._seen.append(name)
            self._symbol = self._symbol_line = None
            return
        label = self._label.fullmatch(line)
        if label:
            if self._current is None:
                self._error("outside-label")
            section = self._sections[self._current]
            if int(label[1], 16) != section["address"] + self._cursors[self._current]:
                self._error("label-address")
            encoded_length = len(line) + 1
            if self._chunk_rows and self._chunk_text + encoded_length > MAX_CHUNK_TEXT:
                self._flush()
            self._symbol, self._symbol_line = label[2], line
            if self._chunk_rows:
                self._chunk_lines.append(line + "\n")
                self._chunk_text += encoded_length
            return
        if self._row_start.match(line):
            if self._current is None:
                self._error("outside-row")
            row = self._row.fullmatch(line)
            if row is None:
                self._error("malformed-row")
            address, byte_text, _mnemonic, _operands = row.groups()
            raw = bytes.fromhex(byte_text)
            if not 1 <= len(raw) <= 15:
                self._error("row-size")
            section, cursor = self._sections[self._current], self._cursors[self._current]
            if int(address, 16) != section["address"] + cursor:
                self._error("row-address")
            if section["bytes"][cursor:cursor + len(raw)] != raw:
                self._error("row-bytes")
            if self._chunk_rows and (self._chunk_bytes + len(raw) > MAX_CHUNK_BYTES or
                                     self._chunk_text + len(line) + 1 > MAX_CHUNK_TEXT):
                self._flush()
            if not self._chunk_rows:
                self._chunk_start = cursor
                prefix = f"Disassembly of section {self._current}:\n"
                if self._symbol_line is not None:
                    prefix += self._symbol_line + "\n"
                self._chunk_lines = [prefix]
                self._chunk_text = len(prefix)
                self._chunk_inherited_symbol = self._symbol[:160] if self._symbol else None
            if self._chunk_text + len(line) + 1 > MAX_CHUNK_TEXT:
                self._error("chunk-text-bound")
            self._chunk_lines.append(line + "\n")
            self._chunk_text += len(line) + 1
            self._chunk_bytes += len(raw)
            self._chunk_rows += 1
            self._cursors[self._current] += len(raw)
            self._rows += 1
            return
        self._error("unexpected-line")

    def _flush(self):
        if not self._chunk_rows:
            return
        if len(self._chunks) >= MAX_CHUNKS:
            self._error("chunk-count-bound")
        source = self._sections[self._current]
        raw = source["bytes"][self._chunk_start:self._chunk_start + self._chunk_bytes]
        address = source["address"] + self._chunk_start
        text = "".join(self._chunk_lines)
        if not 0 < len(raw) <= MAX_CHUNK_BYTES or not 0 < len(text) <= MAX_CHUNK_TEXT:
            self._error("chunk-bound")
        expected = {self._current: {"address": address, "bytes": raw}}
        report = self._inspect(text, expected)
        if not isinstance(report, dict) or report.get("status") not in ("PASS", "FAIL"):
            self._error("oracle-contract")
        if report["status"] != "PASS":
            self._error("oracle-rejected", report)
        section_report = {self._current: {"address": address, "bytes": len(raw),
                                          "sha256": _sha(raw), "decoded_bytes": len(raw)}}
        if type(report.get("instructions")) is not int or report["instructions"] != self._chunk_rows or \
                report.get("coverage_errors") != [] or \
                type(report.get("non_i486_instruction_count")) is not int or \
                report["non_i486_instruction_count"] != 0 or \
                report.get("non_i486_instructions") != [] or report.get("sections") != section_report:
            self._error("oracle-contract", report)
        self._chunks.append({"index": len(self._chunks), "section": self._current,
                             "address": address, "offset": self._chunk_start,
                             "bytes": len(raw), "bytes_sha256": _sha(raw),
                             "oracle_text_bytes": len(text),
                             "oracle_text_sha256": _sha(text.encode("ascii")),
                             "instructions": report["instructions"],
                             "inherited_symbol": self._chunk_inherited_symbol})
        self._instructions += report["instructions"]
        self._chunk_lines = []
        self._chunk_bytes = self._chunk_text = self._chunk_rows = 0
        self._chunk_inherited_symbol = None

    def finish(self):
        if self._finished or self._failed:
            raise ValueError("decoder is closed")
        if self._pending:
            self._error("truncated-line")
        if self._artifact_label is None:
            self._error("missing-preamble")
        self._flush()
        if tuple(self._seen) != self._names or any(self._cursors[name] != len(section["bytes"])
                                                 for name, section in self._sections.items()):
            self._error("section-coverage")
        if not self._rows or self._instructions != self._rows:
            self._error("instruction-coverage")
        self._finished = True
        return {"schema": "win98modern.i486-stream.6970.v1", "status": "PASS",
                "artifact_label": self._artifact_label, "raw_bytes": self._raw_bytes,
                "raw_sha256": self._raw_hash.hexdigest(), "raw_lines": self._raw_lines,
                "instructions": self._instructions, "coverage_errors": [],
                "non_i486_instruction_count": 0, "non_i486_instructions": [],
                "chunks": list(self._chunks),
                "sections": {name: {"address": section["address"], "bytes": len(section["bytes"]),
                                     "sha256": _sha(section["bytes"]), "decoded_bytes": self._cursors[name]}
                             for name, section in self._sections.items()},
                "native_execution_verified": False, "imported_os_dll_code_verified": False}
