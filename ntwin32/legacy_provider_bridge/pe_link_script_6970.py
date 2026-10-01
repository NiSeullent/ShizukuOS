# SPDX-License-Identifier: GPL-2.0-only
"""Bounded pure parsing of actual GNU i386pe scripts and empty list layout.

No process, file, compiler, provider or Windows operation is performed here.
The caller supplies the selected linker's actual verbose bytes and must own
resource admission. This independent parser contains no upstream script
template. Generated scripts retain the actual input's notices and other bytes.
The fixed no-CRT bridge/probe profile has no constructor dispatch: nonempty
constructor/destructor lists are unsupported and fail closed.
"""
import hashlib
import re
import struct

SCRIPT_LIMIT = 64 * 1024
VERBOSE_LIMIT = 256 * 1024
PE_LIMIT = 8 * 1024 * 1024
TOKEN_LIMIT = 16384
LAYOUT_CONTROL_COUNT = 5
ALIASES = ("__CTOR_LIST__", "___CTOR_LIST__", "__DTOR_LIST__", "___DTOR_LIST__")
END_MARKERS = ("__NTW6970_CTOR_END__", "__NTW6970_DTOR_END__")
_DELIMITER = b"=" * 50


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _bounded(raw, limit, label):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= limit:
        raise ValueError(label + " byte bound exceeded or wrong input type")


def extract_default_script(verbose):
    """Return the single delimiter-bounded script from actual ld --verbose."""
    _bounded(verbose, VERBOSE_LIMIT, "GNU verbose output")
    lines = verbose.splitlines(keepends=True)
    boundaries = [i for i, line in enumerate(lines)
                  if line.rstrip(b"\r\n") == _DELIMITER]
    if len(boundaries) != 2 or boundaries[1] <= boundaries[0] + 1:
        raise ValueError("GNU verbose output must contain one complete delimiter pair")
    script = b"".join(lines[boundaries[0] + 1:boundaries[1]])
    _bounded(script, SCRIPT_LIMIT, "GNU default script")
    return script


def _tokens(script):
    _bounded(script, SCRIPT_LIMIT, "GNU default script")
    if b"\0" in script or any(byte > 127 for byte in script):
        raise ValueError("GNU script must be bounded ASCII text")
    tokens = []
    at = 0
    while at < len(script):
        byte = script[at]
        if byte in b" \t\r\n":
            at += 1
            continue
        if script.startswith(b"/*", at):
            end = script.find(b"*/", at + 2)
            if end < 0:
                raise ValueError("GNU script comment is unterminated")
            at = end + 2
            continue
        start = at
        if byte == 34:
            at += 1
            while at < len(script):
                if script[at] == 92:
                    at += 2
                elif script[at] == 34:
                    at += 1
                    break
                else:
                    at += 1
            else:
                raise ValueError("GNU script quoted token is unterminated")
        else:
            match = re.match(rb"[A-Za-z_.$*][A-Za-z_0-9.$*]*|[0-9][A-Za-z_0-9]*", script[at:])
            at += len(match[0]) if match else 1
        tokens.append((script[start:at], start, at))
        if len(tokens) > TOKEN_LIMIT:
            raise ValueError("GNU script token bound exceeded")
    return tokens


def _contexts(tokens):
    depth, stack, depths, pairs = 0, [], [], {}
    for index, (value, _, _) in enumerate(tokens):
        depths.append(depth)
        if value == b"{":
            stack.append(index)
            depth += 1
        elif value == b"}":
            if not stack:
                raise ValueError("GNU script section braces are unbalanced")
            pairs[stack.pop()] = index
            depth -= 1
    if stack:
        raise ValueError("GNU script section braces are unbalanced")
    sections = [i for i, token in enumerate(tokens) if token[0] == b"SECTIONS"]
    if (len(sections) != 1 or sections[0] + 1 >= len(tokens)
            or tokens[sections[0] + 1][0] != b"{"):
        raise ValueError("GNU script requires one SECTIONS context")
    outer = sections[0] + 1
    if depths[outer] != 0:
        raise ValueError("GNU SECTIONS context must be top level")
    return depths, pairs, outer


def _section(tokens, depths, pairs, outer, name):
    candidates = [i for i in range(outer + 1, pairs[outer])
                  if tokens[i][0] == name and depths[i] == 1]
    if len(candidates) != 1:
        raise ValueError("GNU script requires one output section " + name.decode())
    index = candidates[0]
    stop = min(index + 129, pairs[outer])
    for opening in range(index + 1, stop):
        value = tokens[opening][0]
        if value in (b";", b"}"):
            break
        if value == b"{":
            if b":" not in [token[0] for token in tokens[index + 1:opening]]:
                break
            return opening, pairs[opening]
    raise ValueError("GNU output section context is unsupported: " + name.decode())


def relocate_lifecycle_lists(script):
    """Move real list commands, adding alignment and byte-free end markers."""
    tokens = _tokens(script)
    if any(token[0] in {name.encode() for name in END_MARKERS} for token in tokens):
        raise ValueError("GNU default script must not contain private lifecycle end markers")
    formats = [i for i, token in enumerate(tokens) if token[0] == b"OUTPUT_FORMAT"]
    if (len(formats) != 1 or not (
            [token[0] for token in tokens[formats[0]:formats[0] + 6]] ==
            [b"OUTPUT_FORMAT", b"(", b"pei", b"-", b"i386", b")"] or
            [token[0] for token in tokens[formats[0]:formats[0] + 4]] ==
            [b"OUTPUT_FORMAT", b"(", b'"pei-i386"', b")"])):
        raise ValueError("GNU script requires one PE i386 OUTPUT_FORMAT")
    depths, pairs, outer = _contexts(tokens)
    text_open, text_close = _section(tokens, depths, pairs, outer, b".text")
    data_open, data_close = _section(tokens, depths, pairs, outer, b".rdata")
    if text_close >= data_open:
        raise ValueError("GNU text/rdata output section ordering is unsupported")
    positions = {}
    for alias in ALIASES:
        found = [i for i, token in enumerate(tokens) if token[0] == alias.encode()]
        if len(found) != 1:
            raise ValueError("GNU lifecycle alias must occur exactly once: " + alias)
        positions[alias] = found[0]
    if not all(text_open < i < text_close and depths[i] == 2 for i in positions.values()):
        raise ValueError("GNU lifecycle lists must be direct children of .text")
    start = min(positions.values())
    cursor = start

    def take(expected):
        nonlocal cursor
        if [token[0] for token in tokens[cursor:cursor + len(expected)]] != expected:
            raise ValueError("GNU lifecycle commands are unsupported or noncontiguous")
        cursor += len(expected)

    def pair(names):
        order = []
        for _ in range(2):
            if cursor >= len(tokens):
                raise ValueError("GNU lifecycle commands are unsupported or noncontiguous")
            alias = tokens[cursor][0]
            if alias not in names or alias in order:
                raise ValueError("GNU lifecycle alias pair is unsupported")
            order.append(alias)
            take([alias, b"=", b".", b";"])
        take([b"LONG", b"(", b"-", b"1", b")", b";"])
        stem = b"ctors" if names[0].endswith(b"CTOR_LIST__") else b"dtors"
        for selector in (b"." + stem, b"." + stem[:-1]):
            take([b"KEEP", b"(", b"*", b"(", selector, b")", b")"])
            if cursor < len(tokens) and tokens[cursor][0] == b";":
                take([b";"])
        if cursor + 4 >= len(tokens) or tokens[cursor + 4][0] not in (b"SORT", b"SORT_BY_NAME"):
            raise ValueError("GNU sorted lifecycle input command is unsupported")
        sort = tokens[cursor + 4][0]
        take([b"KEEP", b"(", b"*", b"(", sort, b"(", b"." + stem + b".*",
              b")", b")", b")"])
        if cursor < len(tokens) and tokens[cursor][0] == b";":
            take([b";"])
        take([b"LONG", b"(", b"0", b")", b";"])
        return tokens[cursor - 1][2]

    ctor_end_command = pair((b"__CTOR_LIST__", b"___CTOR_LIST__"))
    dtor_end_command = pair((b"__DTOR_LIST__", b"___DTOR_LIST__"))
    if cursor > text_close or set(positions.values()) != {
            i for i in range(start, cursor) if tokens[i][0] in {name.encode() for name in ALIASES}}:
        raise ValueError("GNU lifecycle token range escaped its unique text context")
    first = tokens[start][1]
    last = tokens[cursor - 1][2]
    begin = script.rfind(b"\n", 0, first) + 1
    line_end = script.find(b"\n", last)
    if line_end < 0 or script[begin:first].strip() or script[last:line_end].strip():
        raise ValueError("GNU lifecycle block must occupy complete standalone lines")
    end = line_end + 1
    opening_end = tokens[data_open][2]
    insert_line_end = script.find(b"\n", opening_end)
    if insert_line_end < 0 or script[opening_end:insert_line_end].strip():
        raise ValueError("GNU rdata opening brace must have a standalone line end")
    insert = insert_line_end + 1
    block = script[begin:end]
    indent = script[begin:first]
    alignment = indent + b". = ALIGN(4);\n"
    marker_insertions = []
    for command_end, marker in zip((ctor_end_command, dtor_end_command), END_MARKERS):
        command_line_end = script.find(b"\n", command_end)
        if command_line_end < 0 or script[command_end:command_line_end].strip():
            raise ValueError("GNU list terminator must have a standalone line end")
        marker_insertions.append((command_line_end + 1 - begin,
                                  indent + marker.encode() + b" = .;\n"))
    marked_block = block
    for position, assignment in reversed(marker_insertions):
        marked_block = marked_block[:position] + assignment + marked_block[position:]
    if len(marked_block) != len(block) + sum(len(row[1]) for row in marker_insertions):
        raise ValueError("GNU lifecycle marker insertion changed original block bytes")
    addition = alignment + marked_block
    remaining = script[:begin] + script[end:]
    insertion = insert - (end - begin)
    generated = remaining[:insertion] + addition + remaining[insertion:]
    _bounded(generated, SCRIPT_LIMIT, "Generated GNU script")
    if generated[:insertion] + generated[insertion + len(addition):] != remaining:
        raise ValueError("GNU script byte conservation failed")
    return generated, {
        "status": "PASS", "original_bytes": len(script), "original_sha256": _digest(script),
        "generated_bytes": len(generated), "generated_sha256": _digest(generated),
        "moved_block_bytes": len(block), "moved_block_sha256": _digest(block),
        "all_other_script_bytes_preserved": True, "original_lifecycle_commands_preserved": True,
        "insertion": ".rdata aligned start",
        "added_commands": [". = ALIGN(4);"] + [name + " = .;" for name in END_MARKERS],
        "end_marker_assignments_allocate_runtime_bytes": False,
        "aliases": list(ALIASES), "retained_end_markers": list(END_MARKERS),
        "upstream_template_copied_into_helper": False,
        "constructor_dispatch_verified": False, "native_execution_verified": False,
    }


def _layout(raw, pe_module):
    _bounded(raw, PE_LIMIT, "Actual linked PE")
    with pe_module.PE(data=raw) as pe:
        if pe.FILE_HEADER.Machine != 0x14C or pe.OPTIONAL_HEADER.Magic != 0x10B:
            raise ValueError("Lifecycle layout requires PE32 i386")
        if not 0 < len(pe.sections) <= 96:
            raise ValueError("Lifecycle PE section count is outside bound")
        sections = [section for section in pe.sections if section.Name.rstrip(b"\0") == b".rdata"]
        if len(sections) != 1:
            raise ValueError("Lifecycle layout requires unique .rdata")
        section = sections[0]
        flags = section.Characteristics
        if not flags & 0x40000000 or flags & (0x80000000 | 0x20000000 | 0x20):
            raise ValueError("Lifecycle .rdata must be readable readonly nonexecutable data")
        pointer, count = pe.FILE_HEADER.PointerToSymbolTable, pe.FILE_HEADER.NumberOfSymbols
        if not 0 < count <= 65536 or pointer < pe.OPTIONAL_HEADER.SizeOfHeaders:
            raise ValueError("Lifecycle retained COFF symbols are absent or outside bound")
        strings = pointer + count * 18
        if strings + 4 > len(raw):
            raise ValueError("Lifecycle retained COFF symbols exceed file")
        string_size = struct.unpack_from("<I", raw, strings)[0]
        if not 4 <= string_size <= 2 * 1024 * 1024 or strings + string_size > len(raw):
            raise ValueError("Lifecycle COFF string table exceeds bound")
        symbols, offsets = {}, {}
        index = 0
        while index < count:
            at = pointer + index * 18
            name_bytes, value, number, kind, storage, auxiliary = struct.unpack_from("<8sIhHBB", raw, at)
            if index + auxiliary >= count:
                raise ValueError("Lifecycle COFF auxiliary records exceed symbol count")
            if name_bytes[:4] == b"\0" * 4:
                offset = struct.unpack_from("<I", name_bytes, 4)[0]
                if not 4 <= offset < string_size:
                    raise ValueError("Lifecycle COFF name offset exceeds string table")
                stop = raw.find(b"\0", strings + offset, min(strings + string_size, strings + offset + 257))
                if stop < 0:
                    raise ValueError("Lifecycle COFF name is unterminated or unbounded")
                name = raw[strings + offset:stop].decode("ascii", errors="strict")
            else:
                name = name_bytes.split(b"\0", 1)[0].decode("ascii", errors="strict")
            if name in ALIASES + END_MARKERS:
                if (name in symbols or storage != 2 or not 1 <= number <= len(pe.sections)
                        or pe.sections[number - 1] is not section
                        or value > section.Misc_VirtualSize
                        or (name in ALIASES and value == section.Misc_VirtualSize)):
                    raise ValueError("Lifecycle aliases and end markers must be unique external .rdata symbols")
                symbols[name] = section.VirtualAddress + value
                offsets[name] = at + 8
            index += 1 + auxiliary
        if set(symbols) != set(ALIASES + END_MARKERS):
            raise ValueError("Lifecycle four aliases and two retained end markers are required")
        aliases = {name: symbols[name] for name in ALIASES}
        end_rvas = {name: symbols[name] for name in END_MARKERS}
        ctor, dtor = aliases[ALIASES[0]], aliases[ALIASES[2]]
        if aliases[ALIASES[1]] != ctor or aliases[ALIASES[3]] != dtor:
            raise ValueError("Lifecycle alias pair RVAs differ")
        if ctor % 4 or ctor != section.VirtualAddress or dtor != ctor + 8:
            raise ValueError("Lifecycle lists must be aligned adjacent empty pairs at .rdata start")
        ctor_end, dtor_end = (end_rvas[name] for name in END_MARKERS)
        if (ctor_end % 4 or dtor_end % 4 or ctor_end != ctor + 8 or ctor_end != dtor
                or dtor_end != dtor + 8 or dtor_end != section.VirtualAddress + 16):
            raise ValueError("Lifecycle retained end markers must bound exact eight-byte lists")
        if (section.Misc_VirtualSize < 16 or section.SizeOfRawData < 16
                or section.PointerToRawData < pe.OPTIONAL_HEADER.SizeOfHeaders
                or section.PointerToRawData + section.SizeOfRawData > len(raw)):
            raise ValueError("Lifecycle table bytes are not fully backed .rdata")
        data_at = section.PointerToRawData
        if raw[data_at:data_at + 16] != struct.pack("<4I", 0xFFFFFFFF, 0, 0xFFFFFFFF, 0):
            raise ValueError("Lifecycle empty table sentinels differ")
        exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if exports is not None:
            if len(exports.symbols) > 65536:
                raise ValueError("Lifecycle PE export count exceeds bound")
            if any(symbol.name in {name.encode() for name in END_MARKERS}
                   or symbol.address in set(end_rvas.values())
                   for symbol in exports.symbols):
                raise ValueError("Lifecycle retained end markers must not be PE exports")
        report = {
            "status": "PASS", "alias_rvas": aliases, "section": ".rdata",
            "section_rva": section.VirtualAddress, "section_characteristics": flags,
            "end_marker_rvas": end_rvas,
            "constructor_bytes": ctor_end - ctor, "destructor_bytes": dtor_end - dtor,
            "retained_exact_list_spans_verified": True, "end_markers_exported": False,
            "empty_constructor_destructor_tables_verified": True,
            "constructor_dispatch_verified": False, "full_PE_or_COFF_validation_verified": False,
            "native_execution_verified": False,
        }
        control_offsets = {"data": data_at, "flags": section.get_file_offset() + 36,
                           "symbol_values": offsets, "flags_value": flags,
                           "section_rva": section.VirtualAddress, "alias_rvas": aliases,
                           "section_virtual_bytes": section.Misc_VirtualSize}
        return report, control_offsets


def validate_empty_lifecycle_layout(raw_pe, pe_module):
    """Validate real retained symbols and table bytes; never execute the PE."""
    return _layout(raw_pe, pe_module)[0]


def run_layout_controls(raw_pe, pe_module):
    """Five selected mutations of current linked bytes, with actual PE parsing."""
    _, offsets = _layout(raw_pe, pe_module)
    if offsets["section_virtual_bytes"] < 20:
        raise ValueError("Lifecycle destructor-span control needs backed following .rdata")
    value_offsets = offsets["symbol_values"]
    cases = (
        ("layout-sentinel-tamper", ((offsets["data"], 0),),
         "Lifecycle empty table sentinels differ"),
        ("layout-rdata-executable", ((offsets["flags"], offsets["flags_value"] | 0x20000000),),
         "Lifecycle .rdata must be readable readonly nonexecutable data"),
        ("layout-one-alias-mismatch", ((value_offsets[ALIASES[1]], 4),),
         "Lifecycle alias pair RVAs differ"),
        ("layout-nonempty-adjacency", ((value_offsets[ALIASES[2]], 12),
                                        (value_offsets[ALIASES[3]], 12)),
         "Lifecycle lists must be aligned adjacent empty pairs at .rdata start"),
        ("layout-destructor-end-gap", ((value_offsets[END_MARKERS[1]], 20),),
         "Lifecycle retained end markers must bound exact eight-byte lists"),
    )
    reports = []
    for name, edits, expected in cases:
        changed = bytearray(raw_pe)
        for at, value in edits:
            struct.pack_into("<I", changed, at, value)
        altered = bytes(changed)
        if name == "layout-destructor-end-gap" and altered[offsets["data"]:offsets["data"] + 16] != raw_pe[offsets["data"]:offsets["data"] + 16]:
            raise ValueError("Lifecycle destructor-span control changed sentinel bytes")
        try:
            validate_empty_lifecycle_layout(altered, pe_module)
        except ValueError as error:
            if str(error) != expected:
                raise ValueError("Lifecycle layout control rejected for unintended predicate: " + name) from error
        else:
            raise ValueError("Lifecycle layout negative control was accepted: " + name)
        reports.append({"case": name, "result": "PASS", "expected": "reject",
                        "expected_rejection": expected, "mutated_bytes": len(altered),
                        "mutated_sha256": _digest(altered),
                        "first_sixteen_table_bytes_preserved":
                            altered[offsets["data"]:offsets["data"] + 16] == raw_pe[offsets["data"]:offsets["data"] + 16]})
    if len(reports) != LAYOUT_CONTROL_COUNT or len({row["case"] for row in reports}) != LAYOUT_CONTROL_COUNT:
        raise ValueError("Lifecycle layout control count/uniqueness mismatch")
    return {"status": "PASS", "completed": len(reports), "cases": reports,
            "native_execution_verified": False, "full_layout_predicate_coverage_verified": False}


def _synthetic_script(sort=b"SORT", swapped=False):
    """Small independently composed language fixture, not an upstream script."""
    lines = [b"/* synthetic fixture */", b"OUTPUT_FORMAT(pei-i386)", b"SECTIONS", b"{",
             b"  .text :", b"  {", b"    *(.text)"]
    for stem in (b"CTOR", b"DTOR"):
        aliases = [b"__" + stem + b"_LIST__", b"___" + stem + b"_LIST__"]
        if swapped:
            aliases.reverse()
        lines.extend(b"    " + alias + b" = .;" for alias in aliases)
        selector = stem.lower() + b"s"
        lines.extend([b"    LONG (-1);", b"    KEEP(*( ." + selector + b" ));",
                      b"    KEEP(*( ." + selector[:-1] + b" ));",
                      b"    KEEP(*(" + sort + b"(." + selector + b".*)));", b"    LONG (0);"])
    lines.extend([b"    etext = .;", b"  }", b"  .rdata :", b"  {", b"    *(.rdata)",
                  b"    . = ALIGN(4);", b"    __rt_psrelocs_start = .;",
                  b"    KEEP(*(.rdata_runtime_pseudo_reloc))", b"    __rt_psrelocs_end = .;",
                  b"  }", b"  __RUNTIME_PSEUDO_RELOC_LIST_END__ = .;", b"}"])
    return b"\n".join(lines) + b"\n"


TEXT_CONTROL_COUNT = 15


def run_synthetic_controls():
    """Selected synthetic extraction/context/conservation controls, no I/O."""
    script = _synthetic_script()
    wrapped = b"synthetic ld verbose\n" + _DELIMITER + b"\n" + script + _DELIMITER + b"\n"
    cases = (
        ("text-default-relocation", script, None),
        ("text-alias-order", _synthetic_script(swapped=True), None),
        ("text-sort-by-name", _synthetic_script(sort=b"SORT_BY_NAME"), None),
        ("text-comment-aliases", script.replace(b"/* synthetic fixture */", b"/* __CTOR_LIST__ { } */"), None),
        ("text-unsupported-format", script.replace(b"pei-i386", b"elf32-i386"),
         "GNU script requires one PE i386 OUTPUT_FORMAT"),
        ("text-duplicate-alias", script.replace(b"    etext = .;", b"    __CTOR_LIST__ = .;"),
         "GNU lifecycle alias must occur exactly once: __CTOR_LIST__"),
        ("text-missing-alias", script.replace(b"    __CTOR_LIST__ = .;\n", b""),
         "GNU lifecycle alias must occur exactly once: __CTOR_LIST__"),
        ("text-extra-command", script.replace(b"    ___DTOR_LIST__ = .;", b"    unexpected = .;\n    ___DTOR_LIST__ = .;"),
         "GNU lifecycle alias pair is unsupported"),
        ("text-sentinel-change", script.replace(b"LONG (-1)", b"LONG (1)", 1),
         "GNU lifecycle commands are unsupported or noncontiguous"),
        ("text-missing-keep", script.replace(b"    KEEP(*( .ctor ));\n", b""),
         "GNU lifecycle commands are unsupported or noncontiguous"),
        ("text-duplicate-rdata", script.replace(b"  .rdata :", b"  .rdata : { }\n  .rdata :"),
         "GNU script requires one output section .rdata"),
    )
    reports = []
    for name, source, expected in cases:
        try:
            generated, metadata = relocate_lifecycle_lists(source)
        except ValueError as error:
            if expected is None or str(error) != expected:
                raise ValueError("GNU text control failed/unintended rejection: " + name) from error
        else:
            if expected is not None:
                raise ValueError("GNU malformed text control was accepted: " + name)
            if (not metadata["all_other_script_bytes_preserved"]
                    or not metadata["original_lifecycle_commands_preserved"]
                    or metadata["added_commands"] != [". = ALIGN(4);"] + [marker + " = .;" for marker in END_MARKERS]
                    or any(generated.count(marker.encode() + b" = .;") != 1
                           or b"LONG (0);\n    " + marker.encode() + b" = .;\n" not in generated
                           for marker in END_MARKERS)
                    or generated.index(b"__CTOR_LIST__ = .;") < generated.index(b".rdata :")
                    or generated.index(b"__DTOR_LIST__ = .;") > generated.index(b"*(.rdata)")
                    or source[source.index(b"    etext = .;"):source.index(b"  .rdata :")] not in generated
                    or generated[generated.index(b"    *(.rdata)"):] != source[source.index(b"    *(.rdata)"):]):
                raise ValueError("GNU positive text control lost conservation/start/pseudo-tail invariants")
        reports.append({"case": name, "result": "PASS", "expected": "reject" if expected else "accept",
                        "expected_rejection": expected, "input_sha256": _digest(source)})
    extraction = (
        ("verbose-single-script", wrapped, None),
        ("verbose-missing-delimiter", script,
         "GNU verbose output must contain one complete delimiter pair"),
        ("verbose-duplicate-script", wrapped + wrapped,
         "GNU verbose output must contain one complete delimiter pair"),
        ("verbose-oversized-script", _DELIMITER + b"\n" + b"x" * (SCRIPT_LIMIT + 1) + b"\n" + _DELIMITER + b"\n",
         "GNU default script byte bound exceeded or wrong input type"),
    )
    for name, source, expected in extraction:
        try:
            result = extract_default_script(source)
        except ValueError as error:
            if expected is None or str(error) != expected:
                raise ValueError("GNU extraction control failed/unintended rejection: " + name) from error
        else:
            if expected is not None or result != script:
                raise ValueError("GNU extraction control accepted unexpected bytes: " + name)
        reports.append({"case": name, "result": "PASS", "expected": "reject" if expected else "accept",
                        "expected_rejection": expected, "input_sha256": _digest(source)})
    if len(reports) != TEXT_CONTROL_COUNT or len({row["case"] for row in reports}) != TEXT_CONTROL_COUNT:
        raise ValueError("GNU text control case count/uniqueness mismatch")
    return {"status": "PASS", "completed": len(reports), "cases": reports,
            "native_execution_verified": False, "full_GNU_script_grammar_verified": False}
