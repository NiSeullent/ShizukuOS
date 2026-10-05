#!/usr/bin/env python3
"""Generate the ko-KR STRINGTABLE .rc from src/strings_ko.h (single source of the UI text)."""
import re, sys, pathlib
root = pathlib.Path(__file__).resolve().parents[1]
hdr = (root / "src/strings_ko.h").read_text()
tpl = (root / "res/shell_ko.rc.in").read_text()
rows = re.findall(r'X\((\w+), (\d+), L"([^"]*)"\)', hdr)
if not rows:
    sys.exit("no strings parsed")
out = [tpl, "STRINGTABLE\n{\n"]
for name, num, esc in rows:
    text = esc.encode("ascii").decode("unicode_escape")   # \uXXXX escapes -> real Hangul
    assert '"' not in text and "\\" not in text
    out.append(f'  {num}, "{text}"\n')
out.append("}\n")
pathlib.Path(sys.argv[1]).write_text("".join(out), encoding="utf-8")
print(f"{len(rows)} strings -> {sys.argv[1]}")
