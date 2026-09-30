#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Classify the licence header of every source file in the pinned WebKit tree's WTF, JavaScriptCore and bmalloc
directories (docs/shizukudos10/WEBKIT.md "Licence"). Prints {directory: {licence-combination: count}} as JSON and one
example path per combination. A file matches a licence when its first 8 KB (comment markers removed) contain that
licence's grant text; "NONE" means no recognised grant (generated tables, build scripts, .py/.rb helpers)."""
import collections
import json
import re
import sys
from pathlib import Path

PATTERNS = [
    ("LGPL-2.1-or-later", r"Lesser General Public License as published by the Free Software Foundation either version 2\.1"),
    ("LGPL-2.0-or-later", r"(Library|Lesser) General Public License as published by the Free Software Foundation either version 2[^.]"),
    ("MPL-1.1/GPL-2.0-or-later/LGPL-2.1-or-later", r"Version: MPL 1\.1 GPL 2\.0 LGPL 2\.1"),
    ("BSD-3-Clause", r"Neither the name|may not be used to endorse|names of its contributors may be used"),
    ("BSD-2-Clause", r"Redistribution and use in source and binary forms"),
    ("Apache-2.0 WITH LLVM-exception", r"Apache License v2\.0 with LLVM Exceptions"),
    ("Apache-2.0", r"Apache License, Version 2\.0"),
    ("MIT", r"Permission is hereby granted, free of charge"),
    ("BSL-1.0", r"Boost Software License"),
    ("Unicode-3.0 (ICU)", r"Unicode, Inc|UNICODE, INC"),
    ("ISC", r"Permission to use, copy, modify, and(/or)? distribute"),
]
SUFFIXES = {".h", ".cpp", ".c", ".cc", ".mm", ".rb", ".asm", ".py", ".pl", ".js", ".S", ".hpp", ".inc"}


def classify(text):
    t = re.sub(r"[\s*/#;]+", " ", text[:8000])
    hits = []
    for name, pat in PATTERNS:
        if re.search(pat, t):
            if name == "BSD-2-Clause" and "BSD-3-Clause" in hits:
                continue                                   # the 3-clause text contains the 2-clause text
            if name == "LGPL-2.0-or-later" and "LGPL-2.1-or-later" in hits:
                continue
            hits.append(name)
    return " + ".join(hits) or "NONE"


def scan(tree, dirs=("Source/WTF", "Source/JavaScriptCore", "Source/bmalloc")):
    out = {}
    for d in dirs:
        counts, example = collections.Counter(), {}
        for f in sorted((Path(tree) / d).rglob("*")):
            if f.suffix in SUFFIXES and f.is_file():
                k = classify(f.read_text(errors="replace"))
                counts[k] += 1
                example.setdefault(k, str(f.relative_to(tree)))
        out[d] = {k: {"files": n, "example": example[k]} for k, n in sorted(counts.items(), key=lambda x: -x[1])}
    return out


if __name__ == "__main__":
    print(json.dumps(scan(sys.argv[1] if len(sys.argv) > 1 else "build/upstream/webkit"), indent=1))
