#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Acquire immutable official Korean font bytes for a private DWrite trial.

No font is installed or registered. Assets stay outside Git in a fresh build
directory. Publisher Git blob identities, full local SHA-256 hashes, OFL notice
and independent cmap/design metrics are retained for actual guest acceptance.
"""
import argparse
import hashlib
import importlib.util
from io import BytesIO
import json
from pathlib import Path
import shutil
from urllib.request import Request, urlopen

from fontTools.ttLib import TTFont

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "f8d157532fbfaeda587e826d4cd5b21a49186f7c"
REPOSITORY = "https://github.com/notofonts/noto-cjk"
RAW = "https://raw.githubusercontent.com/notofonts/noto-cjk/" + COMMIT + "/"
ASSETS = (
    ("Sans/OTF/Korean/NotoSansCJKkr-Regular.otf", 16433112,
     "dc4a7c65e6f450bf17c10a2405250b620eb78703"),
    ("Sans/LICENSE", 4301, "d952d62c065f3f35fb83a173496e90b21525aef3"),
    ("Sans/README.md", 10976, "449c31d5774c4387663614096f9fd399a0ffc808"),
)
RESERVE = 20 * 1024**3


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def font_profile(data):
    with TTFont(BytesIO(data), lazy=False) as font:
        cmap = font.getBestCmap()
        names = font["name"].names
        def name(identifier):
            return next((n.toUnicode() for n in names if n.nameID == identifier), None)
        metrics = []
        for character in "AB\uac00\ud55c\uae00\ud604\ub300\ubaa8\ub358":
            glyph = cmap.get(ord(character))
            item = {"character": character, "codepoint": ord(character),
                    "glyph_id": font.getGlyphID(glyph) if glyph else 0}
            if glyph:
                advance, bearing = font["hmtx"].metrics[glyph]
                item.update(advance_width=advance, left_side_bearing=bearing)
            metrics.append(item)
        return {"family": name(1), "version": name(5),
                "units_per_em": font["head"].unitsPerEm,
                "glyph_count": font["maxp"].numGlyphs,
                "hangul_syllables": sum(code in cmap for code in range(0xac00, 0xd7a4)),
                "design_metrics": metrics}


def acquire(output, baseline):
    spec = importlib.util.spec_from_file_location("font_baseline_overlay", ROOT / "tools/required_theme_runtime.py")
    theme = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(theme)
    output = theme.owned_new_directory(output)
    require(output.is_relative_to(ROOT / "build"), "Fresh own ignored output required")
    require(shutil.disk_usage(ROOT).free >= RESERVE + 32 * 1024**2, "Unchanged 20-GiB reserve")
    overlay = theme.verified_overlay(baseline)
    archive = Path(overlay["archive"]["path"])
    original_fonts = []
    for path, data in theme.parse_archive(archive.read_bytes()):
        if path.lower().endswith((".ttf", ".otf")):
            original_fonts.append({"path": path, "sha256": digest(data),
                                   "bytes": len(data), "profile": font_profile(data)})
    output.mkdir(mode=0o700)
    receipt = {"schema": 1, "status": "FAIL", "repository": REPOSITORY,
               "publisher_commit": COMMIT, "license": "OFL-1.1",
               "recipe_sha256": digest(Path(__file__).read_bytes()),
               "baseline_overlay": {"path": str(baseline), "sha256": digest(baseline.read_bytes())},
               "baseline_archive_sha256": digest(archive.read_bytes()),
               "baseline_fonts": original_fonts, "assets": [],
               "reserve_bytes": RESERVE, "fonts_installed": False,
               "fonts_registered": False, "guest_execution_verified": False,
               "korean_directwrite_rendering_verified": False}
    try:
        for path, size, blob in ASSETS:
            require(shutil.disk_usage(ROOT).free >= RESERVE + size, "Font download reserve")
            url = RAW + path
            with urlopen(Request(url, headers={"User-Agent": "Win98-Modern-font-corpus"}), timeout=20) as response:
                data = response.read(size + 1)
            require(len(data) == size, "Publisher asset size mismatch")
            actual_blob = hashlib.sha1(b"blob " + str(size).encode("ascii") + b"\0" + data).hexdigest()
            require(actual_blob == blob, "Publisher Git blob mismatch")
            destination = output / Path(path).name
            with destination.open("xb") as stream:
                stream.write(data)
            destination.chmod(0o400)
            receipt["assets"].append({"publisher_path": path, "url": url,
                                      "git_blob_sha1": blob, "bytes": size,
                                      "sha256": digest(data), "path": str(destination)})
        license_text = (output / "LICENSE").read_text()
        require("SIL OPEN FONT LICENSE Version 1.1" in license_text, "Pinned OFL notice required")
        profile = font_profile((output / "NotoSansCJKkr-Regular.otf").read_bytes())
        require(profile["family"] == "Noto Sans CJK KR" and profile["hangul_syllables"] == 11172,
                "Complete actual Korean syllable cmap required")
        require(all(row["glyph_id"] for row in profile["design_metrics"]), "Real Korean/Latin glyphs required")
        require(theme.verified_overlay(baseline) == overlay, "Original runtime changed")
        require(digest(Path(__file__).read_bytes()) == receipt["recipe_sha256"], "Font recipe changed")
        require(shutil.disk_usage(ROOT).free >= RESERVE, "Final unchanged reserve")
        receipt.update(status="PASS", font_profile=profile,
                       scope="Publisher bytes and independent font-table corpus only; actual DWrite guest render remains required")
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        (output / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--baseline-overlay", type=Path, required=True)
    args = parser.parse_args()
    result = acquire(args.out, args.baseline_overlay.resolve(strict=True))
    print(json.dumps({"status": result["status"], "font_profile": result["font_profile"],
                      "receipt": str(args.out / "receipt.json")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
