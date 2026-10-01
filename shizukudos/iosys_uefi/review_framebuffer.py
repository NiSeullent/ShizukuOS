#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compare retained firmware-GOP memory with its independently captured screen.

Reads stopped-run evidence only. It does not start a guest or establish Windows
identity, document content, input acceptance, or file-save success by itself.
"""
import argparse
import hashlib
import json
from pathlib import Path


def checked_file(run, record, limit):
    path = Path(record["path"]).resolve(strict=True)
    if not path.is_relative_to(run) or not path.is_file():
        raise ValueError("Evidence path is outside the selected run")
    if not 0 < path.stat().st_size <= limit:
        raise ValueError("Evidence size exceeds its bound")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != record["sha256"]:
        raise ValueError("Evidence digest differs from the retained receipt")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--capture", required=True, type=int)
    args = parser.parse_args()
    run = args.run.resolve(strict=True)
    result_data = (run / "result.json").read_bytes()
    native = json.loads(result_data)
    entry_data = (run / "iosys-entry-result.json").read_bytes()
    entry = json.loads(entry_data)
    if (native.get("qemu_exit_code") != 0 or native.get("runtime_failure")
            or native.get("originals_unchanged") is not True
            or native.get("prepared_source_unchanged") is not True
            or entry.get("status") != "PASS" or not entry.get("checks")
            or not all(value is True for value in entry["checks"].values())
            or Path(entry["native_result"]).resolve() != run / "result.json"):
        raise ValueError("Completed immutable native-entry evidence is required")
    if not 0 <= args.capture < len(native["captures"]):
        parser.error("Capture index is outside the retained run")
    capture = native["captures"][args.capture]
    framebuffer = capture["physical_framebuffer"]
    anchor = capture["firmware_gop_handover"]["persistent_locator"]
    if (framebuffer.get("status") != "captured" or anchor.get("status") != "captured"
            or anchor.get("validation_status") != "PASS"
            or framebuffer["bits_per_pixel"] != 32
            or framebuffer["physical"] != anchor["framebuffer_base"]
            or any(framebuffer[key] != anchor[key] for key in ("width", "height", "pitch"))
            or framebuffer["bytes"] != anchor["visible_bytes"]
            or not 0 < framebuffer["width"] <= 8192
            or not 0 < framebuffer["height"] <= 8192
            or framebuffer["pitch"] < framebuffer["width"] * 4
            or framebuffer["pitch"] * framebuffer["height"] != framebuffer["bytes"]):
        raise ValueError("Framebuffer is not bound to a valid persistent GOP locator")
    memory = checked_file(run, framebuffer, 16 * 1024 * 1024)
    if len(memory) != framebuffer["bytes"]:
        raise ValueError("Framebuffer capture length differs from its receipt")
    screenshot = checked_file(run, {"path": capture["screenshot"], "sha256": capture["sha256"]}, 16 * 1024 * 1024)
    from io import BytesIO
    from PIL import Image, ImageChops
    size = framebuffer["width"], framebuffer["height"]
    decoded = Image.frombytes("RGB", size, memory, "raw", "BGRX", framebuffer["pitch"])
    with Image.open(BytesIO(screenshot)) as screen:
        if screen.size != size:
            raise ValueError("Screen resolution differs from firmware-GOP geometry")
        difference = ImageChops.difference(decoded, screen.convert("RGB"))
    pixels = size[0] * size[1]
    # Count RGB pixels with any nonzero component, without conflating channels.
    changed = sum(any(value) for value in zip(*[iter(difference.tobytes())] * 3))
    output = run / f"screen-{args.capture:03d}-gop-review.json"
    png = run / f"screen-{args.capture:03d}-physical-gop.png"
    if output.exists() or png.exists():
        raise ValueError("Review output already exists")
    evidence = {
        "profile": "retained-iosys-gop-screen-comparison", "capture": args.capture,
        "native_result_sha256": hashlib.sha256(result_data).hexdigest(),
        "iosys_entry_result_sha256": hashlib.sha256(entry_data).hexdigest(),
        "physical_framebuffer": framebuffer, "screen_sha256": capture["sha256"],
        "pixels": pixels, "changed_pixels": changed,
        "matching_fraction": (pixels - changed) / pixels,
        "difference_box": difference.getbbox(), "decoded_png": str(png),
        "comparison": "exact" if changed == 0 else "different",
        "sampling": "sequential live samples; differences are reported without an inferred cause",
        "native_gui_result": native.get("status"),
        "file_save_result": native.get("gui_interaction", {}).get("file_readback", {}).get("status"),
        "scope": "memory-to-screen correspondence only; Windows/app acceptance requires visual review",
    }
    with png.open("xb") as stream:
        decoded.save(stream, format="PNG")
    evidence["decoded_png_sha256"] = hashlib.sha256(png.read_bytes()).hexdigest()
    with output.open("x") as stream:
        json.dump(evidence, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"receipt": str(output), "changed_pixels": changed, "pixels": pixels}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
