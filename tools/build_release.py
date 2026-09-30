#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a local release of the Windows 98 Shizuku Second Edition VM install ISO.

    python3 tools/build_release.py [--tag TAG] [--skip-tests] [--allow-dirty] [--out DIR]

1. Builds everything from the checked-out commit in the order the ISO builder uses (BUILD_STEPS of
   tools/build_shizuku_se_iso.py, then install/mkpayload.py), with the ISO's fixed SOURCE_DATE_EPOCH:
     shizukudos/csm/build.py
     shizukudos/tools/shz.py build --profile uefi-multikernel     (DOS16, Kernel32/64, Win64, UEFI loader)
     shizukudos/install/mkpayload.py --out build/shizukudos/install-media
     tools/build_shizuku_se_iso.py --reuse-builds                  (packages the outputs above, receipt-checked)
     tools/build_shizuku_se_disk.py
2. Boots them: shizukudos/tools/shz.py test --suite media (QEMU TCG, SeaBIOS and OVMF). The release fails, and no
   release directory is written, unless the verdict is VERIFIED on exactly the ISO and disk bytes just built.
   --skip-tests is an explicit opt-out: it is logged and written into the manifest as "media_suite": "skipped".
3. Writes build/release/windows98-shizuku-second-edition-<commit12>/ (git-ignored, never published):
     windows98-shizuku-second-edition.iso            the ISO
     windows98-shizuku-second-edition.iso.sha256     sha256sum line (sha256sum -c)
     windows98-shizuku-second-edition-disk.img.xz    the raw disk image, xz-compressed (mostly empty 128 MiB)
     windows98-shizuku-second-edition.json           the ISO receipt;  ...-disk.json  the disk receipt
     media-suite-results.json, boot-matrix.json      shz.py media results and the matrix they judged
     release-manifest.json                           tag, commit, sizes, SHA-256, build date, QEMU/OVMF, results

Nothing is uploaded anywhere. The ISO contains no Microsoft files (docs/shizukudos10/RELEASE.md).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shizukudos" / "tools"))
import qemu as qemu_tools  # noqa: E402

BUILD = ROOT / "build"
PRODUCT = "windows98-shizuku-second-edition"
ISO = BUILD / f"{PRODUCT}.iso"
DISK = BUILD / f"{PRODUCT}-disk.img"
RESULTS = BUILD / "shizukudos" / "results" / "media-latest.json"
SOURCE_DATE_EPOCH = "1785283200"   # FIXED_EPOCH of tools/build_shizuku_se_iso.py and tools/shizuku_se_media.py
PY = sys.executable
BUILD_STEPS = (
    [PY, "shizukudos/csm/build.py"],
    [PY, "shizukudos/tools/shz.py", "build", "--profile", "uefi-multikernel"],
    [PY, "shizukudos/install/mkpayload.py", "--out", "build/shizukudos/install-media"],
    [PY, "tools/build_shizuku_se_iso.py", "--reuse-builds"],
    [PY, "tools/build_shizuku_se_disk.py"],
)
TEST_STEP = [PY, "shizukudos/tools/shz.py", "test", "--suite", "media"]


class ReleaseError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[release {time.strftime('%H:%M:%S')}] {message}", flush=True)


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args: str) -> str:
    result = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ""


def first_line(*command: str) -> str | None:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (result.stdout or result.stderr).strip()
    return text.splitlines()[0] if result.returncode == 0 and text else None


def run_step(command: list[str], env: dict[str, str], timeout: int) -> dict:
    shown = " ".join(str(c) for c in command).replace(PY, "python3", 1)
    log(f"$ {shown}")
    started = time.time()
    try:
        subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=timeout)
    except subprocess.CalledProcessError as exc:
        raise ReleaseError(f"step failed (exit {exc.returncode}): {shown}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ReleaseError(f"step timed out after {timeout} s: {shown}") from exc
    seconds = round(time.time() - started, 1)
    log(f"done in {seconds} s: {shown}")
    return {"command": shown, "seconds": seconds}


def asset(file: Path, **extra) -> dict:
    return {"name": file.name, "bytes": file.stat().st_size, "sha256": sha256(file), **extra}


def check_receipt(path: Path, commit: str, allow_dirty: bool) -> dict:
    receipt = json.loads(path.with_suffix(".json").read_text())
    if receipt["sha256"] != sha256(path) or receipt["bytes"] != path.stat().st_size:
        raise ReleaseError(f"{path} does not match its receipt {path.with_suffix('.json')}")
    if receipt.get("private"):
        raise ReleaseError(f"{path} is a private image (built with --win98-media); it is never released")
    if "git" in receipt and receipt["git"]["revision"] != commit:
        raise ReleaseError(f"{path} was built from {receipt['git']['revision']}, not from HEAD {commit}")
    if "git" in receipt and receipt["git"]["dirty"] and not allow_dirty:
        raise ReleaseError(f"{path} was built from a dirty tree")
    return receipt


def media_suite(started_utc: str, iso_sha: str, disk_sha: str) -> tuple[dict, dict, Path]:
    """The results of the media suite run that just finished, checked against the images just built."""
    if not RESULTS.is_file():
        raise ReleaseError(f"the media suite wrote no {RESULTS}")
    results = json.loads(RESULTS.read_text())
    if results.get("suite") != "media" or results.get("utc", "") < started_utc:
        raise ReleaseError(f"{RESULTS} is not from this run (utc {results.get('utc')}, run started {started_utc})")
    evidence = {r["evidence"] for r in results["results"] if r.get("evidence")}
    if len(evidence) != 1:
        raise ReleaseError(f"expected the results of one matrix run, found {sorted(evidence) or 'none'}")
    matrix_path = Path(evidence.pop()) / "matrix.json"
    matrix = json.loads(matrix_path.read_text())
    if (matrix["media"]["iso"]["sha256"], matrix["media"]["disk"]["sha256"]) != (iso_sha, disk_sha):
        raise ReleaseError("the boot matrix did not boot the ISO and disk image that were just built")
    failed = [r["test"] for r in results["results"] if r["status"] != "PASS"]
    if results["verdict"] != "VERIFIED" or failed or not results["counts"].get("PASS"):
        raise ReleaseError(f"media suite verdict {results['verdict']} {results['counts']}; not PASS: {failed}; "
                           f"evidence {matrix_path.parent}")
    return results, matrix, matrix_path


def host_facts(matrix: dict | None) -> dict:
    qemu = shutil.which("qemu-system-x86_64") or qemu_tools.DEFAULT_QEMU
    ovmf = qemu_tools.DEFAULT_OVMF_CODE
    facts = {
        "os": first_line("lsb_release", "-ds") or platform.platform(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "qemu": qemu_tools.qemu_version(qemu) if Path(qemu).exists() else None,
        "qemu_path": qemu,
        "qemu_package": first_line("dpkg-query", "-W", "-f=${Package} ${Version}", "qemu-system-x86"),
        "ovmf_code": ovmf,
        "ovmf_code_sha256": sha256(Path(ovmf)) if Path(ovmf).is_file() else None,
        "ovmf_package": first_line("dpkg-query", "-W", "-f=${Package} ${Version}", "ovmf"),
    }
    if matrix:
        facts["matrix"] = {"qemu": matrix.get("qemu"), "ovmf_code_sha256": matrix.get("ovmf_code_sha256"),
                           "hardware": matrix.get("hardware"), "s3": matrix.get("s3")}
    return facts


def write_xz(source: Path, destination: Path) -> None:
    with open(source, "rb") as src, lzma.open(destination, "wb", preset=9) as dst:
        shutil.copyfileobj(src, dst, 1 << 20)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tag", help="release name for the manifest (default: the tag on HEAD, if any)")
    parser.add_argument("--skip-tests", action="store_true",
                        help="do NOT run the media boot matrix (explicit opt-out; the manifest says \"skipped\")")
    parser.add_argument("--allow-dirty", action="store_true",
                        help="release from a working tree with uncommitted changes (recorded; directory gets -dirty)")
    parser.add_argument("--out", type=Path, default=BUILD / "release", help="parent directory (default build/release)")
    args = parser.parse_args()

    commit = git("rev-parse", "HEAD")
    if not commit:
        print("error: not a git checkout; a release records its commit", file=sys.stderr)
        return 2
    dirty = bool(git("status", "--porcelain"))
    if dirty and not args.allow_dirty:
        print("error: the working tree has uncommitted changes (git status); commit them or pass --allow-dirty",
              file=sys.stderr)
        return 2
    tag = args.tag or git("describe", "--tags", "--exact-match", "HEAD") or None
    out = args.out.resolve()
    release_dir = out / f"{PRODUCT}-{commit[:12]}{'-dirty' if dirty else ''}"
    log(f"commit {commit}{' (dirty)' if dirty else ''}, tag {tag or '-'}, output {release_dir}")
    if args.skip_tests:
        log("WARNING: --skip-tests: the media boot matrix is NOT run; release-manifest.json records "
            "\"media_suite\": \"skipped\"")

    try:
        env = dict(os.environ, SOURCE_DATE_EPOCH=SOURCE_DATE_EPOCH, PYTHONDONTWRITEBYTECODE="1")
        steps = [run_step(command, env, timeout=4 * 3600) for command in BUILD_STEPS]
        iso_receipt = check_receipt(ISO, commit, args.allow_dirty)
        disk_receipt = check_receipt(DISK, commit, args.allow_dirty)   # the disk receipt records no commit:
        if ({i["path"]: i["sha256"] for i in disk_receipt["inputs"]}   # it must be built from the ISO's inputs
                != {i["path"]: i["sha256"] for i in iso_receipt["inputs"]}):
            raise ReleaseError("the raw disk image and the ISO were not built from the same outputs")
        iso_sha, disk_sha = iso_receipt["sha256"], sha256(DISK)
        log(f"ISO {ISO.stat().st_size} bytes, sha256 {iso_sha}")

        results = matrix = matrix_path = None
        if not args.skip_tests:
            started = utc_now()
            test_env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            try:
                steps.append(run_step(TEST_STEP, test_env, timeout=10 * 3600))
            except ReleaseError as exc:   # a FAIL row exits 1: report from the results file below
                log(f"{exc}; reading the results")
            results, matrix, matrix_path = media_suite(started, iso_sha, disk_sha)
            log(f"media suite {results['verdict']} {results['counts']} ({matrix_path.parent})")
    except ReleaseError as exc:
        log(f"RELEASE FAILED: {exc}")
        return 1

    # Everything goes to <dir>.partial first and is renamed at the end: a release directory is always complete.
    final_dir, release_dir = release_dir, release_dir.with_name(release_dir.name + ".partial")
    for stale in (release_dir, final_dir):
        if stale.exists():
            shutil.rmtree(stale)
    release_dir.mkdir(parents=True)
    iso = release_dir / ISO.name
    shutil.copyfile(ISO, iso)
    if sha256(iso) != iso_sha:
        raise SystemExit(f"{iso} differs from {ISO} after copying")
    (release_dir / f"{ISO.name}.sha256").write_text(f"{iso_sha}  {ISO.name}\n")
    for receipt in (ISO.with_suffix(".json"), DISK.with_suffix(".json")):
        shutil.copyfile(receipt, release_dir / receipt.name)
    disk_xz = release_dir / f"{DISK.name}.xz"
    log(f"xz -9 {DISK.name}")
    write_xz(DISK, disk_xz)

    if results is None:
        media = "skipped"
    else:
        shutil.copyfile(RESULTS, release_dir / "media-suite-results.json")
        shutil.copyfile(matrix_path, release_dir / "boot-matrix.json")
        media = {
            **asset(release_dir / "media-suite-results.json"),
            "command": "python3 shizukudos/tools/shz.py test --suite media",
            "utc": results["utc"], "verdict": results["verdict"], "counts": results["counts"],
            "cases": [{"case": r["test"], "status": r["status"], "detail": r.get("detail", "")}
                      for r in results["results"]],
            "boot_matrix": asset(release_dir / "boot-matrix.json", verdict=matrix["verdict"],
                                 evidence=str(matrix_path.parent.relative_to(ROOT))),
        }
    manifest = {
        "schema": 1,
        "product": "Windows 98 Shizuku Second Edition (ShizukuDOS 10) VM install ISO",
        "tag": tag,
        "commit": commit,
        "commit_date": git("log", "-1", "--format=%cI", commit),
        "dirty": dirty,
        "build_date_utc": utc_now(),
        "builder": {"command": "python3 tools/build_release.py " + " ".join(sys.argv[1:]),
                    "source_date_epoch": int(SOURCE_DATE_EPOCH), "steps": steps},
        "iso": asset(iso, sha256_file=f"{ISO.name}.sha256"),
        "iso_receipt": asset(release_dir / ISO.with_suffix(".json").name,
                             path=str(ISO.with_suffix(".json").relative_to(ROOT))),
        "disk_image": asset(disk_xz, compression="xz", uncompressed={
            "name": DISK.name, "bytes": DISK.stat().st_size, "sha256": disk_sha},
            receipt=asset(release_dir / DISK.with_suffix(".json").name)),
        "media_suite": media,
        "host": host_facts(matrix),
        "docs": "docs/shizukudos10/RELEASE.md",
    }
    (release_dir / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    release_dir.rename(final_dir)
    release_dir = final_dir
    log(f"release written: {release_dir}")
    for path in sorted(release_dir.iterdir()):
        print(f"  {path.stat().st_size:>11}  {path.name}")
    print(f"sha256 {iso_sha}  {ISO.name}\nbytes  {(release_dir / ISO.name).stat().st_size}\ncommit {commit}\n"
          f"media  {'SKIPPED (--skip-tests)' if media == 'skipped' else media['verdict'] + ' ' + json.dumps(media['counts'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
