#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""ShizukuFS v1 crash-consistency test.

A deterministic workload (`sfstool crashload`: rounds of creates, appends, overwrites, truncates, unlinks, renames
over files, mkdir/rmdir, each round ended by sfs_sync() and logged) runs against an ext4 image and is interrupted:

  kill   the writer process is SIGKILLed at a random moment (every write it issued has reached the image file,
         nothing after it has) -- "kill the writer mid-transaction";
  cut    a simulated power cut: the host device holds writes in a volatile cache until each flush, and after a
         random number of writes applies only a random subset of the unflushed ones (reordering/loss) and exits.

Each interrupted image is then checked two ways:
  e2fsck   `e2fsck -fy` (replays the journal, processes orphans) must find nothing else to fix, `e2fsck -fn`
           afterwards must exit 0, and `sfstool crashverify` must find every file synced before the crash intact
           and every later-touched file made only of blocks from its own history (no stale/foreign data);
  libsfs   libsfs mounts the image read-write (its own jbd2 replay + orphan cleanup), `crashverify` must pass,
           and `e2fsck -fn` on the result must exit 0 with no problems.
Usage: run_crash.py [--trials N] [--mode kill|cut|both] [--seed S] [--mkfs "-b 1024 ..."] | --orphan
"""
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "build", "sfstool")

ALLOWED_FSCK = [
    r"^e2fsck \d", r"^Pass \d", r": recovering journal$", r"^Clearing orphaned inode", r"^Truncating orphaned inode",
    r"^\s*$", r"FILE SYSTEM WAS MODIFIED", r"^\S+: \d+/\d+ files", r"^Journal transaction \d+ was corrupt, replay was aborted\.$",
    # e2fsck's own orphan truncation (ext2fs_punch) leaves a small depth-1 tree it then offers to collapse
    r"extent tree \(at level \d+\) could be (shorter|narrower)\.  Optimize\? yes$", r"^Pass 1E: Optimizing extent trees$",
]


def run(cmd, **kw):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kw)


def problems(output):
    bad = []
    for line in output.splitlines():
        if not any(re.search(p, line) for p in ALLOWED_FSCK):
            bad.append(line)
    return bad


def verify(img, log, seed, tmp, tag):
    errs = []
    info = {}
    # path 1: e2fsprogs recovers
    a = os.path.join(tmp, "a.img")
    subprocess.run(["cp", "--sparse=always", img, a], check=True)
    p = run(["e2fsck", "-fy", a])
    info["e2fsck_fy_rc"] = p.returncode
    info["recovered_by_e2fsck"] = "recovering journal" in p.stdout
    info["orphans_e2fsck"] = len(re.findall(r"orphaned inode", p.stdout))
    bad = problems(p.stdout + p.stderr)
    if p.returncode not in (0, 1) or bad:
        errs.append("%s: e2fsck -fy rc=%d problems: %s" % (tag, p.returncode, bad[:12]))
    p = run(["e2fsck", "-fn", a])
    if p.returncode != 0:
        errs.append("%s: e2fsck -fn after -fy rc=%d: %s" % (tag, p.returncode, p.stdout[-800:]))
    p = run([TOOL, "-q", "-r", a, "crashverify", log, str(seed)])
    info["verify_e2fsck"] = p.stdout.strip()
    if p.returncode != 0:
        errs.append("%s: crashverify after e2fsck: %s %s" % (tag, p.stdout.strip(), p.stderr[-1500:]))
    # path 2: libsfs recovers
    b = os.path.join(tmp, "b.img")
    subprocess.run(["cp", "--sparse=always", img, b], check=True)
    p = run([TOOL, b, "crashverify", log, str(seed)])
    info["verify_libsfs"] = p.stdout.strip()
    info["libsfs_log"] = " | ".join(l for l in p.stderr.splitlines() if "replayed" in l or "orphan" in l)[:200]
    if p.returncode != 0:
        errs.append("%s: libsfs replay + crashverify: %s %s" % (tag, p.stdout.strip(), p.stderr[-1500:]))
    p = run(["e2fsck", "-fn", b])
    info["e2fsck_after_libsfs"] = p.returncode
    bad = problems(p.stdout + p.stderr)
    if p.returncode != 0 or bad:
        errs.append("%s: e2fsck -fn after libsfs recovery rc=%d: %s" % (tag, p.returncode, bad[:12]))
    os.unlink(a)
    os.unlink(b)
    return errs, info


def orphan_sweep(tmp):
    """Multi-step unlink / truncate of a 20 MB file on a volume with 256-block groups, mounted with small
    transactions (SFS_MOUNT_SMALL_TXN) so the operation commits mid-way with the inode on the orphan list; a crash
    after every k-th device write. e2fsck must finish the orphan (and nothing else), libsfs must finish it at mount,
    and the file must end up either untouched or completely deleted / truncated."""
    base = os.path.join(tmp, "orph.img")
    subprocess.run(["mkfs.ext4", "-q", "-F", "-b", "1024", "-g", "256", base, "64M"], check=True, capture_output=True)
    subprocess.run([TOOL, "-q", base, "pattern", "/big", "0", "20000000", "1"], check=True, capture_output=True)
    full = run([TOOL, "-q", "-r", base, "tree"]).stdout.split()[4]
    fails, orphans_e2fsck, orphans_libsfs, cases = 0, 0, 0, 0
    for op in (["rm", "/big"], ["truncate", "/big", "1000"]):
        for k in list(range(10, 400, 13)):
            img = os.path.join(tmp, "o.img")
            subprocess.run(["cp", "--sparse=always", base, img], check=True)
            run([TOOL, "-q", "-s", "-K", str(k), img] + op)
            a, b = img + ".a", img + ".b"
            subprocess.run(["cp", "--sparse=always", img, a], check=True)
            subprocess.run(["cp", "--sparse=always", img, b], check=True)
            p = run(["e2fsck", "-fy", a])
            orphans_e2fsck += p.stdout.count("orphaned inode")
            bad = problems(p.stdout + p.stderr)
            q = run(["e2fsck", "-fn", a])
            r = run([TOOL, b, "stats"])
            orphans_libsfs += r.stderr.count("orphan inode")
            t = run(["e2fsck", "-fn", b])
            tree = run([TOOL, "-q", "-r", b, "tree"]).stdout.split()
            state = "absent" if "/big" not in tree else ("full" if tree[4] == full else "size %s" % tree[2])
            ok_state = state in ("absent", "full") if op[0] == "rm" else state in ("full", "size 1000")
            cases += 1
            if bad or q.returncode or r.returncode or t.returncode or not ok_state:
                fails += 1
                print("  orphan %s cut@%d: e2fsck problems %s, -fn %d; libsfs rc %d, -fn %d; file %s" % (
                    op[0], k, bad[:4], q.returncode, r.returncode, t.returncode, state))
    print("orphan sweep: %d/%d crash points passed (e2fsck processed %d orphans, libsfs %d)" % (
        cases - fails, cases, orphans_e2fsck, orphans_libsfs))
    return fails


def main():
    trials = int(sys.argv[sys.argv.index("--trials") + 1]) if "--trials" in sys.argv else 10
    if "--orphan" in sys.argv:
        tmp = tempfile.mkdtemp(prefix="sfsorphan-", dir=os.environ.get("SFS_TMP"))
        try:
            return 1 if orphan_sweep(tmp) else 0
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    mode = sys.argv[sys.argv.index("--mode") + 1] if "--mode" in sys.argv else "both"
    base_seed = int(sys.argv[sys.argv.index("--seed") + 1]) if "--seed" in sys.argv else 1
    rng = random.Random(base_seed)
    tmp = tempfile.mkdtemp(prefix="sfscrash-", dir=os.environ.get("SFS_TMP"))
    base = os.path.join(tmp, "base.img")
    mkfs_opts = sys.argv[sys.argv.index("--mkfs") + 1].split() if "--mkfs" in sys.argv else []
    subprocess.run(["mkfs.ext4", "-q", "-F"] + mkfs_opts + [base, "256M"], check=True)
    failures = 0
    summary = {"kill": 0, "cut": 0, "replayed_by_e2fsck": 0, "orphans": 0}
    try:
        modes = ["kill", "cut"] if mode == "both" else [mode]
        for t in range(trials):
            m = modes[t % len(modes)]
            seed = base_seed * 1000 + t
            img = os.path.join(tmp, "img")
            log = os.path.join(tmp, "log")
            subprocess.run(["cp", "--sparse=always", base, img], check=True)
            if os.path.exists(log):
                os.unlink(log)
            if m == "kill":
                pr = subprocess.Popen([TOOL, "-q", img, "crashload", log, str(seed), "0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                delay = rng.uniform(1.0, 6.0)
                time.sleep(delay)
                pr.send_signal(signal.SIGKILL)
                pr.communicate()
                how = "SIGKILL after %.2fs" % delay
            else:
                n = rng.randint(300, 40000)
                p = run([TOOL, "-q", "-V", "-K", str(n), "-S", str(seed), img, "crashload", log, str(seed), "0"])
                how = "power cut after %d writes (exit %d)" % (n, p.returncode)
                if p.returncode != 77:
                    print("  trial %d: workload ended without reaching the cut (rc=%d) %s" % (t, p.returncode, p.stderr[-300:]))
            syncs = sum(1 for l in open(log) if l.startswith("SYNC")) if os.path.exists(log) else 0
            errs, info = verify(img, log, seed, tmp, "trial %d (%s)" % (t, m))
            summary[m] += 1
            summary["replayed_by_e2fsck"] += 1 if info.get("recovered_by_e2fsck") else 0
            summary["orphans"] += info.get("orphans_e2fsck", 0)
            status = "PASS" if not errs else "FAIL"
            failures += 1 if errs else 0
            print("trial %2d %-4s %s: %s, %d syncs logged; e2fsck -fy rc %s%s; %s; libsfs: %s" % (
                t, m, status, how, syncs, info.get("e2fsck_fy_rc"), " (journal replayed)" if info.get("recovered_by_e2fsck") else "",
                info.get("verify_e2fsck"), info.get("verify_libsfs")))
            for e in errs:
                print("    " + e)
            sys.stdout.flush()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("crash test: %d/%d trials passed (kill %d, power-cut %d; e2fsck replayed the journal in %d; orphans processed %d)" % (
        trials - failures, trials, summary["kill"], summary["cut"], summary["replayed_by_e2fsck"], summary["orphans"]))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
