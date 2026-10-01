# SPDX-License-Identifier: GPL-2.0-only
"""Private checkpoint host fixtures: real QMP Unix peer/files/leases, no VM."""
import contextlib
import ctypes
import dataclasses
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
NATIVE = ROOT / "shizukudos/supervisor/native_win98"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = load("private_checkpoint_tests", NATIVE / "private_checkpoint.py")
info_module = load("checkpoint_actual_info", ROOT / "shizukudos/tools/shzinfo.py")
owned = load("checkpoint_actual_qmp", NATIVE / "owned_capture.py")
guards = load("checkpoint_actual_leases", NATIVE / "build.py")


def info_bytes(disk_bytes=2 << 30):
    info = info_module.Info()
    info.magic = 0x3031505553485A53
    info.version = 3
    info.size = ctypes.sizeof(info_module.Info)
    info.loader_flags = 1
    info.boot_path = 1
    info.region_base = 0x04000000
    info.region_size = 0x01000000
    info.guest_ram_base = 0x08000000
    info.guest_ram_size = 128 << 20
    info.disk_base = 0x100000000
    info.disk_size = disk_bytes
    info.k32_ram_base = 0x10000000
    info.k32_ram_size = 32 << 20
    info.k64_ram_base = 0x12000000
    info.k64_ram_size = 64 << 20
    info.ipc_base = 0x16000000
    info.ipc_size = 4 << 20
    info.memmap_base = 0x17000000
    info.memmap_bytes = 48
    info.memmap_desc_size = 48
    info.blobs[0].name = b"SEABIOS.BIN"
    info.blobs[0].base = 0x18000000
    info.blobs[0].size = 256 << 10
    info.stage = 5
    info.cap_bits = 1 << 16
    info.hv_instance_id = 987654321
    info.domain_generation = 1
    info.domains[5].kind = 3
    info.domains[5].state = 1
    info.domains[5].generation = 1
    return info, bytes(info).ljust(8192, b"\0")


def descriptor(base, pages, kind=2):
    return struct.pack("<IIQQQQ", kind, 0, base, 0, pages, 8).ljust(48, b"\0")


def process_identity(pid):
    text = Path("/proc/%d/stat" % pid).read_text()
    start = int(text[text.rfind(")") + 2:].split()[19])
    return {"pid": pid, "starttime": start,
            "cmdline_sha256": hashlib.sha256(Path("/proc/%d/cmdline" % pid).read_bytes()).hexdigest(),
            "qmp_peer_pid": pid, "qmp_peer_uid": os.getuid()}


@contextlib.contextmanager
def qmp_model(directory, raw, disk, mode="valid"):
    """Real owned child and QMP protocol, with explicitly synthetic physical RAM."""
    path = directory / "qmp.sock"
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read)
        try:
            info = info_module.Info.parse(raw)
            memory_map = descriptor(info.disk_base, len(disk) // 4096)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                listener.listen(1)
                os.write(write, b"R")
                os.close(write)
                conn, _ = listener.accept()
                with conn, conn.makefile("rb") as stream:
                    conn.sendall(b'{"QMP":{}}\n')
                    paused = False
                    disk_calls = 0
                    for line in stream:
                        request = json.loads(line)
                        command = request["execute"]
                        args = request.get("arguments", {})
                        result = {}
                        if command == "qmp_capabilities":
                            pass
                        elif command == "stop":
                            if mode == "stop_error":
                                conn.sendall((json.dumps({"id": request["id"], "error": {"class": "GenericError"}}) + "\n").encode())
                                continue
                            paused = True
                        elif command == "query-status":
                            running = mode == "running" or (mode == "resumed" and disk_calls > 0)
                            result = {"running": running, "status": "running" if running else "paused"}
                        elif command == "pmemsave":
                            if not paused:
                                raise RuntimeError("physical dump before stop")
                            address, size = args["val"], args["size"]
                            if address == 0x04000000:
                                data = raw
                                if mode == "info_changed" and disk_calls:
                                    data = bytearray(raw)
                                    data[info_module.Info.hv_instance_id.offset] ^= 1
                                    data = bytes(data)
                            elif address == info.memmap_base:
                                data = memory_map
                                if mode == "map_ro":
                                    data = descriptor(info.disk_base, len(disk) // 4096, 7)
                            elif info.disk_base <= address < info.disk_base + len(disk):
                                disk_calls += 1
                                offset = address - info.disk_base
                                data = disk[offset:offset + size]
                                if mode == "short":
                                    data = data[:-1]
                                if mode == "disconnect":
                                    break
                            else:
                                raise RuntimeError("unbounded modeled physical request")
                            if mode != "short" and len(data) != size:
                                raise RuntimeError("wrong modeled physical extent")
                            with open(args["filename"], "wb") as output:
                                output.write(data)
                        else:
                            raise RuntimeError("unsupported modeled QMP command")
                        conn.sendall((json.dumps({"id": request["id"], "return": result}) + "\n").encode())
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            os._exit(0)
    os.close(write)
    try:
        if os.read(read, 1) != b"R":
            raise RuntimeError("modeled QMP peer did not become ready")
        qmp = owned.OwnedQMP(path, pid, time.monotonic() + 15)
        try:
            yield qmp, pid
        finally:
            qmp.close()
    finally:
        os.close(read)
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)


class InfoControls(unittest.TestCase):
    ranges = ((0x100000, 0x80000000), (0x100000000, 0x180000000))

    def validate(self, info):
        return m.validate_info(bytes(info).ljust(8192, b"\0"), info_module,
                               ctypes.sizeof(info_module.Info), self.ranges)

    def test_real_c_layout_and_high_ram_disk_is_valid(self):
        self.assertEqual(info_module.selfcheck(ROOT), ctypes.sizeof(info_module.Info))
        info, _ = info_bytes()
        self.assertEqual(self.validate(info).disk_base, 0x100000000)

    def test_total_ram_is_not_a_pci_hole_or_span_bound(self):
        for address in (0x80000000, 0x40000000, 0xfffffffffffff000):
            with self.subTest(address=address), self.assertRaises(ValueError):
                info, _ = info_bytes()
                info.disk_base = address
                self.validate(info)

    def test_wrong_signature_layout_native_domain_or_geometry_is_refused(self):
        for field, value in (("magic", 0), ("version", 2), ("size", 1), ("loader_flags", 3),
                             ("boot_path", 2), ("disk_size", (2 << 30) - 512),
                             ("guest_ram_size", 64 << 20), ("hv_instance_id", 0),
                             ("region_size", 4096), ("stage", 0xdead), ("cap_bits", 0)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                info, _ = info_bytes()
                setattr(info, field, value)
                self.validate(info)
        for field, value in (("kind", 0), ("generation", 0), ("state", 4)):
            with self.subTest(domain_field=field), self.assertRaises(ValueError):
                info, _ = info_bytes()
                setattr(info.domains[5], field, value)
                self.validate(info)

    def test_disk_cannot_overlap_other_loader_regions(self):
        info, _ = info_bytes()
        info.guest_ram_base = info.disk_base
        with self.assertRaises(ValueError):
            self.validate(info)

    def test_loader_map_must_cover_complete_disk_as_loader_data(self):
        good = descriptor(0x100000000, 524288)
        m.validate_loader_map(good, 48, 0x100000000, 2 << 30)
        for raw in (good[:-1], descriptor(0x100000000, 524287),
                    descriptor(0x100000000, 524288, 7), good + good):
            with self.subTest(raw_bytes=len(raw)), self.assertRaises(ValueError):
                m.validate_loader_map(raw, 48, 0x100000000, 2 << 30)


class ProducerControls(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, mode="valid"):
        with tempfile.TemporaryDirectory(prefix="checkpoint-host-") as temporary:
            base = Path(temporary)
            lane = base / "lane"
            lane.mkdir(mode=0o700)
            info, raw = info_bytes(8192)
            disk = bytes(range(256)) * 32
            sources = base / "sources"
            sources.mkdir(mode=0o700)
            refs = {name: name for name in ("controller", "qemu", "ram_observation", "info_header",
                                          "info_parser", "layout_receipt", "budget", "checkpoint_helper")}
            real_paths = {"info_header": ROOT / "shizukudos/supervisor/include/shz_info.h",
                          "info_parser": Path(info_module.__file__), "checkpoint_helper": Path(m.__file__)}
            pins = []
            with qmp_model(base, raw, disk, mode) as (qmp, pid), contextlib.ExitStack() as stack:
                for name in refs:
                    path = real_paths.get(name, sources / name)
                    if name not in real_paths:
                        path.write_bytes(("explicit HOST MODEL reference " + name).encode())
                        path.chmod(0o600)
                    digest = hashlib.sha256(path.read_bytes()).hexdigest()
                    fd, checkpoint = stack.enter_context(guards.read_leased(path, digest, path.stat().st_size))
                    pins.append(m.ReadLease(name, path, fd, digest, path.stat().st_size, checkpoint))
                identity = process_identity(pid)

                def assert_owned():
                    credentials = struct.unpack("3i", qmp.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    current = process_identity(pid)
                    if credentials[:2] != (pid, os.getuid()) or current != identity:
                        raise RuntimeError("owned model process/socket changed")
                    return current

                ram = {"ranges": ((0x100000, 0x80000000), (0x100000000, 0x180000000)),
                       "source_ref": "ram_observation", "qemu_ref": "qemu"}
                adapter = m.ControllerAdapter(qmp.call, assert_owned, lambda: ram, identity,
                                               tuple(pins), refs, info_module, ctypes.sizeof(info_module.Info))
                reservation = m.Reservation(lane, "budget", 8192, (4 << 20), 8192 + (4 << 20), 17 << 30)
                # Only geometry/capacity policy is reduced for bounded HOST MODEL tests.
                with patch.object(m, "DISK_BYTES", 8192), patch.object(m, "CHUNK_BYTES", 4096), \
                     patch.object(m, "NAS_WORKSPACE", base), \
                     patch.object(m.shutil, "disk_usage", return_value=type("Usage", (), {"free": 40 << 30})()):
                    yield base, lane, adapter, reservation, disk

    def assert_unaccepted(self, out):
        self.assertFalse((out / "checkpoint.json").exists())

    def test_owned_paused_capture_readback_and_private_receipt_are_real(self):
        with self.fixture() as (_, lane, adapter, reservation, disk):
            out = lane / "first"
            result = m.capture_private_checkpoint(adapter, reservation, out)
            self.assertEqual((out / "checkpoint.raw").read_bytes(), disk)
            self.assertEqual(result["disk"]["sha256"], hashlib.sha256(disk).hexdigest())
            self.assertEqual(result["disk"]["bytes"], 8192)
            self.assertEqual((out / "checkpoint.raw").stat().st_mode & 0o777, 0o600)
            self.assertEqual(out.stat().st_mode & 0o777, 0o700)
            self.assertEqual(json.loads((out / "checkpoint.json").read_text()), result)
            self.assertTrue(result["source_before_after_match"])
            for name in ("Windows98_boot_verified", "clean_shutdown_verified", "cold_boot_persistence_verified",
                         "live_storage_flush_verified", "controller_adapter_runtime_integration", "VM_verified"):
                self.assertIs(result[name], False)

    def test_running_stop_error_short_dump_changed_info_map_and_peer_loss_refuse(self):
        for mode in ("running", "resumed", "stop_error", "short", "info_changed", "map_ro", "disconnect"):
            with self.subTest(mode=mode), self.fixture(mode) as (_, lane, adapter, reservation, _):
                out = lane / "failed"
                with self.assertRaises((RuntimeError, ValueError, OSError)):
                    m.capture_private_checkpoint(adapter, reservation, out)
                self.assert_unaccepted(out)

    def test_existing_output_and_symlink_parent_are_never_overwritten(self):
        with self.fixture() as (base, lane, adapter, reservation, _):
            out = lane / "old"
            out.mkdir()
            (out / "sentinel").write_bytes(b"retain")
            with self.assertRaises((ValueError, FileExistsError)):
                m.capture_private_checkpoint(adapter, reservation, out)
            self.assertEqual((out / "sentinel").read_bytes(), b"retain")
            link = base / "link"
            link.symlink_to(lane, target_is_directory=True)
            with self.assertRaises(ValueError):
                m.capture_private_checkpoint(adapter, reservation, link / "new")

    def test_source_lease_loss_and_source_hash_mismatch_refuse(self):
        with self.fixture() as (_, lane, adapter, reservation, _):
            original = adapter.sources[0]
            bad = dataclasses.replace(original, sha256="0" * 64)
            changed = dataclasses.replace(adapter, sources=(bad,) + adapter.sources[1:])
            with self.assertRaises((ValueError, RuntimeError)):
                m.capture_private_checkpoint(changed, reservation, lane / "bad-sha")
            fcntl.fcntl(original.fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
            try:
                with self.assertRaises(RuntimeError):
                    m.capture_private_checkpoint(adapter, reservation, lane / "lost-lease")
            finally:
                fcntl.fcntl(original.fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)

    def test_owner_identity_drift_refuses_after_real_chunk_without_receipt(self):
        with self.fixture() as (_, lane, adapter, reservation, _):
            actual = adapter.call

            def call(command, arguments=None):
                answer = actual(command, arguments)
                if command == "pmemsave" and arguments["val"] >= 0x100000000:
                    adapter.owner["starttime"] += 1
                return answer

            changed = dataclasses.replace(adapter, call=call)
            out = lane / "identity-drift"
            with self.assertRaises(RuntimeError):
                m.capture_private_checkpoint(changed, reservation, out)
            self.assert_unaccepted(out)

    def test_corrupt_output_readback_and_fsync_failure_cannot_publish_success(self):
        for failure in ("readback", "fsync"):
            with self.subTest(failure=failure), self.fixture() as (_, lane, adapter, reservation, _):
                out = lane / failure
                if failure == "fsync":
                    setting = patch.object(m.os, "fsync", side_effect=OSError(errno.EIO, "modeled fsync failure"))
                    changed = adapter
                else:
                    actual = adapter.call

                    def corrupt(command, arguments=None):
                        answer = actual(command, arguments)
                        if command == "pmemsave" and arguments["val"] == 0x100001000:
                            with (out / "checkpoint.raw.partial").open("r+b") as data:
                                data.write(b"wrong independent bytes")
                        return answer

                    changed = dataclasses.replace(adapter, call=corrupt)
                    setting = contextlib.nullcontext()
                with setting, self.assertRaises((RuntimeError, OSError)):
                    m.capture_private_checkpoint(changed, reservation, out)
                self.assert_unaccepted(out)

    def test_post_readback_change_and_last_receipt_directory_fsync_refuse(self):
        for failure in ("late-change", "receipt-directory-fsync"):
            with self.subTest(failure=failure), self.fixture() as (_, lane, adapter, reservation, _):
                out = lane / failure
                actual_call = adapter.call

                def late_change(command, arguments=None):
                    answer = actual_call(command, arguments)
                    if command == "pmemsave" and arguments["filename"].endswith("info-after.bin"):
                        with (out / "checkpoint.raw.partial").open("r+b") as disk:
                            disk.write(b"changed after readback")
                    return answer

                actual_fsync = m.os.fsync

                def receipt_fsync(fd):
                    if os.path.isdir("/proc/self/fd/%d" % fd) and (out / "checkpoint.json").exists():
                        raise OSError(errno.EIO, "modeled final receipt directory fsync failure")
                    return actual_fsync(fd)

                changed = dataclasses.replace(adapter, call=late_change) if failure == "late-change" else adapter
                setting = patch.object(m.os, "fsync", side_effect=receipt_fsync) if failure != "late-change" else contextlib.nullcontext()
                with setting, self.assertRaises((RuntimeError, OSError)):
                    m.capture_private_checkpoint(changed, reservation, out)
                self.assert_unaccepted(out)

    def test_existing_disk_checkpoint_is_retained_if_it_appears_before_publication(self):
        with self.fixture() as (_, lane, adapter, reservation, _):
            out = lane / "publication-race"
            actual = adapter.call

            def conflict(command, arguments=None):
                answer = actual(command, arguments)
                if command == "pmemsave" and arguments["val"] == 0x100000000:
                    (out / "checkpoint.raw").write_bytes(b"retained existing private disk")
                return answer

            changed = dataclasses.replace(adapter, call=conflict)
            with self.assertRaises(FileExistsError):
                m.capture_private_checkpoint(changed, reservation, out)
            self.assertEqual((out / "checkpoint.raw").read_bytes(), b"retained existing private disk")
            self.assert_unaccepted(out)

    def test_raw_publication_replacement_or_lease_break_cannot_get_receipt(self):
        for failure in ("replacement", "writer"):
            with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                with self.fixture() as (_, lane, adapter, reservation, disk):
                    out = lane / failure
                    original = m._publish_receipt
                    source_handler = signal.getsignal(signal.SIGIO)

                    def tamper(directory, record, guard):
                        raw = out / "checkpoint.raw"
                        if failure == "replacement":
                            raw.unlink()
                            raw.write_bytes(b"X" * len(disk))
                            raw.chmod(0o600)
                        else:
                            try:
                                fd = os.open(raw, os.O_WRONLY | os.O_NONBLOCK)
                            except OSError as error:
                                if error.errno != errno.EAGAIN:
                                    raise
                            else:
                                try:
                                    os.write(fd, b"X" * len(disk))
                                finally:
                                    os.close(fd)
                        return original(directory, record, guard)

                    try:
                        with patch.object(m, "_publish_receipt", side_effect=tamper):
                            m.capture_private_checkpoint(adapter, reservation, out)
                    finally:
                        self.assert_unaccepted(out)
                        self.assertIs(signal.getsignal(signal.SIGIO), source_handler)

    def test_receipt_partial_replacement_is_refused_before_success(self):
        with self.fixture() as (_, lane, adapter, reservation, _):
            out = lane / "receipt-replacement"
            owned_check = adapter.assert_owned
            replaced = False

            def replace_receipt():
                nonlocal replaced
                partial = out / "checkpoint.json.partial"
                if partial.exists() and not replaced:
                    payload = partial.read_bytes().replace(b"PASS_PRIVATE", b"FAIL_PRIVATE")
                    partial.unlink()
                    partial.write_bytes(payload)
                    partial.chmod(0o600)
                    replaced = True
                return owned_check()

            changed = dataclasses.replace(adapter, assert_owned=replace_receipt)
            with self.assertRaises(RuntimeError):
                m.capture_private_checkpoint(changed, reservation, out)
            self.assertTrue(replaced)
            self.assert_unaccepted(out)

    def test_receipt_writer_break_request_fails_and_restores_source_handler(self):
        for name in ("checkpoint.json.partial", "checkpoint.json"):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                with self.fixture() as (_, lane, adapter, reservation, _):
                    out = lane / "receipt-writer"
                    owned_check = adapter.assert_owned
                    source_handler = signal.getsignal(signal.SIGIO)
                    attempted = False

                    def writer():
                        nonlocal attempted
                        target = out / name
                        if target.exists() and not attempted:
                            attempted = True
                            try:
                                fd = os.open(target, os.O_WRONLY | os.O_NONBLOCK)
                            except OSError as error:
                                if error.errno != errno.EAGAIN:
                                    raise
                            else:
                                try:
                                    os.write(fd, b"X")
                                finally:
                                    os.close(fd)
                        return owned_check()

                    changed = dataclasses.replace(adapter, assert_owned=writer)
                    try:
                        m.capture_private_checkpoint(changed, reservation, out)
                    finally:
                        self.assertTrue(attempted)
                        self.assert_unaccepted(out)
                        self.assertIs(signal.getsignal(signal.SIGIO), source_handler)

    def test_link_boundary_replacement_cannot_publish_a_different_inode(self):
        for name in ("checkpoint.raw", "checkpoint.json"):
            with self.subTest(name=name), self.fixture() as (_, lane, adapter, reservation, disk):
                out = lane / "link-boundary"
                original = m.os.link
                replaced = False

                def replace_at_link(source, destination, *args, **kwargs):
                    nonlocal replaced
                    if destination == name and not replaced:
                        partial = out / (name + ".partial")
                        payload = partial.read_bytes() if name.endswith("json") else b"X" * len(disk)
                        partial.unlink()
                        partial.write_bytes(payload)
                        partial.chmod(0o600)
                        replaced = True
                    return original(source, destination, *args, **kwargs)

                with patch.object(m.os, "link", side_effect=replace_at_link), self.assertRaises((RuntimeError, OSError)):
                    m.capture_private_checkpoint(adapter, reservation, out)
                self.assertTrue(replaced)
                self.assert_unaccepted(out)
                if (out / "checkpoint.raw").exists():
                    self.assertEqual((out / "checkpoint.raw").read_bytes(), disk)

    def test_create_fchmod_failure_closes_new_descriptor(self):
        with tempfile.TemporaryDirectory(prefix="checkpoint-fchmod-") as temporary:
            directory = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            opened = []

            def fail(fd, mode):
                opened.append(fd)
                raise OSError(errno.EIO, "modeled chmod failure")

            try:
                with patch.object(m.os, "fchmod", side_effect=fail), self.assertRaises(OSError):
                    m._create(directory, "private")
                self.assertEqual(len(opened), 1)
                with self.assertRaises(OSError):
                    os.fstat(opened[0])
            finally:
                for fd in opened:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                os.close(directory)

    def test_terminal_directory_close_failure_invalidates_success_receipt(self):
        for failure in ("directory", "raw"):
            with self.subTest(failure=failure), self.fixture() as (_, lane, adapter, reservation, _):
                out = lane / "terminal-close"
                actual = m.os.close
                failed = False

                def close(fd):
                    nonlocal failed
                    target = out if failure == "directory" else out / "checkpoint.raw"
                    current = os.fstat(fd)
                    expected = target.stat() if target.exists() else None
                    matches = expected is not None and (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino)
                    actual(fd)
                    if matches and (out / "checkpoint.json").exists() and not failed:
                        failed = True
                        raise OSError(errno.EIO, "modeled terminal close failure")

                with patch.object(m.os, "close", side_effect=close), self.assertRaises(OSError):
                    m.capture_private_checkpoint(adapter, reservation, out)
                self.assertTrue(failed)
                self.assert_unaccepted(out)

    def test_separate_reservation_and_live_free_space_are_enforced(self):
        with self.fixture() as (_, lane, adapter, reservation, _):
            for bad in (dataclasses.replace(reservation, disk_bytes=4096),
                        dataclasses.replace(reservation, capture_bytes=1),
                        dataclasses.replace(reservation, total_bytes=8192)):
                with self.assertRaises(ValueError):
                    m.capture_private_checkpoint(adapter, bad, lane / "bad-budget")
            with patch.object(m.shutil, "disk_usage", return_value=type("Usage", (), {"free": 17 << 30})()), \
                 self.assertRaises(RuntimeError):
                m.capture_private_checkpoint(adapter, reservation, lane / "space")


if __name__ == "__main__":
    unittest.main()
