# SPDX-License-Identifier: GPL-2.0-only
"""QEMU/QMP helpers for bounded, recorded development-only guest runs.

QEMU is a development and verification tool here. A result obtained under
QEMU/TCG or QEMU/KVM is never reported as a Shizuku Supervisor capability.
"""
import json
import socket
import subprocess
import time
from pathlib import Path

def _first_existing(candidates, fallback):
    return next((c for c in candidates if Path(c).exists()), fallback)


# Fedora/RHEL layout first (the reference host), then Debian/Ubuntu.
DEFAULT_QEMU = _first_existing(["/usr/libexec/qemu-kvm", "/usr/bin/qemu-system-x86_64"], "/usr/libexec/qemu-kvm")
DEFAULT_OVMF_CODE = _first_existing(["/usr/share/edk2/ovmf/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_CODE_4M.fd",
                                     "/usr/share/OVMF/OVMF_CODE.fd"], "/usr/share/edk2/ovmf/OVMF_CODE.fd")
DEFAULT_OVMF_VARS = _first_existing(["/usr/share/edk2/ovmf/OVMF_VARS.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd",
                                     "/usr/share/OVMF/OVMF_VARS.fd"], "/usr/share/edk2/ovmf/OVMF_VARS.fd")


class QMP:
    def __init__(self, path, timeout=10):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            try:
                self.socket = socket.socket(socket.AF_UNIX)
                self.socket.settimeout(5)
                self.socket.connect(str(path))
                break
            except OSError as exc:
                last = exc
                self.socket.close()
                time.sleep(0.1)
        else:
            raise RuntimeError(f"QMP socket never appeared: {last}")
        self.stream = self.socket.makefile("rwb", buffering=0)
        if "QMP" not in json.loads(self.stream.readline()):
            raise RuntimeError("Missing QMP greeting")
        self.call("qmp_capabilities")

    def call(self, command, arguments=None):
        message = {"execute": command}
        if arguments is not None:
            message["arguments"] = arguments
        self.stream.write((json.dumps(message) + "\n").encode())
        while True:
            line = self.stream.readline()
            if not line:
                raise RuntimeError("QMP closed unexpectedly")
            response = json.loads(line)
            if "return" in response:
                return response["return"]
            if "error" in response:
                raise RuntimeError(f"QMP {command}: {response['error']}")

    def hmp(self, command):
        return self.call("human-monitor-command", {"command-line": command})

    def close(self):
        try:
            self.stream.close()
            self.socket.close()
        except OSError:
            pass


def read_guest_memory(qmp, address, size, path):
    """Physical memory dump through QMP: independent of anything the guest prints."""
    path = Path(path)
    path.unlink(missing_ok=True)
    qmp.call("pmemsave", {"val": address, "size": size, "filename": str(path)})
    return path.read_bytes()


def decode_text_page(raw, columns=80, rows=25):
    """80x25 VGA text page (char, attribute pairs) -> list of strings."""
    lines = []
    for row in range(rows):
        chars = raw[row * columns * 2:(row + 1) * columns * 2:2]
        lines.append(bytes(c if 32 <= c < 127 else 32 for c in chars).decode("ascii").rstrip())
    return lines


def cpu_state(qmp):
    """Independent register view from the accelerator (HMP 'info registers')."""
    return qmp.hmp("info registers")


def wait_for(path, needle, timeout):
    """Poll a serial capture file for a marker; True if it appears in time."""
    path = Path(path)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists() and needle.encode() in path.read_bytes():
            return True
        time.sleep(0.2)
    return False


def launch(command, workdir, timeout_note=None):
    """Start QEMU in the background and return the Popen; caller must stop it."""
    err = open(Path(workdir) / "qemu.stderr", "wb")
    return subprocess.Popen([str(x) for x in command], cwd=workdir,
                            stdout=subprocess.DEVNULL, stderr=err)


def qemu_version(qemu=DEFAULT_QEMU):
    r = subprocess.run([qemu, "--version"], capture_output=True, text=True)
    return r.stdout.splitlines()[0] if r.returncode == 0 else None
