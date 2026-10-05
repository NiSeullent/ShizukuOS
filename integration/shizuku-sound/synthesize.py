#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
"""Original ShizukuOS event scores and sample synthesis, with no sampled input.

The score and oscillator are authored in this task, not transcribed from a
recording. Python's math implementation may change least-significant samples
across platforms. Distributed bytes are bound by the resulting SHA-256 pins.
"""
import hashlib
import io
import json
import math
from pathlib import Path
import struct
import wave

RATE = 22050
ROOT = Path(__file__).resolve().parent
OUT = ROOT / "assets"

# Each note is (start milliseconds, duration milliseconds, MIDI pitch, gain).
# New short motifs share a soft bell timbre and leave space between events.
# This is an original functional desktop score, not a historical OS melody.
EVENTS = [
    ("startup", "ShizukuStartup.wav", 2380, -9.0,
     [(35, 850, 62, .55), (230, 880, 69, .60), (515, 880, 76, .70),
      (870, 960, 78, .66), (1220, 1060, 74, .76)]),
    ("shutdown", "ShizukuShutdown.wav", 1650, -11.0,
     [(30, 750, 78, .55), (285, 750, 76, .60), (570, 750, 69, .62),
      (855, 690, 62, .74)]),
    ("login", "ShizukuLogin.wav", 990, -11.0,
     [(20, 560, 69, .55), (205, 590, 74, .65), (400, 490, 76, .75)]),
    ("logout", "ShizukuLogout.wav", 930, -11.5,
     [(20, 530, 76, .60), (190, 540, 74, .65), (370, 460, 69, .70)]),
    ("error", "ShizukuError.wav", 700, -10.5,
     [(20, 285, 57, .75), (20, 285, 63, .26),
      (355, 270, 57, .68), (355, 270, 62, .22)]),
    ("warning", "ShizukuWarning.wav", 750, -11.0,
     [(20, 290, 67, .72), (360, 295, 68, .55)]),
    ("notification", "ShizukuNotification.wav", 640, -12.5,
     [(15, 340, 81, .62), (170, 380, 86, .58)]),
    ("device_connect", "ShizukuConnect.wav", 620, -12.0,
     [(15, 250, 74, .62), (140, 300, 76, .66), (285, 255, 81, .68)]),
    ("device_disconnect", "ShizukuDisconnect.wav", 620, -12.5,
     [(15, 250, 81, .60), (140, 300, 76, .62), (285, 255, 74, .65)]),
    ("navigation", "ShizukuNavigation.wav", 160, -17.0,
     [(8, 110, 86, .75), (8, 100, 74, .13)]),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded_event(milliseconds, peak_dbfs, notes):
    frames = (milliseconds * RATE + 500) // 1000
    mixed = [0.0] * frames
    for start_ms, length_ms, midi, gain in notes:
        begin = (start_ms * RATE + 500) // 1000
        count = (length_ms * RATE + 500) // 1000
        hz = 440.0 * 2.0 ** ((midi - 69) / 12.0)
        attack = min(0.018, length_ms / 4000)
        release = min(0.085, length_ms / 2500)
        duration = (count - 1) / RATE
        for i in range(count):
            at = begin + i
            if at >= frames:
                raise ValueError("Score exceeds bounded event extent")
            t = i / RATE
            onset = min(1.0, t / attack)
            tail = min(1.0, (duration - t) / release)
            # Smooth attacks/releases end at exact zero and prevent hard clicks.
            envelope = math.sin(onset * math.pi / 2) ** 2
            envelope *= math.sin(max(0.0, tail) * math.pi / 2) ** 2
            envelope *= math.exp(-3.15 * t / (duration + .22))
            phase = 2.0 * math.pi * hz * t
            tone = .86 * math.sin(phase)
            tone += .09 * math.sin(phase * 1.0017)
            tone += .045 * math.sin(phase * 2.0)
            tone += .005 * math.sin(phase * 3.0)
            mixed[at] += gain * envelope * tone
    peak = max(abs(value) for value in mixed)
    if not peak:
        raise ValueError("Silent event")
    multiplier = (10.0 ** (peak_dbfs / 20.0)) * 32767 / peak
    samples = [round(value * multiplier) for value in mixed]
    if max(abs(sample) for sample in samples) >= 32767:
        raise ValueError("Clipping event")
    raw = struct.pack("<" + "h" * len(samples), *samples)
    stream = io.BytesIO()
    with wave.open(stream, "wb") as writer:
        writer.setnchannels(1)
        writer.setsampwidth(2)
        writer.setframerate(RATE)
        writer.writeframes(raw)
    return stream.getvalue(), samples


def main():
    OUT.mkdir(exist_ok=True)
    entries = []
    summary = []
    names = {}
    for event, name, milliseconds, peak_dbfs, notes in EVENTS:
        data, samples = encoded_event(milliseconds, peak_dbfs, notes)
        path = OUT / name
        if path.exists() and path.read_bytes() != data:
            raise ValueError("Refusing to rewrite differing candidate: " + name)
        path.write_bytes(data)
        names[event] = name
        entries.append({"event": event, "path": "assets/" + name,
                        "media_target": "\\SHZ\\MEDIA\\" + name.upper(),
                        "bytes": len(data), "sha256": sha(data),
                        "format": {"channels": 1, "bits": 16, "rate": RATE,
                                   "frames": len(samples)}})
        rms = math.sqrt(sum(sample * sample for sample in samples) / len(samples))
        summary.append({"event": event, "name": name,
                        "seconds": len(samples) / RATE,
                        "peak_sample": max(abs(sample) for sample in samples),
                        "peak_dbfs": round(20 * math.log10(max(abs(x) for x in samples) / 32768), 4),
                        "rms_dbfs": round(20 * math.log10(rms / 32768), 4),
                        "clipped_samples": sum(abs(sample) >= 32767 for sample in samples),
                        "first_sample": samples[0], "last_sample": samples[-1]})
    aliases = [
        ("SystemStart", "startup"), ("WindowsLogon", "login"),
        ("WindowsLogoff", "logout"), ("SystemExit", "shutdown"),
        ("SystemAsterisk", "notification"), ("Notification.Default", "notification"),
        ("MailBeep", "notification"), ("SystemExclamation", "warning"),
        ("SystemHand", "error"), (".Default", "notification"),
        ("DeviceConnect", "device_connect"), ("DeviceDisconnect", "device_disconnect"),
        ("MenuCommand", "navigation"), ("Navigating", "navigation"),
    ]
    scheme = ("[Events]\r\n" + "".join(alias + "=" + names[event] + "\r\n"
                                        for alias, event in aliases)).encode("ascii")
    (ROOT / "SHZSOUND.INI").write_bytes(scheme)
    dump = lambda name, obj: (ROOT / name).write_text(
        json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    dump("sound-runtime-assets.json", {
        "schema": "shizuku.sound-assets.v1",
        "source": "original score and oscillator in synthesize.py; no external samples",
        "scope": "public redistribution candidate; no live integration or guest execution",
        "license": "CC0-1.0", "guest_playback": False,
        "generator": {"path": "synthesize.py", "sha256": sha(Path(__file__).read_bytes())},
        "files": entries})
    dump("scheme-assets.json", {"files": [{"path": "SHZSOUND.INI",
        "media_target": "\\SHZ\\SHZSOUND.INI", "bytes": len(scheme),
        "sha256": sha(scheme)}], "provider": "Existing WINMM PlaySound alias resolver",
        "guest_execution": False})
    dump("synthesis-result.json", {
        "status": "GENERATED_TEN_ORIGINAL_EVENTS_PENDING_PRODUCTION_PARSER_AUDIT",
        "asset_bytes": sum(entry["bytes"] for entry in entries),
        "format": "PCM signed 16-bit, mono, 22050 Hz",
        "external_samples": [], "events": summary,
        "audible_review": False, "guest_execution": False})


if __name__ == "__main__":
    main()
