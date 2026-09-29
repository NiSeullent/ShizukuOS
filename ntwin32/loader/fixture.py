# SPDX-License-Identifier: GPL-2.0-only
"""PE32 fixture with a Chromium-shaped TLS, load-config and delay-import layout.

The bytes are synthetic. They are not chrome.exe and are not a claim that the
browser loads. Directory sizes follow the pinned 156.0.8076.0 audit: TLS 24,
load configuration 192.
"""
from __future__ import annotations
import struct

IMAGE_BASE = 0x00400000
DATA_RVA = 0x2000
TEXT_RVA = 0x1000


def _name(text: str) -> bytes:
    return text.encode('ascii') + b'\0'


def build_chromium_shaped_pe() -> bytes:
    data = bytearray(0x800)
    data[0x38:0x38 + 13] = _name('KERNEL32.dll')
    struct.pack_into('<H', data, 0x48, 0)
    data[0x4A:0x4A + len(_name('GetProcAddress'))] = _name('GetProcAddress')
    struct.pack_into('<H', data, 0x60, 0)
    data[0x62:0x62 + 6] = _name('Sleep')
    data[0x70:0x74] = bytes((0x11, 0x22, 0x33, 0x44))
    struct.pack_into('<I', data, 0x78, IMAGE_BASE + TEXT_RVA)
    struct.pack_into('<I', data, 0x7C, 0)
    struct.pack_into('<IIIIII', data, 0x80,
                     IMAGE_BASE + DATA_RVA + 0x70,
                     IMAGE_BASE + DATA_RVA + 0x74,
                     IMAGE_BASE + DATA_RVA + 0x74,
                     IMAGE_BASE + DATA_RVA + 0x78,
                     4, 0)
    struct.pack_into('<I', data, 0xA0, 0xBB40E64E)
    struct.pack_into('<I', data, 0xA8, TEXT_RVA)
    load = bytearray(192)
    struct.pack_into('<I', load, 0, 192)
    struct.pack_into('<I', load, 60, IMAGE_BASE + DATA_RVA + 0xA0)
    struct.pack_into('<I', load, 72, IMAGE_BASE + DATA_RVA + 0xA4)
    struct.pack_into('<I', load, 80, IMAGE_BASE + DATA_RVA + 0xA8)
    struct.pack_into('<I', load, 84, 1)
    struct.pack_into('<I', load, 88, 0x100)
    data[0xB0:0xB0 + 192] = load
    struct.pack_into('<I', data, 0x17C, DATA_RVA + 0x60)
    struct.pack_into('<8I', data, 0x184, 1, DATA_RVA + 0x38, DATA_RVA + 0x170,
                     DATA_RVA + 0x174, DATA_RVA + 0x17C, 0, 0, 0)
    struct.pack_into('<IIIII', data, 0x00, DATA_RVA + 0x28, 0, 0, DATA_RVA + 0x38, DATA_RVA + 0x30)
    struct.pack_into('<II', data, 0x28, DATA_RVA + 0x48, 0)
    struct.pack_into('<II', data, 0x30, DATA_RVA + 0x48, 0)
    data[0x200:0x204] = b'\xa5\xa5\xa5\xa5'

    text = bytearray(0x200)
    # stdcall callback(module, reason, reserved): *(uint32_t *)(module+0x2200) = reason
    text[0:17] = bytes((
        0x8B, 0x44, 0x24, 0x08,
        0x8B, 0x4C, 0x24, 0x04,
        0x89, 0x81, 0x00, 0x22, 0x00, 0x00,
        0xC2, 0x0C, 0x00,
    ))
    headers = bytearray(0x200)
    headers[:2] = b'MZ'
    struct.pack_into('<I', headers, 0x3C, 0x80)
    struct.pack_into('<I', headers, 0x80, 0x00004550)
    struct.pack_into('<HHIIIHH', headers, 0x84, 0x14C, 2, 0, 0, 0, 224, 0x0102)
    optional = 0x98
    struct.pack_into('<H', headers, optional, 0x10B)
    struct.pack_into('<I', headers, optional + 4, 0x200)
    struct.pack_into('<I', headers, optional + 8, 0x800)
    struct.pack_into('<I', headers, optional + 16, TEXT_RVA)
    struct.pack_into('<I', headers, optional + 20, TEXT_RVA)
    struct.pack_into('<I', headers, optional + 24, DATA_RVA)
    struct.pack_into('<I', headers, optional + 28, IMAGE_BASE)
    struct.pack_into('<I', headers, optional + 32, 0x1000)
    struct.pack_into('<I', headers, optional + 36, 0x200)
    struct.pack_into('<HH', headers, optional + 40, 10, 0)
    struct.pack_into('<HH', headers, optional + 48, 10, 0)
    struct.pack_into('<I', headers, optional + 56, 0x3000)
    struct.pack_into('<I', headers, optional + 60, 0x200)
    struct.pack_into('<H', headers, optional + 68, 3)
    struct.pack_into('<H', headers, optional + 70, 0xC140)
    struct.pack_into('<I', headers, optional + 72, 0x100000)
    struct.pack_into('<I', headers, optional + 76, 0x1000)
    struct.pack_into('<I', headers, optional + 80, 0x100000)
    struct.pack_into('<I', headers, optional + 84, 0x1000)
    struct.pack_into('<I', headers, optional + 92, 16)
    def directory(index: int, rva: int, size: int) -> None:
        struct.pack_into('<II', headers, optional + 96 + index * 8, rva, size)
    directory(1, DATA_RVA, 40)
    directory(9, DATA_RVA + 0x80, 24)
    directory(10, DATA_RVA + 0xB0, 192)
    directory(12, DATA_RVA + 0x30, 8)
    directory(13, DATA_RVA + 0x184, 64)
    table = optional + 224
    def section(index: int, name: bytes, virtual: int, raw_size: int, raw: int, flags: int) -> None:
        struct.pack_into('<8sIIIIIIHHI', headers, table + index * 40, name, raw_size, virtual,
                         raw_size, raw, 0, 0, 0, 0, flags)
    section(0, b'.text\0\0\0', TEXT_RVA, 0x200, 0x200, 0x60000020)
    section(1, b'.data\0\0\0', DATA_RVA, 0x800, 0x400, 0xC0000040)
    if len(data) != 0x800:
        raise RuntimeError(f'data section length {len(data):#x}')
    return bytes(headers) + bytes(text) + bytes(data)
