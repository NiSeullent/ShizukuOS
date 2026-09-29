#!/usr/bin/env python3
"""Compare the original C core with Python's independent host Unicode codecs.
No Python implementation source or tables are copied into the core.
SPDX-License-Identifier: GPL-2.0-only
"""
import ctypes
import itertools
import json
from pathlib import Path
import random
import sys


def main():
    library = ctypes.CDLL(str(Path(sys.argv[1]).resolve()))
    byte = ctypes.c_uint8
    wide = ctypes.c_uint16
    count = ctypes.c_size_t
    to16 = library.ntwu_utf8_to_utf16
    to8 = library.ntwu_utf16_to_utf8
    to16.argtypes = [ctypes.POINTER(byte), count, ctypes.POINTER(wide), count,
                     ctypes.c_uint32, ctypes.POINTER(count)]
    to8.argtypes = [ctypes.POINTER(wide), count, ctypes.POINTER(byte), count,
                    ctypes.c_uint32, ctypes.POINTER(count)]
    to16.restype = to8.restype = ctypes.c_int
    cases = {'utf8': 0, 'utf16': 0}

    def compare(values, input_type, output_type, convert, expected, strict_valid):
        source = (input_type * max(1, len(values)))(*values)
        required = count(0x12345678)
        status = convert(source, len(values), None, 0, 1, ctypes.byref(required))
        if strict_valid:
            assert status == 0 and required.value == len(expected), (values, status, required.value)
        else:
            assert status == -3 and required.value == 0x12345678, (values, status, required.value)
        assert convert(source, len(values), None, 0, 0, ctypes.byref(required)) == 0
        assert required.value == len(expected), (values, expected, required.value)
        sentinel = 0xa5 if output_type is byte else 0xa55a
        destination = (output_type * (required.value + 2))(*([sentinel] * (required.value + 2)))
        pointer = ctypes.cast(ctypes.byref(destination, ctypes.sizeof(output_type)), ctypes.POINTER(output_type))
        assert convert(source, len(values), pointer, required.value, 0, ctypes.byref(required)) == 0
        assert list(destination)[1:-1] == expected, (values, expected, list(destination))
        assert destination[0] == destination[-1] == sentinel

    def utf8(data):
        expected = data.decode('utf-8', 'replace').encode('utf-16-le')
        units = [int.from_bytes(expected[i:i + 2], 'little') for i in range(0, len(expected), 2)]
        try:
            data.decode('utf-8', 'strict')
            valid = True
        except UnicodeDecodeError:
            valid = False
        compare(data, byte, wide, to16, units, valid)
        cases['utf8'] += 1

    def utf16(units):
        data = b''.join(unit.to_bytes(2, 'little') for unit in units)
        expected = list(data.decode('utf-16-le', 'replace').encode('utf-8'))
        try:
            data.decode('utf-16-le', 'strict')
            valid = True
        except UnicodeDecodeError:
            valid = False
        compare(units, wide, byte, to8, expected, valid)
        cases['utf16'] += 1

    utf8(b'')
    utf16([])
    for first in range(256):
        utf8(bytes([first]))
        for second in range(256):
            utf8(bytes([first, second]))
    # Cover each 3/4-byte boundary leader with every possible second byte,
    # both truncated and followed by valid/invalid suffixes.
    for lead in (0xe0, 0xe1, 0xed, 0xef, 0xf0, 0xf1, 0xf4, 0xf5):
        for second in range(256):
            for suffix in (b'', b'\x80', b'\xbf\x80', b'A', b'\x80A'):
                utf8(bytes([lead, second]) + suffix)
    for units in itertools.product((0, 0x41, 0xd7ff, 0xd800, 0xdbff, 0xdc00, 0xdfff, 0xe000, 0xffff), repeat=3):
        utf16(units)
    random_source = random.Random(98)
    for _ in range(4096):
        utf8(bytes(random_source.randrange(256) for _ in range(random_source.randrange(41))))
        utf16([random_source.randrange(65536) for _ in range(random_source.randrange(21))])
    print(json.dumps({'status': 'PASS', 'python': sys.version.split()[0],
                      'reference': 'Python builtin Unicode codecs; not native Windows',
                      'cases': cases}, sort_keys=True))


if __name__ == '__main__':
    main()
