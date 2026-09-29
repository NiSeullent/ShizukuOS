#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Original bounded COMMAND.COM branch model; no shell or guest is executed.

Only this diagnostic wrapper's fixed command subset is accepted. The model
assumes successful echo redirection; native disk-write behavior is not proved.
"""
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent


class BatchError(ValueError):
    pass


def validate_batch(text):
    """Parse a restricted wrapper and interpret every byte-sized exit code."""
    if not isinstance(text, str) or not text or len(text) > 8192:
        raise BatchError('Expected bounded batch text')
    text = text.replace('\r\n', '\n')
    if any(ord(c) > 126 or (ord(c) < 32 and c not in '\n\t') for c in text):
        raise BatchError('Only printable ASCII and LF/CRLF text is accepted')
    lines = text.splitlines()
    if len(lines) > 128 or any(len(line) > 256 for line in lines):
        raise BatchError('Batch exceeds bounded line limits')
    code, labels = [], {}
    for raw in lines:
        line = raw.strip()
        lower = line.lower()
        if not line or lower == 'rem' or lower.startswith(('rem ', '@rem ')):
            continue
        if lower == '@echo off':
            op = ('setup',)
        elif lower == 'c:\\ntwlab\\ntwdrun.exe':
            op = ('run',)
        elif match := re.fullmatch(r'if\s+errorlevel\s+(\d+)\s+goto\s+([a-z][a-z0-9_]*)', lower):
            op = ('if', int(match[1]), match[2])
        elif match := re.fullmatch(r'goto\s+([a-z][a-z0-9_]*)', lower):
            op = ('goto', match[1])
        elif match := re.fullmatch(r':([a-z][a-z0-9_]*)', lower):
            if match[1] in labels:
                raise BatchError('Duplicate label')
            labels[match[1]] = len(code)
            op = ('label', match[1])
        elif match := re.fullmatch(r'echo\s+([0-3]|unexpected)\s*>\s*c:\\ntwlab\\ntwdexit\.txt',
                                  line, re.IGNORECASE):
            op = ('capture', match[1])
        elif re.fullmatch(r'ver\s*>\s*c:\\ntwlab\\guestver\.txt', lower):
            op = ('version',)
        elif lower.startswith('echo ') and not any(c in line for c in '<>&|^%!'):
            op = ('info',)
        else:
            raise BatchError('Unsupported command or output path: ' + line)
        code.append(op)
    runs = [i for i, op in enumerate(code) if op[0] == 'run']
    if runs != [1] or not code or code[0] != ('setup',) or code.count(('setup',)) != 1:
        raise BatchError('Exactly one fixed launcher must follow @echo off')
    branches = [op for op in code if op[0] == 'if']
    if [op[1] for op in branches] != [4, 3, 2, 1] or code[2:6] != branches:
        raise BatchError('Capture must immediately test ERRORLEVEL in descending 4/3/2/1 order')
    for op in code:
        target = op[2] if op[0] == 'if' else op[1] if op[0] == 'goto' else None
        if target is not None and target not in labels:
            raise BatchError('Unresolved GOTO target')
    reached, outcomes = set(), {}
    for status in range(256):
        pc, steps, launched, version_writes, information = 0, 0, 0, 0, 0
        captured = []
        while pc < len(code):
            steps += 1
            if steps > 2 * len(code) + 8:
                raise BatchError('Loop or unbounded control flow')
            reached.add(pc)
            op = code[pc]
            pc += 1
            if op[0] == 'run':
                launched += 1
                if launched != 1 or captured:
                    raise BatchError('Launcher repeated or capture precedes launch')
            elif op[0] == 'if':
                if launched != 1 or captured:
                    raise BatchError('Exit status tested outside its capture interval')
                if status >= op[1]:
                    pc = labels[op[2]]
            elif op[0] == 'goto':
                pc = labels[op[1]]
            elif op[0] == 'capture':
                if launched != 1:
                    raise BatchError('Capture before launch')
                captured.append(op[1])
            elif op[0] in ('version', 'info'):
                if len(captured) != 1:
                    raise BatchError('Auxiliary command precedes a unique captured result')
                version_writes += op[0] == 'version'
                information += op[0] == 'info'
        expected = str(status) if status < 4 else 'unexpected'
        if captured != [expected] or information != 1 or version_writes > 1:
            raise BatchError(f'Exit {status} captured incorrectly or output was overwritten')
        outcomes[str(status)] = captured[0]
    if reached != set(range(len(code))):
        raise BatchError('Unreachable branch or command')
    return {'schema': 'ntw.diagnostic_batch.host.v1', 'outcomes': outcomes,
            'tested_exit_codes': 256, 'guest_executed': False}


class DiagnosticBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (HERE / 'run_diagnostic.bat').read_text(encoding='ascii')

    def rejected(self, text):
        with self.assertRaises(BatchError):
            validate_batch(text)

    def test_all_byte_exit_codes_and_required_boundaries(self):
        result = validate_batch(self.text)
        self.assertFalse(result['guest_executed'])
        self.assertEqual(result['tested_exit_codes'], 256)
        self.assertEqual(result['outcomes'], {str(i): str(i) if i < 4 else 'unexpected' for i in range(256)})
        for i in (0, 1, 2, 3, 4, 255):
            self.assertEqual(result['outcomes'][str(i)], str(i) if i < 4 else 'unexpected')

    def test_adjacent_errorlevel_reordering_is_rejected(self):
        lines = self.text.splitlines()
        positions = [i for i, line in enumerate(lines) if line.startswith('if errorlevel ')]
        self.assertEqual(len(positions), 4)
        for left, right in zip(positions, positions[1:]):
            with self.subTest(left=left):
                changed = lines[:]
                changed[left], changed[right] = changed[right], changed[left]
                self.rejected('\n'.join(changed))

    def test_each_missing_goto_and_capture_is_rejected(self):
        lines = self.text.splitlines()
        for i, line in enumerate(lines):
            if line.startswith(('goto ', 'if errorlevel ')) or '>' in line and 'NTWDEXIT.TXT' in line:
                with self.subTest(line=line):
                    self.rejected('\n'.join(lines[:i] + lines[i + 1:]))

    def test_unexpected_threshold_and_status_capture_mutations(self):
        for threshold in (0, 1, 3, 5, 255, 256, 999999):
            self.rejected(self.text.replace('if errorlevel 4 ', f'if errorlevel {threshold} ', 1))
        for value in ('0', '1', '2', '3', 'unexpected'):
            target = 'echo ' + value + ' >'
            changed = self.text.replace(target, 'echo ' + ('0' if value != '0' else '1') + ' >', 1)
            self.assertNotEqual(changed, self.text)
            self.rejected(changed)

    def test_duplicate_missing_looping_and_dead_labels(self):
        for old, new in ((':code1', ':unknown'), (':done', ':missing'),
                         ('goto done', 'goto code1'), ('goto done', 'goto absent')):
            self.rejected(self.text.replace(old, new, 1))
        self.rejected(self.text + '\ngoto done\n:unused\n')

    def test_wrong_launcher_paths_redirection_and_extra_commands(self):
        for old, new in (('ntwdrun.exe', 'ntwrun.exe'), ('c:\\ntwlab\\ntwdrun.exe', 'ntwdrun.exe'),
                         ('NTWDEXIT.TXT', 'NTWEXIT.TXT'), (' >', ' >>'),
                         ('c:\\ntwlab\\ntwdrun.exe', 'c:\\ntwlab\\ntwdrun.exe\nver')):
            self.rejected(self.text.replace(old, new, 1))
        for suffix in ('\ndel c:\\ntwlab\\NTWDEXIT.TXT', '\necho x&evil', '\necho %ERRORLEVEL%',
                       '\nc:\\ntwlab\\ntwdrun.exe', '\n@echo off'):
            self.rejected(self.text + suffix)

    def test_text_bounds_and_line_endings(self):
        self.assertEqual(validate_batch(self.text), validate_batch(self.text.replace('\n', '\r\n')))
        for bad in (None, b'@echo off', '', '\ufeff' + self.text, self.text + '\x00',
                    self.text + '\x1a', self.text + '\r', 'X' * 8193, self.text + '\n' * 129):
            self.rejected(bad)


if __name__ == '__main__':
    unittest.main()
