# SPDX-License-Identifier: GPL-2.0-only
"""Execute real production main/ipc code with bounded hardware-only adapters."""
from pathlib import Path
import os
import subprocess
import unittest

ROOT = Path(__file__).resolve().parent
GCC = os.environ.get('SHZ_K32_GCC', '/usr/bin/gcc')


class Kernel32Lifetime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = ROOT / 'host-fixture'
        command = [GCC, '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                   str(ROOT / 'host_fixture.c'), '-o', str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        (ROOT / 'host-compile.log').write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    def run_case(self, case):
        result = subprocess.run([str(self.binary), str(case)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print(result.stdout.strip())

    def test_native_service_survives_cap_and_qa_end_then_answers_real_ipc(self):
        self.run_case(0)

    def test_default_qa_preserves_twenty_second_exit(self):
        self.run_case(1)

    def test_default_qa_preserves_actual_session_end_ack_and_exit(self):
        self.run_case(2)

    def test_legacy_bootinfo_ignores_absent_cmdline_tail(self):
        self.run_case(3)

    def test_native_failed_owner_closes_with_failure(self):
        self.run_case(4)

    def test_native_absent_owner_is_not_success(self):
        self.run_case(5)

    def test_native_unknown_owner_state_is_not_success(self):
        self.run_case(6)

    def test_native_unavailable_state_hypercall_is_not_success(self):
        self.run_case(7)

    def test_malformed_native_policy_is_refused_before_initialization(self):
        for case in (8,9,10,11,12,13,14,15,16,17,18,19,22,23):
            with self.subTest(case=case):
                self.run_case(case)

    def test_actual_channel_identity_is_verified_before_server_start(self):
        for case in (20,21):
            with self.subTest(case=case):
                self.run_case(case)

    def test_inconsistent_empty_cmdline_does_not_silently_select_qa(self):
        self.run_case(24)

    def test_actual_supervisor_writer_selects_only_native_kernel32(self):
        source=(ROOT/'source/shizukudos/supervisor/src/kdom.c').read_text()
        body=source.split('    bi = (shz_bootinfo_t *)(ram + SHZ_BOOTINFO_GPA);',1)[1].split('    if (ept_init(',1)[0]
        body='    bi = (shz_bootinfo_t *)(ram + SHZ_BOOTINFO_GPA);'+body
        header=ROOT/'source/shizukudos/kernel32/service_policy.h'
        code='#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n'
        code+='#include "source/shizukudos/abi/shz_abi.h"\n#include "source/shizukudos/supervisor/include/shz_info.h"\n'
        if header.exists():
            code+='#include "source/shizukudos/kernel32/service_policy.h"\n'
        code+='''
#define KERNEL_GPA 0x100000ull
#define INITRD_GPA 0x02000000ull
static shz_bootinfo_t result;
static void write_actual(int lm,unsigned flags) {
    uint8_t ram_store[SHZ_BOOTINFO_GPA+sizeof(shz_bootinfo_t)]={0};
    uint8_t *ram=ram_store; shz_bootinfo_t *bi;
    shz_info_t record={0},*info=&record;
    struct { unsigned generation; } dom={1},*d=&dom;
    shz_blob_t image={.size=4096},*kernel=&image,*initrd=0;
    unsigned id=lm?4:3; uint64_t size=16u<<20;
    info->loader_flags=flags; info->tsc_hz=1000000;
'''+body+'''
    result=*bi;
}
int main(void) {
    write_actual(0,0); if(result.cmdline_size || result.cmdline[0]) return 1;
    write_actual(1,1); if(result.cmdline_size || result.cmdline[0]) return 2;
    write_actual(0,1);
    if(result.cmdline_size!=21 || strcmp(result.cmdline,"shz.k32-service=win98") || result.flags) return 3;
    puts("PASS actual Supervisor bootinfo block: only native K32 selects service"); return 0;
}
'''
        cfile=ROOT/'writer-fixture.c'; binary=ROOT/'writer-fixture'; cfile.write_text(code)
        command=[GCC,'-std=gnu11','-O2','-Wall','-Wextra','-Werror',str(cfile),'-o',str(binary)]
        result=subprocess.run(command,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        print(result.stdout.strip())


if __name__ == '__main__':
    unittest.main()
