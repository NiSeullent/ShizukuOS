# SPDX-License-Identifier: GPL-2.0-only
"""Exercise real source admission/pins and Kernel64 entry/exception bodies.

The C cases model only hardware/service boundaries. They execute the exact
production function bodies; native compilation and guest controls remain separate.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
SHZ = REPO / "shizukudos"
NAMES = ("lib.c", "arch.c", "main.c", "gfx_fb.c", "gfx_gop.c", "gfx_input.c", "gfx_wm.c")


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def function(text, name):
    start = text.index(name + "(")
    start = text.rfind("\n", 0, start) + 1
    opening = text.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.builder = module("dead_source_builder", SHZ / "dead_screen/build.py")
        self.base = {n: (SHZ / "kernel64" / n).read_text() for n in NAMES}

    def test_coherent_default_is_idempotent(self):
        self.assertTrue(hasattr(self.builder, "integration_state"), "coherent default admission guard missing")
        self.assertTrue(self.builder.integration_state(self.base))
        self.assertEqual(self.builder.changed(self.base), self.base)

    def test_partial_and_duplicate_hooks_are_refused(self):
        self.assertTrue(hasattr(self.builder, "integration_state"), "partial admission guard missing")
        for name, hook in (("lib.c", "    ds_native_capture_begin();\n"),
                           ("main.c", "    ds_native_control();\n"),
                           ("gfx_gop.c", "#include \"../dead_screen/native.h\"\n")):
            for replacement in ("", hook + hook):
                broken = dict(self.base)
                self.assertEqual(broken[name].count(hook), 1)
                broken[name] = broken[name].replace(hook, replacement)
                with self.subTest(name=name, duplicate=bool(replacement)):
                    with self.assertRaisesRegex(RuntimeError, "partial|incoherent"):
                        self.builder.changed(broken)
        broken = dict(self.base)
        broken["main.c"] += "\nvoid wrong_extra_hook(void) { ds_native_init(); }\n"
        with self.assertRaisesRegex(RuntimeError, "partial|incoherent"):
            self.builder.changed(broken)

    def test_bare_current_sources_keep_installer_peer_and_driver_callbacks(self):
        # Derive a bare fixture from the real public source, without needing a
        # private historical checkout or changing any original source file.
        bare = {}
        for name, text in self.base.items():
            text = text.replace('#include "../dead_screen/native.h"\n', '')
            text = text.replace('#ifdef SHZ_STANDALONE\n    ds_native_timer_ready();\n#endif\n', '')
            text = re.sub(r'^    ds_native_(capture_char|capture_begin|init|control|bind|keyboard_ready)\([^\n]*\);\n', '', text, flags=re.M)
            text = text.replace('    if (!(r->cs & 3)) ds_native_exception(r);\n', '')
            text = text.replace('int ds_native_control_prepare_gui(void) { return wm_init(); }\n\n', '')
            text = text.replace('    uint64_t sp, bp;\n    __asm__ volatile("mov %%rsp, %0" : "=r"(sp));\n    __asm__ volatile("mov %%rbp, %0" : "=r"(bp));\n    ds_native_panic((uint64_t)__builtin_return_address(0), sp, bp);', '    shz_exit(99);')
            bare[name] = text
        self.assertTrue(hasattr(self.builder, "integration_state"), "bare/default admission guard missing")
        self.assertFalse(self.builder.integration_state(bare))
        adapted = self.builder.changed(bare)
        self.assertTrue(self.builder.integration_state(adapted))
        self.assertEqual(adapted, self.base)
        self.assertIn("ntdrv_run_bugcheck_callbacks();", adapted["lib.c"])
        self.assertIn("k64_boot_has_kernel32_peer(&bootinfo)", adapted["main.c"])
        self.assertLess(adapted["main.c"].index("ds_native_control();"),
                        adapted["main.c"].index('k64_cmdline_has("shz.setup=interactive")'))

    def test_real_kernel_source_hashes_pin_every_dead_source_and_font(self):
        builder = module("kernel_source_builder", SHZ / "kbuild.py")
        pins = builder.source_hashes()
        expected = {str(p.relative_to(REPO)) for p in (SHZ / "dead_screen").glob("*")
                    if p.suffix in (".c", ".h")}
        expected.add("shizukudos/supervisor/src/font8x8_basic.h")
        self.assertTrue(expected <= pins.keys(), sorted(expected - pins.keys()))
        # Exercise the actual hash function against real changed byte inputs,
        # keeping the staged source immutable by using a separate temporary tree.
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for rel in expected:
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes((REPO / rel).read_bytes())
            builder.REPO, builder.SHZ = root, root / "shizukudos"
            # Explicit non-directory inputs of source_hashes are required too.
            for rel in ("shizukudos/tools/shzlib.py", "shizukudos/win64/pe_parse.c", "shizukudos/kbuild.py"):
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes((REPO / rel).read_bytes())
            builder.__file__ = str(root / "shizukudos/kbuild.py")
            before = builder.source_hashes()
            for rel in sorted(expected):
                p = root / rel
                original = p.read_bytes()
                p.write_bytes(original + b"\n/* deliberate source mutation */\n")
                self.assertNotEqual(before[rel], builder.source_hashes()[rel], rel)
                p.write_bytes(original)

    def test_kernel_builder_links_only_four_units_in_both_modes(self):
        import ast
        builder = module("kernel_link_builder", SHZ / "kbuild.py")
        self.assertEqual([p.name for p in builder.dead_screen_sources()],
                         ["dead_screen.c", "render.c", "native.c", "control.c"])
        tree = ast.parse((SHZ / "kbuild.py").read_text())
        calls = {node.args[0].value: node for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == "build_kernel" and node.args and isinstance(node.args[0], ast.Constant)}
        for profile in ("kernel64", "kernel64s"):
            extras = next(kw.value for kw in calls[profile].keywords if kw.arg == "extra_c")
            self.assertEqual(sum(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                                 and n.func.id == "dead_screen_sources" for n in ast.walk(extras)), 1)
        for profile in ("kernel32", "kernel32s"):
            self.assertNotIn("dead_screen_sources", ast.unparse(calls[profile]))


COMMON = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <setjmp.h>
#include "SHZ_ABI"
#include "DS_NATIVE"
#define CHECK(x) do { ++checks; if (!(x)) {fprintf(stderr,"check failed %s:%d: %s\n",__FILE__,__LINE__,#x);exit(1);} } while(0)
static unsigned checks;
static jmp_buf jump;
static unsigned exit_code;
static char events[256];
static void mark(char c) { size_t n=strlen(events);CHECK(n+1<sizeof events);events[n]=c;events[n+1]=0; }
static void cli(void) {mark('c');}
static void sti(void) {mark('i');}
static void shz_exit(unsigned code) __attribute__((noreturn));
static void shz_exit(unsigned code) {exit_code=code;longjmp(jump,1);}
static void shz_evidence(unsigned a,uint64_t b) {CHECK(a==31);(void)b;mark('e');}
static void kprintf(const char *fmt,...) {(void)fmt;}
#define KASSERT(x) do {if(!(x))shz_exit(99);}while(0)
'''

BOOT = r'''
#define K64_VIRT_BASE 0
#define KVER "Kernel64 host boundary model"
#define VEC_TIMER 0x20
#define TICK_US 1000
#ifdef SHZ_STANDALONE
#define READY "tyif"
#else
#define READY "tif"
#endif
typedef struct {uint64_t base,size;uint32_t width,height,pitch,bpp,format;} k64_boot_fb_t;
static shz_bootinfo_t bootinfo;
static int initrd_files=-1,peer,tests,setup,desktop,ipc,bridge,controlled,timer_status;
static int k64_boot_has_kernel32_peer(const shz_bootinfo_t *b) {(void)b;return peer;}
static int k64_cmdline_has(const char *token) {return strstr(bootinfo.cmdline,token)!=NULL;}
static uint64_t p2v(uint64_t p) {return p;}
static void arch_init(void) {mark('a');}
static void mem_init(const shz_bootinfo_t *b) {(void)b;mark('m');}
void ds_native_init(void) {mark('d');}
static void krandom_init(const void *p,size_t n) {(void)p;(void)n;mark('r');}
static int k64_boot_framebuffer(k64_boot_fb_t *b) {(void)b;return -1;}
void pci_log_devices(void) {}
static void fs_init(void) {}
static int fs_load_archive(const uint8_t *p,size_t n) {(void)p;(void)n;return 0;}
void disk_init(void) {}
static void sched_init(void) {}
static int shz_timer_set(unsigned v,unsigned us) {CHECK(v==VEC_TIMER&&us==TICK_US);mark('t');return timer_status;}
void ds_native_timer_ready(void) {mark('y');}
void ds_native_control(void) {mark('f');if(controlled)shz_exit(0xde);}
unsigned k64_desktop(void) {++desktop;mark('D');return 7;}
static void setup_autostart(const shz_bootinfo_t *b) {(void)b;++setup;mark('S');}
static void run_self_tests(const shz_bootinfo_t *b) {(void)b;++tests;mark('Q');}
void ntdrv_selftest(void) {}
void k64_autorun(void) {}
void k64_autorun_observe(void) {}
static void ipc64_init(const shz_bootinfo_t *b) {(void)b;++ipc;}
static int ipc64_run_tests(void) {return 0;}
static void subsys64_start(const shz_bootinfo_t *b) {(void)b;++bridge;}
static void report_final(void) {}
static unsigned tests_failed(void) {return 0;}
ACTUAL_BODY
static void reset(void) {events[0]=0;tests=setup=desktop=ipc=bridge=controlled=timer_status=peer=0;exit_code=0;memset(&bootinfo,0,sizeof bootinfo);}
static void boot(const char *cmd,unsigned magic) {
 shz_bootinfo_t info={0};info.magic=magic;info.abi_major=SHZ_ABI_MAJOR;info.domain_id=SHZ_DOM_KERNEL64;info.size=sizeof info;
 snprintf(info.cmdline,sizeof info.cmdline,"%s",cmd);
 if(!setjmp(jump)) {kmain((uintptr_t)&info);CHECK(0);}
}
int main(void) {
 reset();boot("shz.desktop",SHZ_BOOTINFO_MAGIC);CHECK(exit_code==7&&desktop==1&&tests==0&&setup==0);CHECK(strstr(events,"amd")&&strstr(events,READY "D"));
 reset();boot("shz.setup=interactive shz.desktop",SHZ_BOOTINFO_MAGIC);CHECK(exit_code==7&&desktop==1&&setup==1&&tests==0);CHECK(strstr(events,READY "SD"));
 reset();boot("",SHZ_BOOTINFO_MAGIC);CHECK(exit_code==0&&tests==1&&setup==1&&ipc==0&&bridge==1);CHECK(strstr(events,READY "Q"));
 reset();peer=1;boot("",SHZ_BOOTINFO_MAGIC);CHECK(ipc==1&&bridge==1&&tests==1);
 reset();peer=-1;boot("shz.desktop",SHZ_BOOTINFO_MAGIC);CHECK(exit_code==97&&events[0]==0);
 reset();boot("shz.desktop",0);CHECK(exit_code==97&&events[0]==0);
 reset();timer_status=-1;boot("shz.desktop",SHZ_BOOTINFO_MAGIC);CHECK(exit_code==99&&strchr(events,'y')==NULL&&strchr(events,'f')==NULL&&desktop==0);
 reset();controlled=1;boot("shz.setup=interactive",SHZ_BOOTINFO_MAGIC);CHECK(exit_code==0xde&&desktop==0&&setup==0&&tests==0&&strstr(events,READY));
 printf("{\"checks\":%u,\"scope\":\"actual-kmain-body-boundary-model\"}\n",checks);return 0;
}
'''

EXCEPTION = r'''
#define VEC_TIMER 0x20
#define VEC_DOORBELL 0x21
#define KWIN_BASE 0xffffc10000000000ull
#define KWIN_SIZE 0x8000000000ull
#define PT_W 2
#define PT_NX (1ull<<63)
ACTUAL_REGS
static uint32_t exception_count[32];static uint64_t timer_irqs,demand_lo,demand_hi,demand_faults;
static void (*irq_handlers[256])(struct regs *);
static const char *names[32];
static uint64_t fault_addr;static int file_recovered,user_page_recovered,driver_recovered,user_recovered,seen;
static void krandom_irq(uint64_t v,uint64_t rip) {(void)v;(void)rip;}
void standalone_eoi(void) {}void standalone_eoi_irq(unsigned v) {(void)v;}
static void sched_tick_from(int user) {(void)user;}
int current_thread_must_stop(void) {return 0;}void check_kill(void) {}
void ipc64_doorbell_irq(void) {}
static uint64_t read_cr2(void) {return fault_addr;}static uint64_t read_cr3(void) {return 0x123000;}
int kwin_fault(uint64_t addr) {(void)addr;return file_recovered;}
static uint64_t pmm_alloc(void) {return 0x456000;}static uint64_t kernel_pml4(void) {return 0x123000;}
static int vm_map(uint64_t root,uint64_t addr,uint64_t pa,uint64_t flags) {(void)root;(void)addr;(void)pa;(void)flags;return 0;}
int user_page_fault(struct regs *r,uint64_t addr) {(void)r;(void)addr;return user_page_recovered;}
int ntdrv_kernel_exception(struct regs *r) {(void)r;return driver_recovered;}
static int user_fault(struct regs *r) {(void)r;return user_recovered;}
void ds_native_exception(const struct regs *r) {CHECK(!(r->cs&3));CHECK(r->rip==0x12345678);++seen;shz_exit(0xde);}
ACTUAL_BODY
static void run(unsigned vector,unsigned cs) {
 struct regs r={0};r.vector=vector;r.cs=cs;r.rip=0x12345678;exit_code=0;
 if(!setjmp(jump))isr_dispatch(&r);
}
int main(void) {
 run(6,8);CHECK(exit_code==0xde&&seen==1);
 run(6,3);CHECK(exit_code==98&&seen==1);
 driver_recovered=1;run(6,8);CHECK(exit_code==0&&seen==1);driver_recovered=0;
 user_recovered=1;run(6,3);CHECK(exit_code==0&&seen==1);user_recovered=0;
 file_recovered=1;fault_addr=KWIN_BASE;run(14,8);CHECK(exit_code==0&&seen==1);file_recovered=0;
 demand_lo=0x1000;demand_hi=0x3000;fault_addr=0x2000;run(14,8);CHECK(exit_code==0&&demand_faults==1&&seen==1);
 user_page_recovered=1;run(14,3);CHECK(exit_code==0&&seen==1);
 run(VEC_TIMER,8);CHECK(exit_code==0&&timer_irqs==1&&seen==1);
 printf("{\"checks\":%u,\"scope\":\"actual-isr-dispatch-boundary-model\"}\n",checks);return 0;
}
'''

PANIC = r'''
#include <stdarg.h>
static char reason[256];static unsigned used,active,callbacks,panics;
static void kvprintf(const char *fmt,__builtin_va_list ap) {char out[256];vsnprintf(out,sizeof out,fmt,ap);if(active){size_t n=strlen(out);CHECK(used+n<sizeof reason);memcpy(reason+used,out,n+1);used+=(unsigned)n;}}
void ds_native_capture_begin(void) {active=1;used=0;reason[0]=0;mark('b');}
static void ntdrv_run_bugcheck_callbacks(void) {++callbacks;mark('B');}
void ds_native_panic(uint64_t ip,uint64_t sp,uint64_t bp) {(void)bp;CHECK(ip!=0&&sp!=0);++panics;mark('P');shz_exit(0xde);}
ACTUAL_BODY
int main(void) {
 if(!setjmp(jump)){kpanic("real reason %d",42);CHECK(0);}
 CHECK(exit_code==0xde&&callbacks==1&&panics==1);CHECK(strcmp(events,"cbBeP")==0);CHECK(strstr(reason,"real reason 42"));
 printf("{\"checks\":%u,\"scope\":\"actual-kpanic-body-boundary-model\"}\n",checks);return 0;
}
'''


class ActualBodyTests(unittest.TestCase):
    def test_production_entry_exception_and_panic_bodies(self):
        k64 = (SHZ / "kernel64/k64.h").read_text()
        regs = k64[k64.index("struct regs {"):k64.index("};", k64.index("struct regs {")) + 2]
        cases = (("entry", "main.c", "kmain", BOOT),
                 ("exception", "arch.c", "isr_dispatch", EXCEPTION),
                 ("panic", "lib.c", "kpanic", PANIC))
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw)
            for label, source, name, fixture in cases:
                body = function((SHZ / "kernel64" / source).read_text(), name)
                common = COMMON.replace("SHZ_ABI", str(SHZ / "abi/shz_abi.h")).replace("DS_NATIVE", str(SHZ / "dead_screen/native.h"))
                text = common + fixture.replace("ACTUAL_REGS", regs).replace("ACTUAL_BODY", body)
                c = out / (label + ".c")
                c.write_text(text)
                for standalone in ((False, True) if label == "entry" else (True,)):
                    for cc, flags in (("gcc", ["-O2"]), ("clang", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
                        with self.subTest(label=label, compiler=cc, standalone=standalone):
                            exe = out / (label + "-" + cc + str(standalone))
                            compiled = subprocess.run([cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", *(["-DSHZ_STANDALONE"] if standalone else []), *flags, c, "-o", exe], text=True, capture_output=True, timeout=60)
                            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                            env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1", UBSAN_OPTIONS="halt_on_error=1")
                            result = subprocess.run([exe], text=True, capture_output=True, timeout=30, env=env)
                            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                            self.assertEqual(result.stderr, "")
                            self.assertGreater(json.loads(result.stdout)["checks"], 5)


if __name__ == "__main__":
    unittest.main()
