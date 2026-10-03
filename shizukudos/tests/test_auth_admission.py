#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Independent auth-policy controls using the complete production dispatcher.

Reuses test_auth_kernel.c hardware, user-memory, filesystem and loader boundary
adapters. Private fixture extensions exercise admission only; they do not model
the actual filesystem/graphics/IPC syscall routers or Windows98/VMM enforcement.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "shizukudos/tests/test_auth_kernel.c"


def capture():
    pending = [FIXTURE, Path(__file__).resolve(), ROOT / "shizukudos/kernel64/auth_core.c",
               ROOT / "shizukudos/kernel64/ipc_core.c"]
    sources = {}
    while pending:
        path = pending.pop().resolve()
        rel = path.relative_to(ROOT)
        if rel in sources:
            continue
        data = path.read_bytes()
        sources[rel] = data
        pending.extend(path.parent / name.decode() for name in
                       re.findall(rb'^\s*#\s*include\s*"([^"\n]+)"', data, re.M))
    return sources


def definition(source, name):
    match = re.search(r"^[^\n;{}]*\b" + name + r"\([^;{}]*\)\s*\{", source, re.M)
    if not match:
        raise ValueError("production definition missing: " + name)
    depth = 1
    for i in range(match.end(), len(source)):
        depth += (source[i] == "{") - (source[i] == "}")
        if not depth:
            return source[match.start():i + 1]
    raise ValueError("unterminated production definition: " + name)


FREE_BOUNDARIES = r'''
static unsigned host_vad_frees,host_heap_frees;
void vad_destroy(process_t *p){assert(p);host_vad_frees++;}
void kfree(void *p){if(p){host_heap_frees++;free(p);}}
void kprintf(const char *fmt,...){(void)fmt;}
static void section_free(kobject_t *o){(void)o;assert(0);}
static void npfs_free(kobject_t *o){(void)o;assert(0);}
static void ioctx_free(kobject_t *o){(void)o;assert(0);}
static void iocp_free(kobject_t *o){(void)o;assert(0);}
static void job_free(kobject_t *o){(void)o;assert(0);}
static void timer_free(kobject_t *o){(void)o;assert(0);}
'''


CONTROLS = r'''
    /* Complete real policy against regular, elevated and sandbox subjects. */
    const uint32_t privileged[]={SYS_NtShzBlkRead,SYS_NtShzSetupBlkRead,
        SYS_NtShzBlkWrite,SYS_NtShzSetupBlkWrite,SYS_NtDeviceIoControlFile,
        SYS_NtLoadDriver,SYS_NtUnloadDriver};
    /* Registry permissions are concrete-node gates, covered by run_registry_accounts.py. */
    for(unsigned i=0;i<sizeof privileged/sizeof *privileged;i++) {
        assert(!shz_auth_syscall_allowed(&children[0],privileged[i]));
        assert(shz_auth_syscall_allowed(&children[1],privileged[i]));
        assert(!shz_auth_syscall_allowed(&children[2],privileged[i]));
    }
    host_lowered_integrity=0x1000;
    assert(!shz_auth_syscall_allowed(&children[1],SYS_NtShzBlkRead));
    assert(!shz_auth_syscall_allowed(&children[1],SYS_NtLoadDriver));
    host_lowered_integrity=UINT32_MAX;
    assert(shz_auth_syscall_allowed(&children[0],SYS_NtShzBlkQuery));
    assert(!shz_auth_syscall_allowed(&children[0],SYS_NtUserClipboard));
    assert(!shz_auth_special_allowed(&children[2],OB_NPIPE));

    char normal[64]="foo",same[64]="foo",elevated[64]="foo",low[64]="foo";
    assert(!shz_auth_object_name(&children[0],normal,sizeof normal));
    assert(!shz_auth_object_name(&inherited,same,sizeof same));
    assert(!shz_auth_object_name(&children[1],elevated,sizeof elevated));
    assert(!shz_auth_object_name(&children[2],low,sizeof low));
    assert(!strcmp(normal,same)&&strcmp(normal,elevated)&&strcmp(normal,low));
    char global[64]="Global\\foo",small[16]="foo";
    assert(shz_auth_object_name(&children[0],global,sizeof global)==STATUS_NOT_SUPPORTED);
    assert(!strcmp(global,"Global\\foo"));
    assert(shz_auth_object_name(&children[0],small,sizeof small)==STATUS_OBJECT_NAME_INVALID);
    assert(!strcmp(small,"foo"));
    char reserved_name[64]="@000003e8:00000001:00002000:foo";
    assert(shz_auth_object_name(&children[0],reserved_name,sizeof reserved_name)==STATUS_OBJECT_NAME_INVALID);

    fsnode_t own={0},alien={0},file={0};
    strcpy(users.name,"Users");users.parent=&root;
    strcpy(own.name,"1000");own.parent=&users;
    strcpy(alien.name,"1001");alien.parent=&users;
    strcpy(file.name,"private.txt");file.parent=&own;
    assert(shz_auth_node_access(&children[0],&file,0));
    assert(shz_auth_node_access(&children[0],&file,1));
    assert(!shz_auth_node_access(&children[2],&file,1));
    file.parent=&alien;
    assert(!shz_auth_node_access(&children[0],&file,0));
    assert(shz_auth_node_access(&children[1],&file,0));
    host_lowered_integrity=0x1000;
    assert(!shz_auth_node_access(&children[1],&file,0));
    host_lowered_integrity=UINT32_MAX;
    assert(!shz_auth_path_access(&children[0],"C:\\Users\\1000\\..\\1001\\private.txt",0));
    assert(!shz_auth_path_access(&children[0],"C:\\Users\\1000\\private.txt:stream",0));
    assert(!shz_auth_path_access(&children[0],"\\Device\\HarddiskVolume1\\Users\\1001\\private.txt",0));
    puts("auth independent admission: raw reads, device controls, lowered IL, IPC names and canonical nodes PASS");

    /* Pending admission is denied even between otherwise identical anonymous
     * subjects. The real constructor publication sequence is tested separately. */
    process_t fresh={0};kobject_t process_object={0},thread_object={0};
    fresh.used=1;fresh.pid=500;fresh.create_tick=500;
    process_object.type=OB_PROCESS;process_object.u.proc.p=&fresh;
    assert(!shz_auth_process_pending(&fresh));
    assert(subject(&fresh).auth_id==0x4e7&&find(&fresh,0)->pending);
    assert(shz_auth_process_access(&fresh,&fresh));
    assert(!shz_auth_process_access(&caller,&fresh));
    assert(!shz_auth_handle_allowed(&caller,&process_object));
    shz_auth_process_ready(&fresh);
    assert(shz_auth_process_access(&caller,&fresh));
    assert(shz_auth_handle_allowed(&caller,&process_object));
    assert(!shz_auth_process_pending(&fresh));
    assert(!shz_auth_inherit(&children[0],&fresh));
    assert(!shz_auth_process_access(&children[0],&fresh));
    shz_auth_process_ready(&fresh);
    assert(shz_auth_process_access(&children[0],&fresh));
    assert(!shz_auth_process_access(&caller,&fresh));
    assert(shz_auth_handle_allowed(&children[0],&process_object));
    assert(!shz_auth_handle_allowed(&caller,&process_object));
    thread_object.type=OB_THREAD;thread_object.u.thr.pid=children[0].pid;
    assert(!shz_auth_handle_allowed(&caller,&thread_object));
    assert(shz_auth_handle_allowed(&inherited,&thread_object));
    fresh.handles=calloc(1,sizeof *fresh.handles);assert(fresh.handles);
    fresh.terminated=1;fresh.teardown=1;
    assert(subject(&fresh).uid==1000&&find(&fresh,0));
    assert(!shz_auth_process_access(&caller,&fresh));
    ipc_object_free(&process_object);
    assert(fresh.used&&fresh.handles&&find(&fresh,0));
    assert(!host_vad_frees&&!host_heap_frees);
    fresh.teardown=2;ipc_object_free(&process_object);
    assert(!find(&fresh,0)&&!fresh.used&&!fresh.handles);
    assert(host_vad_frees==1&&host_heap_frees==1);
    assert(!call(&caller,SHZ_AUTH_QUERY,0,&out)&&out.subject.auth_id==0x4e7);

    shz_auth_request anonymous_sandbox=req;
    anonymous_sandbox.user[0]=0;anonymous_sandbox.password_bytes=0;
    assert(!call(&caller,SHZ_AUTH_SANDBOX_LAUNCH,&anonymous_sandbox,&out));
    assert(out.subject.auth_id==0x4e7&&out.subject.integrity==0x1000);
    assert(out.subject.flags&SHZ_SUBJECT_SANDBOX);
    assert(!find(&children[4],0)->pending);
    assert(!shz_auth_process_access(&children[4],&caller));
    assert(!shz_auth_syscall_allowed(&children[4],SYS_NtShzBlkRead));
    puts("auth independent lifetime: pending process/thread handle denial, ready publication, retained ownership and anonymous sandbox PASS");
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout',type=float,default=300)
    parser.add_argument("--label", default="current")
    parser.add_argument("--compiler", choices=("gcc", "clang", "all"), default="all")
    args = parser.parse_args()
    out = ROOT / "build/fd5c2-auth-review" / args.label
    if out.exists():
        raise SystemExit("fresh label required")
    sources = capture()
    fixture = sources[FIXTURE.relative_to(ROOT)].decode()
    main_marker = "int main(void){"
    if fixture.count(main_marker) != 1:
        raise SystemExit("host fixture entry marker changed: review required")
    free_hook = definition(sources[Path("shizukudos/kernel64/ipc_core.c")].decode(), "ipc_object_free")
    fixture = fixture.replace(main_marker, FREE_BOUNDARIES + "\n" + free_hook + "\n" + main_marker)
    boundary = "uint32_t shz_token_integrity(process_t *p,uint32_t fallback){(void)p;return fallback;}"
    marker = "    inherited.pid=16;"
    if fixture.count(boundary) != 1 or fixture.count(marker) != 1:
        raise SystemExit("host boundary/extension marker changed: review required")
    fixture = fixture.replace(boundary, "static uint32_t host_lowered_integrity=UINT32_MAX;\n"
                              "uint32_t shz_token_integrity(process_t *p,uint32_t fallback){(void)p;"
                              "return host_lowered_integrity<fallback?host_lowered_integrity:fallback;}")
    fixture = fixture.replace(marker, CONTROLS + "\n" + marker)
    visible = "process_t *process_slot(unsigned i){(void)i;return 0;}"
    loader = "child_count++;st=ex->prepare(*p,ex->prepare_ctx);return st;"
    children = "static process_t children[8];static thread_t threads[8];"
    if any(fixture.count(text) != 1 for text in (visible, loader, children)):
        raise SystemExit("host process/loader boundary changed: review required")
    fixture = fixture.replace(visible, "static process_t *host_visible;\n"
                              "process_t *process_slot(unsigned i){return i==1?host_visible:0;}")
    fixture = fixture.replace(children, children + "\nstatic process_t host_observer={.used=1,.pid=900};")
    fixture = fixture.replace(loader, "child_count++;assert(!shz_auth_process_pending(*p));"
                              "assert(!shz_auth_process_access(&host_observer,*p));"
                              "assert(shz_auth_process_access(*p,*p));"
                              "st=ex->prepare(*p,ex->prepare_ctx);"
                              "if(!st)shz_auth_process_ready(*p);return st;")
    enrollment = "    assert(call(&caller,SHZ_AUTH_REGISTER,&req,&out)==STATUS_ACCESS_DENIED);"
    if fixture.count(enrollment) != 1:
        raise SystemExit("enrollment marker changed: review required")
    fixture = fixture.replace(enrollment, '    char reserved_before[64]="@000003e8:00000001:00002000:foo";\n'
                              '    assert(shz_auth_object_name(&caller,reserved_before,sizeof reserved_before)==STATUS_OBJECT_NAME_INVALID);\n'
                              '    host_visible=&caller;assert(shz_auth_bootstrap_prepare(&broker,0)==STATUS_ACCESS_DENIED);\n'
                              '    assert(!find(&broker,0));host_visible=0;\n'
                              + enrollment)
    snap = out / "source"
    for rel, data in sources.items():
        dst = snap / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
    unit = snap / FIXTURE.relative_to(ROOT)
    unit.write_text(fixture)
    hashes = {str(p): hashlib.sha256(data).hexdigest() for p, data in sources.items()}
    results = []
    for compiler in (["gcc", "clang"] if args.compiler == "all" else [args.compiler]):
        cc = shutil.which(compiler)
        if not cc:
            raise SystemExit("required compiler missing: " + compiler)
        exe = out / (compiler + "-auth-admission")
        flags = ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation"]
        if compiler == "clang":
            flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]
        command = [cc, *flags, str(unit), str(snap / "shizukudos/kernel64/auth_core.c"), "-o", str(exe)]
        built = subprocess.run(command, capture_output=True, text=True, timeout=30)
        (out / (compiler + "-compile.log")).write_text(built.stdout + built.stderr)
        result = {"compiler": compiler, "command": command, "compile_exit": built.returncode}
        if not built.returncode:
            started=time.monotonic()
            try:
                ran = subprocess.run([str(exe)], capture_output=True, text=True, timeout=args.timeout,
                                     env=dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1"))
                status=ran.returncode;log=ran.stdout+ran.stderr
            except subprocess.TimeoutExpired as error:
                status=124;log=(error.stdout or b'').decode(errors='replace')+(error.stderr or b'').decode(errors='replace')+'\nTIMEOUT\n'
            (out / (compiler + "-run.log")).write_text(log)
            result.update(run_exit=status,elapsed_seconds=time.monotonic()-started,timeout_seconds=args.timeout,
                          binary_sha256=hashlib.sha256(exe.read_bytes()).hexdigest())
            print(compiler,log,end="",flush=True)
        else:
            print(built.stderr)
        results.append(result)
    stable = all((ROOT / p).read_bytes() == data for p, data in sources.items())
    receipt = {"source_sha256": hashes, "source_stable": stable, "results": results,
               "generated_fixture_sha256": hashlib.sha256(unit.read_bytes()).hexdigest(),
               "scope": "complete production auth dispatcher/account policy and unchanged final-object-free hook with host boundary adapters; no complete syscall routing or native Windows proof"}
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return 0 if stable and results and all(r.get("run_exit", 1) == 0 for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
