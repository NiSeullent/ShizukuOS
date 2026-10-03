#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute production console constructors, grants and APIs at host boundaries.

No guest runs. Allocation, native queries, ASCII diagnostic transport, locks and
PEB storage are modeled; handle insertion/lookup, console identity/checks,
GetStdHandle, screen model and original assertions are actual source bodies.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess


def function(source, name):
    match = re.search(r'^([^\n]*\b' + re.escape(name) + r'\s*\([^\n]*)', source, re.M)
    if not match:
        raise ValueError('missing actual function ' + name)
    start = source.index('{', match.start())
    depth = 0
    tokens = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*|[{}]', re.S)
    for token in tokens.finditer(source, start):
        if token[0] == '{':
            depth += 1
        elif token[0] == '}':
            depth -= 1
            if not depth:
                return source[match.start():token.end()]
    raise ValueError('unclosed actual function ' + name)


def constructor(source):
    start = source.index('        kobject_t *in = console_object(0), *outo = console_object(1), *err = console_object(1);')
    end = source.index('\n    }', start)
    body = source[start:end]
    return 'static int defaults(process_t *p, uint32_t std_h[3]) { int32_t st;\n' + body + '\nreturn 0; failed: return st; }\n'


def captures(source, reverse=False):
    old = '''    CHECK(GetConsoleScreenBufferInfo(out, &a) && a.dwSize.X == 80 && a.dwSize.Y == 25 && a.srWindow.Right == 79 && a.srWindow.Bottom == 24,
          "GetConsoleScreenBufferInfo: an 80x25 buffer and window");
    WriteFile(out, "abc", 3, &w, 0);
    CHECK(GetConsoleScreenBufferInfo(out, &b) && b.dwCursorPosition.X == a.dwCursorPosition.X + 3 && b.dwCursorPosition.Y == a.dwCursorPosition.Y,
          "writing 3 characters moves the cursor 3 columns");
    WriteConsoleW(out, W("\\r\\n"), 2, &w, 0);
    CHECK(GetConsoleScreenBufferInfo(out, &b) && b.dwCursorPosition.X == 0, "CR LF returns to column 0");
    CHECK(SetConsoleTextAttribute(out, FOREGROUND_GREEN | FOREGROUND_INTENSITY) && GetConsoleScreenBufferInfo(out, &b) &&
          b.wAttributes == (FOREGROUND_GREEN | FOREGROUND_INTENSITY), "SetConsoleTextAttribute is reported back");
'''
    new = '''    BOOL initial_buffer_ok = GetConsoleScreenBufferInfo(out, &a) && a.dwSize.X == 80 && a.dwSize.Y == 25 && a.srWindow.Right == 79 && a.srWindow.Bottom == 24;
    WriteFile(out, "abc", 3, &w, 0);
    BOOL cursor_write_ok = GetConsoleScreenBufferInfo(out, &b) && b.dwCursorPosition.X == a.dwCursorPosition.X + 3 && b.dwCursorPosition.Y == a.dwCursorPosition.Y;
    WriteConsoleW(out, W("\\r\\n"), 2, &w, 0);
    BOOL cursor_crlf_ok = GetConsoleScreenBufferInfo(out, &b) && b.dwCursorPosition.X == 0;
    BOOL attribute_ok = SetConsoleTextAttribute(out, FOREGROUND_GREEN | FOREGROUND_INTENSITY) && GetConsoleScreenBufferInfo(out, &b) &&
          b.wAttributes == (FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    CHECK(initial_buffer_ok, "GetConsoleScreenBufferInfo: an 80x25 buffer and window");
    CHECK(cursor_write_ok, "writing 3 characters moves the cursor 3 columns");
    CHECK(cursor_crlf_ok, "CR LF returns to column 0");
    CHECK(attribute_ok, "SetConsoleTextAttribute is reported back");
'''
    if reverse:
        old, new = new, old
    if source.count(old) != 1:
        raise ValueError('exact original four assertions required')
    return source.replace(old, new)


PREFIX = r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
typedef int BOOL;typedef int32_t NTSTATUS;typedef uint32_t DWORD,ULONG;typedef uintptr_t ULONG_PTR,HANDLE;
typedef uint8_t BYTE;typedef uint16_t WCHAR,WORD;typedef int16_t SHORT;typedef void *PVOID;typedef ULONG *PULONG;
typedef DWORD *LPDWORD;typedef const void *LPVOID;typedef void VOID;
typedef struct { SHORT X,Y;} COORD;typedef struct {SHORT Left,Top,Right,Bottom;} SMALL_RECT;
typedef struct {COORD dwSize,dwCursorPosition;WORD wAttributes;SMALL_RECT srWindow;COORD dwMaximumWindowSize;} CONSOLE_SCREEN_BUFFER_INFO,*PCONSOLE_SCREEN_BUFFER_INFO;
typedef struct {union{WCHAR UnicodeChar;char AsciiChar;}Char;WORD Attributes;}CHAR_INFO;
typedef struct file{int console;uint32_t access,options;} file_t;
typedef struct object{uint32_t type,refs;struct{struct{file_t*file;uint32_t access;}file;}u;}kobject_t;
typedef struct{struct{ kobject_t*obj;uint32_t access,inherit;}handles[16];unsigned handle_cap,handle_count;}process_t;
typedef struct {uintptr_t Status,Information;}SHZ_IO_STATUS_BLOCK;
#define K32API
#define WINAPI
#define NTAPI
#define TRUE 1
#define FALSE 0
#define OB_FILE 1
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define GENERIC_ALL 0x10000000u
#define FILE_READ_DATA 1
#define FILE_WRITE_DATA 2
#define FOREGROUND_GREEN 2
#define FOREGROUND_INTENSITY 8
#define STD_INPUT_HANDLE ((DWORD)-10)
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define STD_ERROR_HANDLE ((DWORD)-12)
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define STATUS_SUCCESS 0
#define STATUS_NO_MEMORY ((int32_t)0xc0000017)
#define ERROR_ACCESS_DENIED 5
#define ERROR_INVALID_HANDLE 6
#define ERROR_INVALID_PARAMETER 87
#define ERROR_NOT_SUPPORTED 50
#define ERROR_NO_UNICODE_TRANSLATION 1113
#define ERROR_WRITE_FAULT 29
#define ENABLE_PROCESSED_OUTPUT 1
#define ENABLE_WRAP_AT_EOL_OUTPUT 2
#define CON_COLS 80
#define CON_ROWS 25
#define AcquireSRWLockShared(x) ((void)0)
#define ReleaseSRWLockShared(x) ((void)0)
#define AcquireSRWLockExclusive(x) ((void)0)
#define ReleaseSRWLockExclusive(x) ((void)0)
static process_t proc;static _Alignas(8)uint8_t params[64];static DWORD last_error;static int alloc_fail;
static SHORT g_x,g_y;static WORD g_attr=7;static CHAR_INFO g_cells[2000];static int g_cells_init;
static int k32t_checks,k32t_failed,controls;
static uint64_t irq_save(void){return 0;}static void irq_restore(uint64_t f){(void)f;}
/* Console objects have no account realm gate; full account policy is covered by
 * the Kernel64 authority controls, outside this console constructor fixture. */
static int shz_auth_handle_allowed(process_t*p,kobject_t*o){(void)p;(void)o;return 1;}
static void*kzalloc(size_t n){if(alloc_fail)return 0;return calloc(1,n);}static void kfree(void*p){free(p);}
static kobject_t*ob_create(int t,int unused){(void)unused;kobject_t*o=kzalloc(sizeof*o);if(o){o->type=t;o->refs=1;}return o;}
static void ob_deref(kobject_t*o){if(o&&!--o->refs){free(o->u.file.file);free(o);}}
static DWORD GetLastError(void){return last_error;}static void SetLastError(DWORD n){last_error=n;}
static void shz_set_last_error(DWORD n){last_error=n;}static void k32_nt_error(NTSTATUS st){last_error=(DWORD)st;}
static void*shz_peb(void){return params;}
#define PEB_PARAMS(x) ((uint8_t*)(x))
static int k32_console_attached(void){return 1;}
static DWORD k32_console_output_mode(void){return 3;}
static int k32_utf8_to_wide(const char*s,int n,WCHAR*w,int cap){if(n!=1||cap<1||(unsigned char)*s>127)return 0;w[0]=(unsigned char)s[0];return 1;}
static int wide_to_utf8(const WCHAR*w,int n,char*s,int cap){if(n>cap)return 0;for(int i=0;i<n;i++){if(w[i]>127)return 0;s[i]=(char)w[i];}return n;}
static void REQUIRE(int cond){++controls;if(!cond){fprintf(stderr,"control failed at count %d\n",controls);exit(3);}}
'''
NATIVE = r'''
static int copy_to_user(process_t*p,uint64_t at,const void*buf,uint64_t size){(void)p;memcpy((void*)(uintptr_t)at,buf,size);return 0;}
static void file_object_closed(kobject_t*o){(void)o;}
static void handle_close(process_t*p,uint32_t h){kobject_t*o=handle_lookup(p,h,OB_FILE);if(o){p->handles[h/4-1].obj=0;ob_deref(o);}}
static void set_iosb(process_t*p,uint64_t at,int32_t st,uint64_t info){(void)p;(void)at;(void)st;(void)info;}
#define STATUS_ACCESS_VIOLATION ((int32_t)0xc0000005)
#define IO_OPENED 1
static NTSTATUS NtQueryVolumeInformationFile(HANDLE h,SHZ_IO_STATUS_BLOCK*io,void*buf,ULONG len,ULONG cls){
 kobject_t*o=handle_lookup(&proc,h,OB_FILE);if(!o||len!=8||cls!=4)return ERROR_INVALID_HANDLE;
 ULONG*d=buf;d[0]=o->u.file.file->console==1||o->u.file.file->console==2?0x50:7;d[1]=0;io->Information=8;return 0;
}
static NTSTATUS NtQueryInformationFile(HANDLE h,SHZ_IO_STATUS_BLOCK*io,void*buf,ULONG len,ULONG cls){
 kobject_t*o=handle_lookup(&proc,h,OB_FILE);if(!o||cls!=9)return ERROR_INVALID_HANDLE;
 const char*n=o->u.file.file->console==1?"\\CONIN$":o->u.file.file->console==2?"\\CONOUT$":"\\disk";
 size_t count=strlen(n);if(len<4+count*2)return ERROR_INVALID_PARAMETER;
 ULONG bytes=(ULONG)count*2;memcpy(buf,&bytes,4);for(size_t i=0;i<count;i++){WCHAR c=(unsigned char)n[i];memcpy((BYTE*)buf+4+i*2,&c,2);}io->Information=4+bytes;return 0;
}
NTSTATUS NTAPI NtQueryObject(HANDLE h,ULONG cls,PVOID buf,ULONG len,PULONG returned){
 kobject_t*o=handle_lookup(&proc,h,OB_FILE);if(!o||cls||len<56)return ERROR_INVALID_HANDLE;
 memset(buf,0,len);((ULONG*)buf)[1]=proc.handles[h/4-1].access;if(returned)*returned=56;return 0;
}
'''
TRANSPORT = r'''
static BOOL WriteFile(HANDLE h,const VOID*buf,DWORD n,DWORD*put,void*overlap){
 (void)overlap;if(put)*put=0;if(!k32_console_check(h,1,GENERIC_WRITE))return 0;
 k32_console_track(buf,n);if(put)*put=n;return 1;
}
static const WCHAR*W(const char*s){static WCHAR buf[32];unsigned i=0;do{buf[i]=(unsigned char)s[i];}while(s[i++]);return buf;}
static int diagnostic_printf(const char*format,...){char b[512];va_list ap;va_start(ap,format);int n=vsnprintf(b,sizeof b,format,ap);va_end(ap);
 if(n<0||n>=(int)sizeof b){return -1;}DWORD put=0;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),b,(DWORD)n,&put,0);return n;}
#define printf diagnostic_printf
'''
SUFFIX = r'''
#undef printf
static void teardown(void){for(unsigned i=0;i<proc.handle_cap;i++)if(proc.handles[i].obj){ob_deref(proc.handles[i].obj);proc.handles[i].obj=0;}}
static void reset(void){teardown();memset(&proc,0,sizeof proc);proc.handle_cap=16;memset(params,0,sizeof params);g_x=7;g_y=24;g_attr=7;g_cells_init=0;memset(g_cells,0,sizeof g_cells);k32t_checks=k32t_failed=0;}
static void load_defaults(void){uint32_t hs[3];REQUIRE(defaults(&proc,hs)==0);for(int i=0;i<3;i++)memcpy(params+0x20+i*8,&(HANDLE){hs[i]},sizeof(HANDLE));}
static void controls_all(void){
 reset();load_defaults();CONSOLE_SCREEN_BUFFER_INFO info;HANDLE output=GetStdHandle(STD_OUTPUT_HANDLE);
 for(int i=0;i<3;i++){HANDLE h;memcpy(&h,params+0x20+i*8,sizeof h);kobject_t*o=handle_lookup(&proc,h,OB_FILE);REQUIRE(o!=0);REQUIRE(proc.handles[h/4-1].access==(GENERIC_READ|GENERIC_WRITE));REQUIRE(o->u.file.file->access==(GENERIC_READ|GENERIC_WRITE));REQUIRE(o->u.file.file->console==(i?2:1));}
 REQUIRE(GetConsoleScreenBufferInfo(output,&info));REQUIRE(info.dwSize.X==80&&info.dwSize.Y==25);REQUIRE(SetConsoleTextAttribute(output,10));REQUIRE(GetConsoleScreenBufferInfo(output,&info)&&info.wAttributes==10);
 HANDLE input=GetStdHandle(STD_INPUT_HANDLE);SetLastError(0);REQUIRE(!GetConsoleScreenBufferInfo(input,&info)&&GetLastError()==ERROR_INVALID_HANDLE);
 uint32_t ro,wo; kobject_t*o=handle_lookup(&proc,output,OB_FILE);REQUIRE(!handle_insert(&proc,o,GENERIC_READ,&ro));REQUIRE(!handle_insert(&proc,o,GENERIC_WRITE,&wo));
 REQUIRE(GetConsoleScreenBufferInfo(ro,&info));SetLastError(0);REQUIRE(!SetConsoleTextAttribute(ro,15)&&GetLastError()==ERROR_ACCESS_DENIED);
 REQUIRE(SetConsoleTextAttribute(wo,15));SetLastError(0);REQUIRE(!GetConsoleScreenBufferInfo(wo,&info)&&GetLastError()==ERROR_ACCESS_DENIED);
 HANDLE old=output;REQUIRE(SetStdHandle(STD_OUTPUT_HANDLE,ro));REQUIRE(GetStdHandle(STD_OUTPUT_HANDLE)==ro);SetLastError(0);REQUIRE(!SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),1)&&GetLastError()==ERROR_ACCESS_DENIED);REQUIRE(SetStdHandle(STD_OUTPUT_HANDLE,old));
 uint32_t disk; kobject_t*file=ob_create(OB_FILE,0);file->u.file.file=kzalloc(sizeof(file_t));REQUIRE(!handle_insert(&proc,file,GENERIC_READ|GENERIC_WRITE,&disk));ob_deref(file);REQUIRE(SetStdHandle(STD_OUTPUT_HANDLE,disk));REQUIRE(GetStdHandle(STD_OUTPUT_HANDLE)==disk);SetLastError(0);REQUIRE(!GetConsoleScreenBufferInfo(disk,&info)&&GetLastError()==ERROR_INVALID_HANDLE);REQUIRE(SetStdHandle(STD_OUTPUT_HANDLE,old));
 SetLastError(0);REQUIRE(!GetConsoleScreenBufferInfo(0,&info)&&GetLastError()==ERROR_INVALID_HANDLE);SetLastError(0);REQUIRE(!GetConsoleScreenBufferInfo(3,&info)&&GetLastError()==ERROR_INVALID_HANDLE);
 for(unsigned i=0;i<4;i++){const uint32_t rights[]={0,GENERIC_READ,GENERIC_WRITE,GENERIC_READ|GENERIC_WRITE};uint64_t h=0;REQUIRE(!explicit_console(&proc,"\\??\\CONOUT$",rights[i],&h));kobject_t*opened=handle_lookup(&proc,h,OB_FILE);REQUIRE(opened!=0);REQUIRE(proc.handles[h/4-1].access==rights[i]);REQUIRE(opened->u.file.file->access==rights[i]);REQUIRE(opened->u.file.access==rights[i]);REQUIRE(!!GetConsoleScreenBufferInfo(h,&info)==!!(rights[i]&GENERIC_READ));REQUIRE(!!SetConsoleTextAttribute(h,7)==!!(rights[i]&GENERIC_WRITE));}
 alloc_fail=1;REQUIRE(!console_object(0));REQUIRE(!console_object(1));alloc_fail=0;teardown();
}
int main(void){reset();load_defaults();fixture();int checks=k32t_checks,failures=k32t_failed;
 if(checks!=4||failures!=EXPECTED){fprintf(stderr,"assertions %d failure %d expected %d\n",checks,failures,EXPECTED);teardown();return 1;}
 if(CONTROLS)controls_all();else teardown();
 printf("{\"checks\":%d,\"failures\":%d,\"controls\":%d}\n",checks,failures,controls);return 0;}
'''


def compile_run(directory, cc, flags, label, sources, wanted, controls):
    file = sources['file']; console = sources['console']; fixture = sources['fixture']
    code = PREFIX + function(sources['sysfile'], 'console_object')
    code += '\n'.join(function(sources['objects'], n) for n in ('handle_insert', 'handle_lookup')) + constructor(sources['ldr'])
    code += NATIVE
    branch_start=sources['sysfile'].index('    if (!strcmp(path, "\\\\??\\\\CONOUT$") || !strcmp(path, "\\\\??\\\\CONIN$")) {')
    # Capture only this balanced branch. Later admission checks belong to the
    # complete NtCreateFile router and require their own real syscall fixtures.
    branch=function(sources['sysfile'][branch_start:],'if')
    code += 'static int32_t explicit_console(process_t*p,const char*path,uint32_t a2,uint64_t*result){kobject_t*o;int32_t st;uint32_t h;uint64_t a1=(uintptr_t)result,a4=0;\n'+branch+'\nreturn ERROR_INVALID_HANDLE;}\n'
    code += '\n'.join(function(file, n) for n in ('GetStdHandle','SetStdHandle','k32_console_handle','k32_console_check'))
    code += '\n'.join(function(console, n) for n in ('cells_init','scroll_model','track_char','k32_console_track','out_handle','out_write_handle','GetConsoleScreenBufferInfo','SetConsoleTextAttribute'))
    code += TRANSPORT + function(file,'WriteConsoleW')
    macro = sources['header'][sources['header'].index('#define CHECK(cond, what)'):sources['header'].index('#define CHECKV(cond, what, ...)')]
    start = fixture.index('    CHECK(GetConsoleScreenBufferInfo(out, &a)') if '    BOOL initial_buffer_ok =' not in fixture else fixture.index('    BOOL initial_buffer_ok =')
    end = fixture.index('    SetConsoleTextAttribute(out, a.wAttributes);', start)
    code += '\n' + macro + '\nstatic void fixture(void){ CONSOLE_SCREEN_BUFFER_INFO a={0},b={0};HANDLE out=GetStdHandle(STD_OUTPUT_HANDLE);DWORD w=0;\n' + fixture[start:end] + '\n}\n'
    code += SUFFIX.replace('EXPECTED',str(wanted)).replace('CONTROLS',str(int(controls)))
    path = directory/(cc+'-'+label+'.c');exe=path.with_suffix('.exe');path.write_text(code)
    compiled=subprocess.run([cc,'-std=gnu11','-O2','-Wall','-Wextra','-Werror',*flags,str(path),'-o',str(exe)],capture_output=True,text=True,timeout=60)
    if compiled.returncode:raise RuntimeError(label+': '+compiled.stdout+compiled.stderr)
    result=subprocess.run([str(exe)],capture_output=True,text=True,timeout=30)
    if result.returncode:raise RuntimeError(label+': '+result.stdout+result.stderr)
    return {'compiler':cc,'case':label,**json.loads(result.stdout),'exit_code':result.returncode}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--repo',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    if args.out.exists():parser.error('new owned output required')
    paths={'sysfile':'shizukudos/kernel64/sysfile.c','ldr':'shizukudos/kernel64/ldr.c','fixture':'shizukudos/win64/tests/t_k32_sys.c','objects':'shizukudos/kernel64/objects.c','file':'shizukudos/win64/kernel32/k32_file.c','console':'shizukudos/win64/kernel32/k32_console.c','header':'shizukudos/win64/tests/k32test.h'}
    raw={n:(args.repo/p).read_bytes() for n,p in paths.items()};before={paths[n]:hashlib.sha256(b).hexdigest() for n,b in raw.items()};original={n:b.decode() for n,b in raw.items()}
    if '    BOOL initial_buffer_ok =' in original['fixture']:
        original['fixture']=captures(original['fixture'],reverse=True)
    for name,rights in (('in','0x80000000u'),('outo','0x40000000u'),('err','0x40000000u')):
        fixed=name+', 0xc0000000u'
        if original['ldr'].count(fixed)==1:original['ldr']=original['ldr'].replace(fixed,name+', '+rights)
    if 'f->access = GENERIC_READ | GENERIC_WRITE;' in original['sysfile']:
        original['sysfile']=original['sysfile'].replace('f->access = GENERIC_READ | GENERIC_WRITE;', 'f->access = output ? GENERIC_WRITE : GENERIC_READ;')
        original['sysfile']=original['sysfile'].replace('        ((file_t *)o->u.file.file)->access = (uint32_t)a2;       /* Explicit opens retain the requested rights. */\n        o->u.file.access = (uint32_t)a2;\n','')
    candidate=dict(original)
    for before_grant in ('in, 0x80000000u','outo, 0x40000000u','err, 0x40000000u'):
        if candidate['ldr'].count(before_grant)!=1:raise ValueError('original default handle grants required')
        candidate['ldr']=candidate['ldr'].replace(before_grant,before_grant.split(',')[0]+', 0xc0000000u')
    if candidate['sysfile'].count('f->access = output ? GENERIC_WRITE : GENERIC_READ;')!=1:raise ValueError('original constructor access required')
    candidate['sysfile']=candidate['sysfile'].replace('f->access = output ? GENERIC_WRITE : GENERIC_READ;', 'f->access = GENERIC_READ | GENERIC_WRITE;')
    explicit='        o = console_object(!strcmp(path, "\\\\??\\\\CONOUT$"));\n        if (!o) return STATUS_NO_MEMORY;\n'
    if candidate['sysfile'].count(explicit)!=1:raise ValueError('exact explicit console constructor required')
    candidate['sysfile']=candidate['sysfile'].replace(explicit,explicit+'        ((file_t *)o->u.file.file)->access = (uint32_t)a2;       /* Explicit opens retain the requested rights. */\n        o->u.file.access = (uint32_t)a2;\n')
    final=dict(candidate);final['fixture']=captures(original['fixture'])
    mutation=dict(final);mutation['console']=mutation['console'].replace('info->dwSize.X = CON_COLS; info->dwSize.Y = CON_ROWS;', 'info->dwSize.X = CON_COLS - 1; info->dwSize.Y = CON_ROWS;')
    args.out.mkdir(parents=True);results=[]
    for cc,flags in (('gcc',[]),('clang',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])):
        results.append(compile_run(args.out,cc,flags,'original-rights-fail',original,4,False))
        results.append(compile_run(args.out,cc,flags,'rights-only-logging-still-fails',candidate,1,False))
        results.append(compile_run(args.out,cc,flags,'rights-and-captured-observations',final,0,True))
        results.append(compile_run(args.out,cc,flags,'actual-geometry-corruption-detected',mutation,1,False))
    if any((args.repo/paths[n]).read_bytes()!=b for n,b in raw.items()):raise RuntimeError('read-only production source changed')
    result={'status':'HOST_PRODUCTION_CONSTRUCTOR_AND_CONSOLE_CONTROLS_PASS','cases':results,'sources_sha256':before,'guest_executed':False,'Windows98_acceptance':False,'modern_app_acceptance':False}
    (args.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
