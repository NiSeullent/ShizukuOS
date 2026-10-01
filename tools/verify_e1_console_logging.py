#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute the actual console cell operations and E1 assertions around logging.

The boundary fixture uses one valid owned handle, no-op host locks, and ASCII
conversion for diagnostic output only. It runs no guest/Windows application.
"""
from pathlib import Path
import argparse, hashlib, json, os, re, subprocess, tempfile

def function(source, name):
    m = re.search(r'^([^\n]*\b' + re.escape(name) + r'\([^\n]*)', source, re.M)
    if not m:
        raise ValueError('actual production function absent: ' + name)
    start = source.index('{', m.start())
    depth = 0
    tokens = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*|[{}]', re.S)
    for token in tokens.finditer(source, start):
        if token[0] == '{': depth += 1
        if token[0] == '}':
            depth -= 1
            if depth == 0: return source[m.start():token.end()]
    raise ValueError('unclosed actual production body: ' + name)

def snapshot_fixture(source):
    old = '    CHECK(ok, "fill changes actual character cell and clips at buffer end");\n'
    check = '    CHECK(ok, "attribute fill changes attribute while preserving character");'
    if old not in source or source.count(old) != 1 or source.count(check) != 1:
        raise ValueError('exact two original assertions required')
    source = source.replace(old, '    BOOL character_fill_ok = ok;\n')
    return source.replace(check, '    CHECK(character_fill_ok, "fill changes actual character cell and clips at buffer end");\n' + check)

def cell_block(source):
    start = source.index('    ok = FillConsoleOutputCharacterW(out, 0x03a9, 10, at, &n);')
    end = source.index('    at.X = -1;', start)
    return source[start:end]

PREFIX = r'''#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
typedef int BOOL;typedef uint32_t DWORD;typedef uint16_t WORD,WCHAR;typedef int16_t SHORT;
typedef uintptr_t HANDLE;typedef DWORD *LPDWORD;typedef WCHAR *LPWSTR;typedef WORD *LPWORD;
typedef struct {SHORT X,Y;} COORD;
typedef struct {union {WCHAR UnicodeChar;char AsciiChar;} Char;WORD Attributes;} CHAR_INFO;
#define K32API
#define WINAPI
#define TRUE 1
#define FALSE 0
#define CON_COLS 80
#define CON_ROWS 25
#define GENERIC_READ 1
#define GENERIC_WRITE 2
#define ENABLE_PROCESSED_OUTPUT 1
#define ENABLE_WRAP_AT_EOL_OUTPUT 2
#define ERROR_INVALID_PARAMETER 87
#define AcquireSRWLockShared(x) ((void)0)
#define ReleaseSRWLockShared(x) ((void)0)
#define AcquireSRWLockExclusive(x) ((void)0)
#define ReleaseSRWLockExclusive(x) ((void)0)
static SHORT g_x,g_y;static WORD g_attr=7;static CHAR_INFO g_cells[2000];static int g_cells_init;
static DWORD last_error;
static DWORD GetLastError(void){return last_error;}
static void SetLastError(DWORD x){last_error=x;}
static void shz_set_last_error(DWORD x){last_error=x;}
static BOOL k32_console_check(HANDLE h,int kind,DWORD access){(void)kind;(void)access;return h==1;}
static DWORD k32_console_output_mode(void){return 3;}
static int k32_utf8_to_wide(const char*s,int n,WCHAR*w,int cap){if(n!=1||cap<1||(unsigned char)*s>127)return 0;w[0]=(unsigned char)s[0];return 1;}
static int k32t_checks,k32t_failed;
'''
PRINTF = r'''static int diagnostic_printf(const char*format,...){
 char bytes[512];va_list ap;va_start(ap,format);int n=vsnprintf(bytes,sizeof bytes,format,ap);va_end(ap);
 if(n<0 || n>=(int)sizeof bytes)return -1;
 k32_console_track(bytes,(DWORD)n);return n;
}
#define printf diagnostic_printf
'''

def compile_run(directory, cc, flags, label, console, block, macro, wanted):
    names = ('cells_init','scroll_model','track_char','k32_console_track','out_handle','out_write_handle',
             'cell_reach','FillConsoleOutputCharacterW','FillConsoleOutputAttribute',
             'ReadConsoleOutputCharacterW','ReadConsoleOutputAttribute')
    bodies = '\n'.join(function(console, name) for name in names)
    code = PREFIX + bodies + '\n' + PRINTF + macro + r'''
int main(void){
 HANDLE out=1;COORD at={79,24};DWORD n=0,got=0;WCHAR text[8];WORD attrs[4];BOOL ok;
 g_x=0;g_y=24;
''' + block + r'''
#undef printf
 printf("{\"checks\":%d,\"failures\":%d,\"final_last_cell\":%u}\n",k32t_checks,k32t_failed,g_cells[1999].Char.UnicodeChar);
 return k32t_checks==2 && k32t_failed==EXPECTED ? 0:1;
}
'''
    code = code.replace('EXPECTED', str(wanted))
    source = directory/(cc+'-'+label+'.c');exe=source.with_suffix('.exe');source.write_text(code)
    subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Werror',*flags,str(source),'-o',str(exe)],check=True,capture_output=True,text=True,timeout=60)
    result=subprocess.run([str(exe)],capture_output=True,text=True,timeout=30)
    if result.returncode!=0:raise RuntimeError(label+': '+result.stdout+result.stderr)
    detail=json.loads(result.stdout)
    return {'compiler':cc,'case':label,**detail,'exit_code':result.returncode}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    if args.out.exists():parser.error('fresh owned output directory required')
    names=('shizukudos/win64/tests/t_e1_kernel32.c','shizukudos/win64/tests/k32test.h','shizukudos/win64/kernel32/k32_console.c')
    original={n:(args.repo/n).read_bytes() for n in names}
    pins={n:hashlib.sha256(b).hexdigest() for n,b in original.items()}
    fixture,header,console=(original[n].decode() for n in names)
    old_check='    CHECK(ok, "fill changes actual character cell and clips at buffer end");\n'
    saved='    BOOL character_fill_ok = ok;\n'
    saved_check='    CHECK(character_fill_ok, "fill changes actual character cell and clips at buffer end");\n'
    if saved in fixture and saved_check in fixture and old_check not in fixture:
        fixture=fixture.replace(saved,old_check).replace(saved_check,'')
    if hashlib.sha256(fixture.encode()).hexdigest()!='d9f122ef8a226d498c1a122318be30e66932c5e20fbd1da409a3fcca6f101db2':
        raise ValueError('known original E1 fixture/admitted snapshot correction required')
    macro=header[header.index('#define CHECK(cond, what)'):header.index('#define CHECKV(cond, what, ...)')]
    candidate=snapshot_fixture(fixture)
    bad='for (i = 0; i < *written; ++i) g_cells[start + i].Attributes = attr;'
    if console.count(bad)!=1:raise ValueError('exact production attribute loop required')
    broken=console.replace(bad,'for (i = 0; i < *written; ++i) { g_cells[start + i].Attributes = attr; g_cells[start + i].Char.UnicodeChar = 0; }')
    args.out.mkdir(parents=True)
    checks=[]
    for cc,flags in (('gcc',[]),('clang',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])):
        checks.append(compile_run(args.out,cc,flags,'original-log-interference',console,cell_block(fixture),macro,1))
        checks.append(compile_run(args.out,cc,flags,'snapshots-before-logging',console,cell_block(candidate),macro,0))
        checks.append(compile_run(args.out,cc,flags,'actual-char-corruption-still-fails',broken,cell_block(candidate),macro,1))
    if any((args.repo/n).read_bytes()!=raw for n,raw in original.items()):raise RuntimeError('source changed during host control')
    result={'status':'ACTUAL_BODY_LOG_INTERFERENCE_AND_CAPTURE_CONTROLS_PASS','checks':checks,'sources_sha256':pins,
            'guest_executed':False,'Windows98_acceptance':False,'modern_app_acceptance':False}
    (args.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
