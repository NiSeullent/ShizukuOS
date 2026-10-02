/* SPDX-License-Identifier: GPL-2.0-only -- WinAPI host model, no real boot. */
#include "../probe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL line %u: %s\n",(unsigned)__LINE__,#x); exit(1); } } while (0)
#define OUT ((HANDLE)(uintptr_t)1)
#define WR ((HANDLE)(uintptr_t)2)
#define RD ((HANDLE)(uintptr_t)3)
static const char nonce[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char expected[] = "PERSCHK1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n";
static const char create_cmd[] = "PERSCHK.EXE create C:\\PERS0001.DAT 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char verify_cmd[] = "PERSCHK.EXE verify C:\\PERS0001.DAT 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static unsigned checks, cases;
static DWORD version, read_limit, write_limit, read_at, file_size, write_calls, read_calls, opens, flushes, close_wr, close_rd, out_calls;
static char file[160], output[256], active_path[32];
static unsigned exists, wr_open, rd_open, output_size;
static unsigned fail_create, fail_reopen, fail_write_at, zero_write, over_write, fail_flush, fail_close_wr, fail_close_rd;
static unsigned fail_read_at, zero_read, over_read, eof_junk, fail_eof, bad_size, high_size, fail_stdout, zero_stdout, over_stdout, bad_stdout;
static char *entry_command;
static DWORD exit_code;
static jmp_buf exit_env;
void mainCRTStartup(void);

static void reset(int present) {
  version=0xc0000a04u; read_limit=write_limit=160; read_at=0; file_size=present ? 75 : 0;
  write_calls=read_calls=opens=flushes=close_wr=close_rd=out_calls=0;
  exists=(unsigned)present; wr_open=rd_open=output_size=0;
  fail_create=fail_reopen=fail_write_at=zero_write=over_write=fail_flush=fail_close_wr=fail_close_rd=0;
  fail_read_at=zero_read=over_read=eof_junk=fail_eof=bad_size=high_size=fail_stdout=zero_stdout=over_stdout=bad_stdout=0;
  memset(file,0,sizeof file); memset(output,0,sizeof output); strcpy(active_path,"C:\\PERS0001.DAT");
  if(present) memcpy(file,expected,75);
  ++cases;
}
DWORD GetVersion(void) { return version; }
HANDLE GetStdHandle(DWORD which) { CHECK(which==STD_OUTPUT_HANDLE); return bad_stdout==1 ? INVALID_HANDLE_VALUE : bad_stdout==2 ? NULL : OUT; }
char *GetCommandLineA(void) { return entry_command; }
void ExitProcess(DWORD code) { exit_code=code; longjmp(exit_env,1); }
HANDLE CreateFileA(const char *path,DWORD access,DWORD share,void *security,DWORD disposition,DWORD attrs,HANDLE template_file) {
  ++opens; CHECK(!share && !security && attrs==FILE_ATTRIBUTE_NORMAL && !template_file); CHECK(!strcmp(path,active_path));
  if(access==GENERIC_WRITE) {
    CHECK(disposition==CREATE_NEW); CHECK(!wr_open && !rd_open);
    if(fail_create || exists) return INVALID_HANDLE_VALUE;
    exists=1; file_size=0; wr_open=1; return WR;
  }
  CHECK(access==GENERIC_READ && disposition==OPEN_EXISTING && !wr_open && !rd_open);
  if(fail_reopen || !exists) return INVALID_HANDLE_VALUE;
  rd_open=1; read_at=0; return RD;
}
BOOL WriteFile(HANDLE h,const void *data,DWORD size,DWORD *got,void *overlapped) {
  DWORD n; CHECK(got && !overlapped && size>0);
  if(h==OUT) {
    ++out_calls; if(fail_stdout) return FALSE;
    if(zero_stdout) { *got=0; return TRUE; }
    if(over_stdout) { *got=size+1; return TRUE; }
    n=size<write_limit ? size : write_limit; CHECK(output_size+n<sizeof output); memcpy(output+output_size,data,n); output_size+=n; *got=n; return TRUE;
  }
  CHECK(h==WR && wr_open); ++write_calls;
  if(write_calls==fail_write_at) return FALSE;
  if(zero_write) { *got=0; return TRUE; }
  if(over_write) { *got=size+1; return TRUE; }
  n=size<write_limit ? size : write_limit; CHECK(file_size+n<=sizeof file); memcpy(file+file_size,data,n); file_size+=n; *got=n; return TRUE;
}
BOOL ReadFile(HANDLE h,void *data,DWORD size,DWORD *got,void *overlapped) {
  DWORD n; CHECK(h==RD && rd_open && got && !overlapped && size>0); ++read_calls;
  if(read_calls==fail_read_at) return FALSE;
  if(read_at==file_size) {
    if(fail_eof) return FALSE;
    if(eof_junk) { *(char *)data='X'; *got=1; return TRUE; }
    *got=0; return TRUE;
  }
  if(zero_read) { *got=0; return TRUE; }
  if(over_read) { *got=size+1; return TRUE; }
  n=file_size-read_at; if(n>size) n=size; if(n>read_limit) n=read_limit;
  memcpy(data,file+read_at,n); read_at+=n; *got=n; return TRUE;
}
BOOL FlushFileBuffers(HANDLE h) { CHECK(h==WR && wr_open); ++flushes; return fail_flush ? FALSE : TRUE; }
BOOL CloseHandle(HANDLE h) {
  if(h==WR) { CHECK(wr_open); ++close_wr; wr_open=0; return fail_close_wr ? FALSE : TRUE; }
  CHECK(h==RD && rd_open); ++close_rd; rd_open=0; return fail_close_rd ? FALSE : TRUE;
}
DWORD GetFileSize(HANDLE h,DWORD *high) { CHECK(h==RD && rd_open && high); *high=high_size; return bad_size ? 0xffffffffu : file_size; }
static void failure_cleanup(void) { CHECK(!wr_open && !rd_open); CHECK(!strstr(output,"VERIFIED")); }
static void refuse(const char *command) { reset(0); CHECK(perschk_run(command)!=0); CHECK(!exists && !opens && !write_calls && !read_calls && !flushes); failure_cleanup(); }
static void command_for(char *out,const char *mode,const char *path,const char *token) {
  int n=snprintf(out,512,"PERSCHK.EXE %s %s %s",mode,path,token); CHECK(n>0 && n<512);
}
int main(void) {
  char command[512], saved[160]; DWORD rc; unsigned i;
  reset(0); CHECK(perschk_run(create_cmd)==0); CHECK(exists && file_size==75 && !memcmp(file,expected,75));
  CHECK(opens==2 && flushes==1 && close_wr==1 && close_rd==1 && !wr_open && !rd_open);
  CHECK(!strcmp(output,"PERSCHK CREATE VERIFIED C:\\PERS0001.DAT 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"));
  reset(1); CHECK(perschk_run(verify_cmd)==0); CHECK(opens==1 && !write_calls && !flushes && !close_wr && close_rd==1); CHECK(!memcmp(file,expected,75));
  CHECK(!strcmp(output,"PERSCHK VERIFY VERIFIED C:\\PERS0001.DAT 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n"));
  reset(0); write_limit=7; read_limit=3; CHECK(perschk_run(create_cmd)==0); CHECK(write_calls==11 && read_calls==26 && file_size==75 && !memcmp(file,expected,75)); CHECK(!wr_open && !rd_open);
  reset(1); memcpy(file,"ORIGINAL KEEP",13); memcpy(saved,file,sizeof file); CHECK(perschk_run(create_cmd)!=0); CHECK(opens==1 && !write_calls && !flushes && !close_wr && !memcmp(file,saved,sizeof file)); failure_cleanup();
  reset(0); fail_create=1; CHECK(perschk_run(create_cmd)!=0); CHECK(!exists && !close_wr && !read_calls); failure_cleanup();
  reset(0); fail_reopen=1; CHECK(perschk_run(create_cmd)!=0); CHECK(file_size==75 && close_wr==1 && !close_rd && !memcmp(file,expected,75)); failure_cleanup();
  for(i=0;i<6;++i) {
    reset(0); write_limit=7;
    if(i==0) fail_write_at=1; else if(i==1) fail_write_at=3; else if(i==2) zero_write=1;
    else if(i==3) over_write=1; else if(i==4) fail_flush=1; else fail_close_wr=1;
    CHECK(perschk_run(create_cmd)!=0); CHECK(exists && close_wr==1 && opens==1 && !close_rd); failure_cleanup();
    if(i==1) CHECK(file_size==14 && !memcmp(file,expected,14));
  }
  for(i=0;i<8;++i) {
    reset(1);
    if(i==0) fail_read_at=1; else if(i==1) { read_limit=3; fail_read_at=3; }
    else if(i==2) zero_read=1; else if(i==3) over_read=1; else if(i==4) eof_junk=1;
    else if(i==5) fail_eof=1; else if(i==6) bad_size=1; else high_size=1;
    CHECK(perschk_run(verify_cmd)!=0); CHECK(close_rd==1 && !write_calls && !flushes && !memcmp(file,expected,75)); failure_cleanup();
  }
  reset(1); fail_close_rd=1; CHECK(perschk_run(verify_cmd)!=0); CHECK(close_rd==1 && !write_calls); failure_cleanup();
  for(i=0;i<75;++i) { reset(1); file[i]^=1; CHECK(perschk_run(verify_cmd)!=0); CHECK(close_rd==1 && !write_calls); failure_cleanup(); }
  for(i=0;i<3;++i) { reset(1); file_size=i==0 ? 0 : i==1 ? 74 : 76; CHECK(perschk_run(verify_cmd)!=0); CHECK(close_rd==1 && !write_calls); failure_cleanup(); }
  for(i=0;i<3;++i) { reset(1); if(i==0) fail_stdout=1; else if(i==1) zero_stdout=1; else over_stdout=1; CHECK(perschk_run(verify_cmd)!=0); CHECK(close_rd==1 && !wr_open && !rd_open); }
  for(i=1;i<=2;++i) { reset(0); bad_stdout=i; CHECK(perschk_run(create_cmd)!=0); CHECK(!exists && !opens && !write_calls); }
  for(i=0;i<3;++i) { reset(0); version=i==0 ? 0xc0000004u : i==1 ? 0xc0005a04u : 0x00000a04u; CHECK(perschk_run(create_cmd)!=0); CHECK(!exists && !opens); failure_cleanup(); }
  {
    const char *paths[]={"C:\\CON","C:\\con.DAT","C:\\AUX.TXT","C:\\PRN","C:\\NUL.DAT","C:\\COM1.DAT","C:\\com9.dat","C:\\LPT0.X","C:\\LPT9.X","C:\\CLOCK$.DAT","C:\\..\\A.DAT","C:\\A\\B.DAT","C:\\A.DAT:Z","C:\\A.DAT.","\"C:\\A.DAT \"","C:\\LONGER123.DAT","C:\\NAME.ABCD","C:/NAME.DAT","D:\\NAME.DAT","C:NAME.DAT","\\\\server\\NAME.DAT","C:\\A*.DAT","C:\\A?.DAT","C:\\AUTOEXEC.BAT","C:\\CONFIG.SYS","C:\\COMMAND.COM","C:\\IO.SYS","C:\\MSDOS.SYS","C:\\WIN.COM","C:\\WINSTART.BAT","C:\\WININIT.INI","C:\\WINBOOT.INI","C:\\SYSTEM.DAT","C:\\USER.DAT"};
    for(i=0;i<sizeof paths/sizeof paths[0];++i) { command_for(command,"create",paths[i],nonce); refuse(command); }
  }
  refuse(NULL); refuse(""); refuse("PERSCHK.EXE"); refuse("PERSCHK.EXE create");
  command_for(command,"CREATE","C:\\PERS0001.DAT",nonce); refuse(command);
  command_for(command,"create","C:\\PERS0001.DAT","0123"); refuse(command);
  strcpy(command,create_cmd); command[strlen(command)-1]='g'; refuse(command);
  snprintf(command,sizeof command,"%s0",create_cmd); refuse(command);
  snprintf(command,sizeof command,"%s extra",create_cmd); refuse(command);
  snprintf(command,sizeof command,"%s\n",create_cmd); refuse(command);
  snprintf(command,sizeof command,"%s\tX",create_cmd); refuse(command);
  memset(command,'A',sizeof command); refuse(command);
  snprintf(command,sizeof command,"\"C:\\Program Files\\PERSCHK.EXE\" create C:\\PERS0001.DAT %s",nonce);
  reset(0); CHECK(perschk_run(command)==0 && file_size==75); CHECK(!wr_open && !rd_open);
  snprintf(command,sizeof command,"\"C:\\Program Files\\PERSCHK.EXE\"x create C:\\PERS0001.DAT %s",nonce); refuse(command);
  snprintf(command,sizeof command,"PERSCHK.EXE\tcreate\tC:\\PERS0001.DAT\t%s  \t",nonce); reset(0); CHECK(perschk_run(command)==0);
  command_for(command,"create","C:\\p1.dat","ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"); reset(0); strcpy(active_path,"C:\\p1.dat"); CHECK(perschk_run(command)==0); CHECK(!memcmp(file+9,"ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",64));
  reset(1); entry_command=(char *)verify_cmd;
  if(!setjmp(exit_env)) { mainCRTStartup(); CHECK(0); }
  rc=exit_code; CHECK(rc==0 && close_rd==1 && !write_calls);
  printf("PERSCHK host %u cases / %u checks (WinAPI modeled; no real cold boot)\n",cases,checks);
  return 0;
}
