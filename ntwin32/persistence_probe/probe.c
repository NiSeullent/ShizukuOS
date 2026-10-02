/* SPDX-License-Identifier: GPL-2.0-only -- explicit manual testing probe only.
 * No CRT, automatic boot changes, file overwrite, delete or persistence claim. */
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include "probe.h"
#define COMMAND_LIMIT 512u
#define NONCE_BYTES 64u
#define MARKER_BYTES 75u

static int space(char c) { return c==' ' || c=='\t'; }
static char upper(char c) { return c>='a' && c<='z' ? (char)(c-'a'+'A') : c; }
static int same(const char *a,const char *b) {
  while(*a && *b && *a==*b) { ++a; ++b; }
  return *a==*b;
}
static int token(const char **at,char *out,DWORD bound) {
  DWORD n=0;
  while(space(**at)) ++*at;
  while(**at && !space(**at)) {
    if(n+1>=bound || **at=='"') return 0;
    out[n++]=*(*at)++;
  }
  out[n]=0; return n!=0;
}
static int path_allowed(const char *path) {
  char stem[9],name[13]; DWORD base=0,ext=0,n=0; const char *p;
  static const char *const boot_names[]={"AUTOEXEC.BAT","CONFIG.SYS","COMMAND.COM","IO.SYS","MSDOS.SYS",
    "WIN.COM","WINSTART.BAT","WININIT.INI","WINBOOT.INI","SYSTEM.DAT","USER.DAT","SYSTEM.INI",
    "WIN.INI","BOOT.INI","SHZSTART.BAT","SHZSTART.COM"};
  if(path[0]!='C' || path[1]!=':' || path[2]!='\\') return 0;
  p=path+3;
  while(*p && *p!='.') {
    char c=upper(*p++);
    if(base==8 || !((c>='A' && c<='Z') || (c>='0' && c<='9') || c=='_')) return 0;
    stem[base++]=c; name[n++]=c;
  }
  if(!base) return 0;
  stem[base]=0;
  if(*p=='.') {
    ++p; name[n++]='.';
    while(*p) {
      char c=upper(*p++);
      if(ext==3 || !((c>='A' && c<='Z') || (c>='0' && c<='9') || c=='_')) return 0;
      name[n++]=c; ++ext;
    }
    if(!ext) return 0;
  }
  name[n]=0;
  if(same(stem,"CON") || same(stem,"PRN") || same(stem,"AUX") || same(stem,"NUL")) return 0;
  if(base==4 && ((stem[0]=='C' && stem[1]=='O' && stem[2]=='M') ||
                (stem[0]=='L' && stem[1]=='P' && stem[2]=='T')) && stem[3]>='0' && stem[3]<='9') return 0;
  for(n=0;n<sizeof boot_names/sizeof boot_names[0];++n) if(same(name,boot_names[n])) return 0;
  return 1;
}
static int parse(const char *command,int *create,char *path,char *nonce) {
  DWORD i=0; char mode[7]; const char *p;
  if(!command) return 0;
  while(i<COMMAND_LIMIT && command[i]) {
    unsigned char c=(unsigned char)command[i++];
    if((c<32 && c!='\t') || c>126) return 0;
  }
  if(!i || i==COMMAND_LIMIT) return 0;
  p=command; while(space(*p)) ++p;
  if(*p=='"') {
    const char *first=++p;
    while(*p && *p!='"') ++p;
    if(!*p || p==first) return 0;
    ++p; if(*p && !space(*p)) return 0;
  } else {
    const char *first=p;
    while(*p && !space(*p)) { if(*p=='"') return 0; ++p; }
    if(p==first) return 0;
  }
  if(!token(&p,mode,sizeof mode) || !token(&p,path,16) || !token(&p,nonce,65)) return 0;
  while(space(*p)) ++p;
  if(*p || !path_allowed(path)) return 0;
  if(same(mode,"create")) *create=1;
  else if(same(mode,"verify")) *create=0;
  else return 0;
  for(i=0;i<NONCE_BYTES;++i) {
    char c=nonce[i];
    if(!((c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F'))) return 0;
  }
  return nonce[NONCE_BYTES]==0;
}
static int write_all(HANDLE handle,const char *data,DWORD bytes) {
  DWORD at=0;
  while(at<bytes) {
    DWORD got=0;
    if(!WriteFile(handle,data+at,bytes-at,&got,NULL) || !got || got>bytes-at) return 0;
    at+=got;
  }
  return 1;
}
static DWORD create_marker(const char *path,const char *expected) {
  DWORD rc=0;
  HANDLE handle=CreateFileA(path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
  if(handle==INVALID_HANDLE_VALUE) return 40;
  if(!write_all(handle,expected,MARKER_BYTES)) rc=41;
  else if(!FlushFileBuffers(handle)) rc=42;
  if(!CloseHandle(handle)) rc=43;
  return rc;
}
static DWORD verify_marker(const char *path,const char *expected) {
  DWORD high=0,at=0,got=0,rc=0,i; char data[MARKER_BYTES],extra;
  HANDLE handle=CreateFileA(path,GENERIC_READ,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
  if(handle==INVALID_HANDLE_VALUE) return 50;
  if(GetFileSize(handle,&high)!=MARKER_BYTES || high) rc=51;
  while(!rc && at<MARKER_BYTES) {
    got=0;
    if(!ReadFile(handle,data+at,MARKER_BYTES-at,&got,NULL) || !got || got>MARKER_BYTES-at) rc=52;
    else at+=got;
  }
  if(!rc && (!ReadFile(handle,&extra,1,&got,NULL) || got)) rc=53;
  if(!rc) for(i=0;i<MARKER_BYTES;++i) if(data[i]!=expected[i]) { rc=54; break; }
  if(!CloseHandle(handle)) rc=55;
  return rc;
}
static int emit_success(HANDLE output,int create,const char *path,const char *nonce) {
  const char *prefix=create ? "PERSCHK CREATE VERIFIED " : "PERSCHK VERIFY VERIFIED ";
  char line[128]; DWORD n=0,i;
  while(*prefix) line[n++]=*prefix++;
  while(*path) line[n++]=*path++;
  line[n++]=' ';
  for(i=0;i<NONCE_BYTES;++i) line[n++]=nonce[i];
  line[n++]='\r'; line[n++]='\n';
  return write_all(output,line,n);
}
DWORD perschk_run(const char *command) {
  char path[16],nonce[65],expected[MARKER_BYTES]; DWORD i,rc=0,version; int create=0;
  HANDLE output;
  if(!parse(command,&create,path,nonce)) rc=10;
  if(!rc) {
    version=GetVersion();
    if((version & 0xffffu)!=0x0a04u || !(version & 0x80000000u)) rc=20;
  }
  output=GetStdHandle(STD_OUTPUT_HANDLE);
  if(!output || output==INVALID_HANDLE_VALUE) return rc ? rc : 30;
  if(!rc) {
    static const char prefix[]="PERSCHK1 ";
    for(i=0;i<9;++i) expected[i]=prefix[i];
    for(i=0;i<NONCE_BYTES;++i) expected[9+i]=nonce[i];
    expected[73]='\r'; expected[74]='\n';
    if(create) rc=create_marker(path,expected);
    if(!rc) rc=verify_marker(path,expected);
  }
  if(rc) { static const char failure[]="PERSCHK FAILED\r\n"; (void)write_all(output,failure,sizeof failure-1); return rc; }
  return emit_success(output,create,path,nonce) ? 0 : 60;
}
void mainCRTStartup(void) { ExitProcess(perschk_run(GetCommandLineA())); }
