/* SPDX-License-Identifier: GPL-2.0-only
 * Additive CRT wrappers around genuine file, directory, environment, process,
 * and console providers. No Wine/Microsoft CRT source is copied. */
#include "crtint.h"
#ifdef SHZ_UCRT_LEGACY_HOST
#include "../../tests/ucrt_legacy_host_contract.h"
#else
#include "crtos.h"
#endif

/* Local declarations for actual kernel32 providers; shared ABI headers stay
 * unchanged. GetBinaryTypeW is looked up because older runtimes lack it. */
IMP_ os_bool WINAPI_ SetFileAttributesW(const wchar16 *, os_dword);
IMP_ unsigned WINAPI_ GetDriveTypeW(const wchar16 *);
extern crt_errno_t CRTAPI _dupenv_s(char **, size_t *, const char *);
extern void CRTAPI abort(void) CRT_NORETURN;

#define LEGACY_PATH_MAX 260u
#define LEGACY_TEXT_MAX 32767u

static void legacy_os_error(os_dword error)
{
    crt_dosmaperr(error ? error : 31); /* ERROR_GEN_FAILURE */
}

static wchar16 *legacy_wide(const char *text)
{
    int count;
    wchar16 *wide;
    size_t length=0;
    while (length < LEGACY_TEXT_MAX && text[length]) ++length;
    if (length == LEGACY_TEXT_MAX) { crt_set_errno(CRT_ENAMETOOLONG); return 0; }
    count=MultiByteToWideChar(OS_CP_ACP,0,text,-1,0,0);
    if (count<=0) { legacy_os_error(GetLastError()); return 0; }
    if ((unsigned)count > LEGACY_TEXT_MAX+1) { crt_set_errno(CRT_ENAMETOOLONG); return 0; }
    wide=crt_malloc((size_t)count*sizeof *wide);
    if (!wide) { crt_set_errno(CRT_ENOMEM); return 0; }
    if (MultiByteToWideChar(OS_CP_ACP,0,text,-1,wide,count)!=count) {
        os_dword error=GetLastError(); crt_free(wide); legacy_os_error(error); return 0;
    }
    return wide;
}

static wchar16 *legacy_absolute(const wchar16 *path)
{
    os_dword required=GetFullPathNameW(path,0,0,0),got;
    wchar16 *absolute;
    if (!required) { legacy_os_error(GetLastError()); return 0; }
    if (required>LEGACY_TEXT_MAX+1) { crt_set_errno(CRT_ENAMETOOLONG); return 0; }
    absolute=crt_malloc((size_t)required*sizeof *absolute);
    if (!absolute) { crt_set_errno(CRT_ENOMEM); return 0; }
    got=GetFullPathNameW(path,required,absolute,0);
    if (!got || got>=required) {
        os_dword error=GetLastError(); crt_free(absolute);
        if (got>=required) crt_set_errno(CRT_ERANGE); else legacy_os_error(error);
        return 0;
    }
    return absolute;
}

DLLAPI int CRTAPI _chmod(const char *path, int mode)
{
    wchar16 *wide;
    os_dword attributes,error;
    CRT_VALIDATE(path != 0, CRT_EINVAL, -1);
    wide=legacy_wide(path); if (!wide) return -1;
    attributes=GetFileAttributesW(wide);
    if (attributes==OS_INVALID_FILE_ATTRIBUTES) {
        error=GetLastError(); crt_free(wide); legacy_os_error(error); return -1;
    }
    /* Windows ignores unrelated mode bits; write permission controls only the
     * readonly attribute. Preserve every other actual file attribute. */
    if (mode & 0x80) attributes &= ~OS_FILE_ATTRIBUTE_READONLY;
    else attributes |= OS_FILE_ATTRIBUTE_READONLY;
    if (!attributes) attributes=OS_FILE_ATTRIBUTE_NORMAL;
    if (!SetFileAttributesW(wide,attributes)) {
        error=GetLastError(); crt_free(wide); legacy_os_error(error); return -1;
    }
    crt_free(wide); return 0;
}

DLLAPI char *CRTAPI _mktemp(char *pattern)
{
    size_t length=0,i;
    unsigned id;
    char letter;
    CRT_VALIDATE(pattern != 0, CRT_EINVAL, 0);
    while (length<LEGACY_TEXT_MAX && pattern[length]) ++length;
    if (length==LEGACY_TEXT_MAX) { pattern[0]=0; crt_set_errno(CRT_ENAMETOOLONG); return 0; }
    if (length<6) { pattern[0]=0; CRT_VALIDATE(0,CRT_EINVAL,0); }
    for (i=length-6;i<length;i++) if (pattern[i]!='X') {
        pattern[0]=0; CRT_VALIDATE(0,CRT_EINVAL,0);
    }
    id=(unsigned)(GetCurrentProcessId()%100000);
    for (i=length;i>length-5;) { --i; pattern[i]=(char)('0'+id%10); id/=10; }
    for (letter='a';letter<='z';++letter) {
        wchar16 *wide;
        os_dword attributes,error;
        pattern[length-6]=letter;
        wide=legacy_wide(pattern);
        if (!wide) { pattern[0]=0; return 0; }
        attributes=GetFileAttributesW(wide); error=GetLastError(); crt_free(wide);
        if (attributes!=OS_INVALID_FILE_ATTRIBUTES) continue;
        /* Only the real file-not-found error proves this candidate absent.
         * A missing directory, denied access, or failed conversion does not. */
        if (error==2) return pattern;
        pattern[0]=0; legacy_os_error(error); return 0;
    }
    pattern[0]=0; crt_set_errno(CRT_EEXIST); return 0;
}

DLLAPI int CRTAPI _resetstkoflw(void)
{
    /* Actual stacks are fully committed, DeallocationStack == StackLimit.
     * Generic one-shot PAGE_GUARD has no overflow/growth recovery protocol. */
    crt_set_errno(CRT_ENOSYS); *crt_doserrno_ptr()=120; return 0;
}

/* Publish a checked absolute narrow path only after the real file lookup. */
static int legacy_search_candidate(const char *candidate, char *out)
{
    wchar16 *wide,*absolute;
    int bytes;
    os_dword attributes,error;
    wide=legacy_wide(candidate); if (!wide) return -1;
    attributes=GetFileAttributesW(wide); error=GetLastError();
    if (attributes==OS_INVALID_FILE_ATTRIBUTES) {
        crt_free(wide); legacy_os_error(error);
        return error==2 || error==3 ? 0 : -1;
    }
    if (attributes & OS_FILE_ATTRIBUTE_DIRECTORY) { crt_free(wide); crt_set_errno(CRT_ENOENT); return 0; }
    absolute=legacy_absolute(wide); crt_free(wide); if (!absolute) return -1;
    bytes=WideCharToMultiByte(OS_CP_ACP,0,absolute,-1,0,0,0,0);
    if (bytes<=0) { os_dword error=GetLastError(); crt_free(absolute); legacy_os_error(error); return -1; }
    if ((unsigned)bytes>LEGACY_PATH_MAX) { crt_free(absolute); crt_set_errno(CRT_ERANGE); return -1; }
    if (WideCharToMultiByte(OS_CP_ACP,0,absolute,-1,out,bytes,0,0)!=bytes) {
        os_dword error=GetLastError(); crt_free(absolute); out[0]=0; legacy_os_error(error); return -1;
    }
    crt_free(absolute); return 1;
}

DLLAPI void CRTAPI _searchenv(const char *filename, const char *variable, char *out)
{
    char *environment=0,*cursor;
    char candidate[LEGACY_PATH_MAX];
    size_t filename_length,length;
    int result,saved_errno=crt_get_errno(); unsigned long saved_dos=*crt_doserrno_ptr();
    CRT_VALIDATE_NORET(out != 0,CRT_EINVAL);
    out[0]=0;
    CRT_VALIDATE_NORET(filename != 0 && variable != 0,CRT_EINVAL);
    filename_length=crt_strlen(filename);
    if (!filename_length) { crt_set_errno(CRT_ENOENT); return; }
    if (filename_length>=LEGACY_PATH_MAX) { crt_set_errno(CRT_ERANGE); return; }
    result=legacy_search_candidate(filename,out);
    if (result==1) { crt_set_errno(saved_errno); *crt_doserrno_ptr()=saved_dos; return; }
    if (result<0) return;
    if (_dupenv_s(&environment,0,variable)!=0) return;
    if (!environment) { crt_set_errno(CRT_ENOENT); return; }
    cursor=environment;
    while (*cursor) {
        int quoted=0,too_long=0;
        length=0;
        while (*cursor && (*cursor!=';' || quoted)) {
            char ch=*cursor++;
            if (ch=='"') { quoted=!quoted; continue; }
            if (length+1<LEGACY_PATH_MAX) candidate[length++]=ch;
            else too_long=1;
        }
        if (*cursor==';') ++cursor;
        /* Always consume the complete component, even when it cannot fit. */
        if (too_long || quoted || !length) continue;
        if (candidate[length-1]!='\\' && candidate[length-1]!='/') {
            if (length+1>=LEGACY_PATH_MAX) continue;
            candidate[length++]='\\';
        }
        if (length+filename_length>=LEGACY_PATH_MAX) continue;
        crt_memcpy(candidate+length,filename,filename_length+1);
        result=legacy_search_candidate(candidate,out);
        if (result) {
            crt_free(environment);
            if (result==1) { crt_set_errno(saved_errno); *crt_doserrno_ptr()=saved_dos; }
            return;
        }
    }
    crt_free(environment); crt_set_errno(CRT_ENOENT);
}

DLLAPI wchar16 *CRTAPI _wgetdcwd(int drive, wchar16 *out, int maximum)
{
    wchar16 root[4]={0},*temporary=0;
    os_dword required,got;
    size_t capacity;
    int allocated=0;
    CRT_VALIDATE(drive>=0 && drive<=26 && maximum>0,CRT_EINVAL,0);
    if (drive) {
        wchar16 letter;
        root[0]=(wchar16)('A'+drive-1); root[1]=':'; root[2]='\\';
        if (GetDriveTypeW(root)<2) { CRT_VALIDATE(0,CRT_EACCES,0); }
        required=GetCurrentDirectoryW(0,0);
        if (!required) { legacy_os_error(GetLastError()); return 0; }
        if (required>LEGACY_TEXT_MAX+1) { crt_set_errno(CRT_ENAMETOOLONG); return 0; }
        temporary=crt_malloc((size_t)required*sizeof *temporary);
        if (!temporary) { crt_set_errno(CRT_ENOMEM); return 0; }
        got=GetCurrentDirectoryW(required,temporary);
        if (!got || got>=required) {
            os_dword error=GetLastError(); crt_free(temporary);
            if (got>=required) crt_set_errno(CRT_ERANGE); else legacy_os_error(error);
            return 0;
        }
        letter=temporary[0];
        if (letter>='a' && letter<='z') letter=(wchar16)(letter-'a'+'A');
        /* The genuine provider keeps one process CWD, with no per-drive state.
         * X:. on another drive falls back to its root and proves no retained CWD. */
        if (got<2 || temporary[1]!=':' || letter!=root[0]) {
            crt_free(temporary); crt_set_errno(CRT_ENOSYS); *crt_doserrno_ptr()=120; return 0;
        }
        required=got+1;
    } else {
        required=GetCurrentDirectoryW(0,0);
        if (!required) { legacy_os_error(GetLastError()); return 0; }
    }
    if (required>LEGACY_TEXT_MAX+1) { crt_free(temporary); crt_set_errno(CRT_ENAMETOOLONG); return 0; }
    capacity=(size_t)maximum;
    if (!out) {
        if (capacity<required) capacity=required;
        out=crt_malloc(capacity*sizeof *out);
        if (!out) { crt_free(temporary); crt_set_errno(CRT_ENOMEM); return 0; }
        allocated=1;
    } else if (capacity<required) {
        crt_free(temporary); crt_set_errno(CRT_ERANGE); return 0;
    }
    if (temporary) { crt_memcpy(out,temporary,(size_t)required*sizeof *out); crt_free(temporary); return out; }
    got=GetCurrentDirectoryW((os_dword)capacity,out);
    if (!got || got>=capacity) {
        os_dword error=GetLastError(); if (allocated) crt_free(out);
        if (got>=capacity) crt_set_errno(CRT_ERANGE); else legacy_os_error(error);
        return 0;
    }
    return out;
}

static void legacy_console_text(const wchar16 *text)
{
    char *bytes;
    int length;
    os_dword written;
    if (!text) return;
    length=WideCharToMultiByte(OS_CP_UTF8,0,text,-1,0,0,0,0);
    if (length<=1 || (unsigned)length>LEGACY_TEXT_MAX+1) return;
    bytes=crt_malloc((size_t)length); if (!bytes) return;
    if (WideCharToMultiByte(OS_CP_UTF8,0,text,-1,bytes,length,0,0)==length)
        WriteFile(GetStdHandle(OS_STD_ERROR),bytes,(os_dword)(length-1),&written,0);
    crt_free(bytes);
}

DLLAPI void CRTAPI _wassert(const wchar16 *expression, const wchar16 *file, unsigned line)
{
    static const wchar16 prefix[]={'A','s','s','e','r','t','i','o','n',' ','f','a','i','l','e','d',':',' ',0};
    static const wchar16 separator[]={',',' ','f','i','l','e',' ',0};
    static const wchar16 line_prefix[]={',',' ','l','i','n','e',' ',0};
    wchar16 digits[11],*end=digits+10;
    *end=0;
    do { *--end=(wchar16)('0'+line%10); line/=10; } while (line);
    legacy_console_text(prefix); legacy_console_text(expression);
    legacy_console_text(separator); legacy_console_text(file);
    legacy_console_text(line_prefix); legacy_console_text(end);
    { static const wchar16 newline[]={'\n',0}; legacy_console_text(newline); }
    abort(); /* Existing real SIGABRT/default process termination. */
}

DLLAPI int CRTAPI system(const char *command)
{
    static const wchar16 kernel32[]={'k','e','r','n','e','l','3','2','.','d','l','l',0};
    typedef os_bool (WINAPI_ *binary_type_fn)(const wchar16 *,os_dword *);
    struct { os_handle process,thread; os_dword pid,tid; } process={0};
    os_startupinfow startup;
    binary_type_fn binary_type;
    char *shell=0,path[LEGACY_PATH_MAX];
    wchar16 *wide_shell=0,*wide_command=0,*line=0;
    size_t shell_length,command_length,total,i;
    os_dword type,error,code=0,waited;
    int result=-1;
    if (_dupenv_s(&shell,0,"COMSPEC")!=0) return command?-1:0;
    if (!shell || !*shell) {
        crt_free(shell); shell=0; _searchenv("cmd.exe","PATH",path);
        if (!path[0]) return command?-1:0;
    }
    wide_shell=legacy_wide(shell?shell:path); crt_free(shell);
    if (!wide_shell) return command?-1:0;
    binary_type=(binary_type_fn)GetProcAddress(GetModuleHandleW(kernel32),"GetBinaryTypeW");
    if (!binary_type) { crt_set_errno(CRT_ENOSYS); *crt_doserrno_ptr()=120; goto done; }
    if (!binary_type(wide_shell,&type)) { legacy_os_error(GetLastError()); goto done; }
    if (type!=6) { crt_set_errno(CRT_ENOEXEC); *crt_doserrno_ptr()=193; goto done; } /* Actual kernel executes AMD64 PE only. */
    if (!command) { result=1; goto done; }
    wide_command=legacy_wide(command); if (!wide_command) goto done;
    shell_length=crt_wcslen(wide_shell); command_length=crt_wcslen(wide_command);
    total=shell_length+command_length+9;
    if (total>LEGACY_TEXT_MAX+1) { crt_set_errno(CRT_E2BIG); goto done; }
    /* CMD receives its documented /c string with outer quotes preserved. */
    line=crt_malloc(total*sizeof *line);
    if (!line) { crt_set_errno(CRT_ENOMEM); goto done; }
    i=0; line[i++]='"'; crt_memcpy(line+i,wide_shell,shell_length*sizeof *line); i+=shell_length;
    line[i++]='"'; line[i++]=' '; line[i++]='/'; line[i++]='c'; line[i++]=' '; line[i++]='"';
    crt_memcpy(line+i,wide_command,command_length*sizeof *line); i+=command_length;
    line[i++]='"'; line[i]=0;
    crt_memset(&startup,0,sizeof startup); startup.cb=sizeof startup;
    startup.dwFlags=0x100; /* STARTF_USESTDHANDLES */
    startup.hStdInput=GetStdHandle(OS_STD_INPUT); startup.hStdOutput=GetStdHandle(OS_STD_OUTPUT); startup.hStdError=GetStdHandle(OS_STD_ERROR);
    if (!CreateProcessW(wide_shell,line,0,0,1,0,0,0,&startup,&process)) {
        legacy_os_error(GetLastError()); goto done;
    }
    waited=WaitForSingleObject(process.process,OS_INFINITE);
    if (waited!=0) { legacy_os_error(GetLastError()); goto handles; }
    if (!GetExitCodeProcess(process.process,&code)) { legacy_os_error(GetLastError()); goto handles; }
    result=(int)code;
handles:
    error=0;
    if (!CloseHandle(process.thread)) error=GetLastError();
    if (!CloseHandle(process.process) && !error) error=GetLastError();
    if (error && result!=-1) { legacy_os_error(error); result=-1; }
done:
    crt_free(line); crt_free(wide_command); crt_free(wide_shell);
    return !command && result==-1?0:result;
}
