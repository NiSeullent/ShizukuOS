/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Native Files/editor work engine. Uses the existing Win32 -> NT -> fsnode ->
 * mounted-volume path exclusively. Copy/verification runs on a native worker;
 * the caller's UI never waits for a disk stream. Current backend limitations
 * (UTF8 bounds, no full ShareAccess isolation) are explicitly retained.
 */
#include "shzcrt.h"
#include "fileops.h"
#include "shz_auth.h"
#include <stddef.h>
__declspec(dllimport) LONG WINAPI NtShzToken(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR);

#define CHUNK 32768u
#define TRASH_DIR L".ShizukuTrash"
struct SHZ_FILE_JOB {
    volatile LONG references, cancel;
    CRITICAL_SECTION lock;
    HANDLE thread; /* UI-owned handle; worker never touches it. */
    SHZ_FILE_OPERATION op;
    BOOL replace;
    WCHAR source[SHZ_FILE_PATH_CAP], destination[SHZ_FILE_PATH_CAP];
    BYTE *blob;
    DWORD blob_size;
    SHZ_FILE_RESULT result;
    int slot;
};
typedef struct {
    BYTE magic[8];
    DWORD version, bytes;
    ULONGLONG file_size, content_hash, record_hash;
    DWORD path_chars, reserved;
    WCHAR original[SHZ_FILE_PATH_CAP];
} TRASH_RECORD;
typedef char record_layout[(offsetof(TRASH_RECORD, original) == 48 && sizeof(TRASH_RECORD) == 568) ? 1 : -1];
static volatile LONG sequence;
/* Registry protects only weak HWND copies. Worker lifetime references protect
 * jobs. No I/O or window message is sent while holding this small lock. */
#define MAX_JOBS 16
static volatile LONG registry_lock, active_operations, file_generation;
static SHZ_FILE_JOB *jobs[MAX_JOBS];
static HWND owners[MAX_JOBS];
static void registry_enter(void) {
    while (InterlockedCompareExchange(&registry_lock,1,0)) Sleep(0);
}
static void registry_leave(void) { InterlockedExchange(&registry_lock,0); }
static BOOL register_job(SHZ_FILE_JOB *job) {
    int i;
    registry_enter();
    for(i=0;i<MAX_JOBS;i++)if(!jobs[i])break;
    if(i<MAX_JOBS){jobs[i]=job;owners[i]=NULL;job->slot=i;InterlockedIncrement(&active_operations);}
    registry_leave();
    if(i==MAX_JOBS){SetLastError(ERROR_BUSY);return FALSE;}
    return TRUE;
}
static void unregister_job(SHZ_FILE_JOB *job) {
    registry_enter();
    if(job->slot>=0&&job->slot<MAX_JOBS&&jobs[job->slot]==job){jobs[job->slot]=NULL;owners[job->slot]=NULL;}
    registry_leave();
}
void ShzFileJobSetOwner(SHZ_FILE_JOB *job,HWND owner) {
    if(!job)return;
    registry_enter();
    if(job->slot>=0&&job->slot<MAX_JOBS&&jobs[job->slot]==job)owners[job->slot]=owner;
    registry_leave();
}
BOOL ShzFileOpsCanExit(void) {
    HWND live[MAX_JOBS];int i;DWORD pid;WCHAR cls[32];
    if(!InterlockedCompareExchange(&active_operations,0,0))return TRUE;
    registry_enter();for(i=0;i<MAX_JOBS;i++)live[i]=owners[i];registry_leave();
    for(i=0;i<MAX_JOBS;i++)if(live[i]&&IsWindow(live[i])&&
        GetWindowThreadProcessId(live[i],&pid)&&pid==GetCurrentProcessId()&&
        GetClassNameW(live[i],cls,32)>0) {
        const WCHAR *a=cls,*b=L"ShizukuFiles";
        while(*a&&*a==*b){++a;++b;}
        if(!*a&&!*b){PostMessageW(live[i],SHZ_FILEOPS_EXIT_BLOCKED,0,0);SetForegroundWindow(live[i]);break;}
    }
    SetLastError(ERROR_BUSY);return FALSE;
}
DWORD ShzFileOpsGeneration(void){return (DWORD)InterlockedCompareExchange(&file_generation,0,0);}

static size_t length(const WCHAR *s) { size_t n = 0; if (s) while (n<SHZ_FILE_PATH_CAP && s[n]) ++n; return n; }
static WCHAR fold(WCHAR c) { return c >= L'a' && c <= L'z' ? (WCHAR)(c - 32) : c; }
static BOOL equal(const WCHAR *a, const WCHAR *b) {
    while (*a && fold(*a) == fold(*b)) { ++a; ++b; }
    return *a == *b;
}
static BOOL copy(WCHAR *to, const WCHAR *from) {
    size_t n = length(from);
    if (!from || n >= SHZ_FILE_PATH_CAP) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
    memcpy(to, from, (n + 1) * sizeof(WCHAR)); return TRUE;
}
static BOOL append(WCHAR *to, const WCHAR *tail) {
    size_t n = length(to), z = length(tail);
    if (n + z >= SHZ_FILE_PATH_CAP) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
    memcpy(to + n, tail, (z + 1) * sizeof(WCHAR)); return TRUE;
}
static BOOL reserved_name(const WCHAR *s, size_t n) {
    WCHAR base[9]; size_t k = 0;
    while (k < n && s[k] != L'.' && k < 8) { base[k] = fold(s[k]); ++k; }
    base[k] = 0;
    return equal(base,L"CON") || equal(base,L"PRN") || equal(base,L"AUX") || equal(base,L"NUL") ||
           equal(base,L"CLOCK$") || (k == 4 && ((base[0]==L'C' && base[1]==L'O' && base[2]==L'M') ||
           (base[0]==L'L' && base[1]==L'P' && base[2]==L'T')) && base[3]>=L'1' && base[3]<=L'9');
}
BOOL ShzFilePathValidW(const WCHAR *path) {
    size_t i, n = length(path), begin = 3;
    unsigned bytes = 3, component = 0;
    DWORD error = ERROR_INVALID_NAME;
    if (!path || n < 3 || n + 4 >= 260 || fold(path[0]) < L'A' || fold(path[0]) > L'Z' ||
        path[1] != L':' || path[2] != L'\\') goto fail;
    for (i = 3; i < n; ++i) {
        unsigned c = path[i], add;
        if (c == L'\\') {
            if (!component || path[i-1] == L'.' || path[i-1] == L' ' || reserved_name(path + begin, i-begin)) goto fail;
            ++bytes; component = 0; begin = i + 1; continue;
        }
        if (c < 32 || c == L'/' || c == L':' || c == L'*' || c == L'?' || c == L'"' || c == L'<' || c == L'>' || c == L'|') goto fail;
        if (c >= 0xd800 && c < 0xdc00) {
            if (i + 1 >= n || path[i+1] < 0xdc00 || path[i+1] > 0xdfff) goto fail;
            ++i; add = 4;
        } else {
            if (c >= 0xdc00 && c <= 0xdfff) goto fail;
            add = c < 0x80 ? 1 : c < 0x800 ? 2 : 3;
        }
        component += add; bytes += add;
        if (component >= 128 || bytes + 4 >= 300) { error = ERROR_FILENAME_EXCED_RANGE; goto fail; }
    }
    if (component && (path[n-1] == L'.' || path[n-1] == L' ' || reserved_name(path + begin, n-begin))) goto fail;
    return TRUE;
fail: SetLastError(error); return FALSE;
}
static BOOL parent_path(const WCHAR *path, WCHAR out[SHZ_FILE_PATH_CAP]) {
    size_t n;
    if (!ShzFilePathValidW(path) || !copy(out, path)) return FALSE;
    n = length(out);
    while (n > 3 && out[n-1] != L'\\') out[--n] = 0;
    if (n < 3) { SetLastError(ERROR_INVALID_NAME); return FALSE; }
    out[n] = 0; return TRUE;
}
static BOOL ensure_directory(const WCHAR *path) {
    DWORD attrs;
    if (!ShzFilePathValidW(path)) return FALSE;
    attrs = GetFileAttributesW(path);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        if (!(attrs & FILE_ATTRIBUTE_DIRECTORY) || (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) { SetLastError(ERROR_DIRECTORY); return FALSE; }
        return TRUE;
    }
    if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND) return FALSE;
    if (!CreateDirectoryW(path, NULL)) return FALSE;
    InterlockedIncrement(&file_generation);
    attrs = GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) { SetLastError(ERROR_DIRECTORY); return FALSE; }
    return TRUE;
}
static BOOL flush_path(const WCHAR *path, BOOL directory) {
    DWORD e = 0;
    HANDLE h = CreateFileW(path, directory ? FILE_WRITE_ATTRIBUTES : GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                          directory ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    if (!FlushFileBuffers(h)) e = GetLastError();
    if (!CloseHandle(h) && !e) e = GetLastError();
    if (e) { SetLastError(e); return FALSE; }
    return TRUE;
}
BOOL ShzFileDocumentsPathW(WCHAR out[SHZ_FILE_PATH_CAP]) {
    WCHAR profile[SHZ_FILE_PATH_CAP];DWORD n;size_t i=9;uint32_t uid=0;
    if(!out){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    out[0]=0;SetLastError(0);
    n=GetEnvironmentVariableW(L"USERPROFILE",profile,SHZ_FILE_PATH_CAP);
    if(!n){
        if(GetLastError()==ERROR_ENVVAR_NOT_FOUND)return copy(out,L"E:\\SHZ\\DOCUMENTS");
        SetLastError(ERROR_INVALID_NAME);return FALSE;
    }
    if(n>=SHZ_FILE_PATH_CAP){SetLastError(ERROR_FILENAME_EXCED_RANGE);return FALSE;}
    if(!ShzFilePathValidW(profile)){return FALSE;}
    if(n<10||fold(profile[0])!=L'E'||profile[1]!=L':'||profile[2]!=L'\\'||
       fold(profile[3])!=L'U'||fold(profile[4])!=L'S'||fold(profile[5])!=L'E'||
       fold(profile[6])!=L'R'||fold(profile[7])!=L'S'||profile[8]!=L'\\'){
        SetLastError(ERROR_NOT_SUPPORTED);return FALSE;
    }
    if(profile[i]==L'0'){SetLastError(ERROR_INVALID_NAME);return FALSE;}
    while(profile[i]>=L'0'&&profile[i]<=L'9'){
        unsigned digit=(unsigned)(profile[i++]-L'0');
        if(uid>(UINT32_MAX-digit)/10){SetLastError(ERROR_INVALID_NAME);return FALSE;}
        uid=uid*10+digit;
    }
    if(!uid||profile[i]){SetLastError(ERROR_INVALID_NAME);return FALSE;}
    return copy(out,profile)&&append(out,L"\\Documents")&&ShzFilePathValidW(out);
}
static void decimal(WCHAR out[11],uint32_t value){
    WCHAR reverse[10];unsigned i=0,k=0;
    do{reverse[i++]=(WCHAR)(L'0'+value%10);value/=10;}while(value);
    while(i)out[k++]=reverse[--i];
    out[k]=0;
}
BOOL ShzFileResolveDocumentsW(WCHAR out[SHZ_FILE_PATH_CAP],BOOL create) {
    WCHAR candidate[SHZ_FILE_PATH_CAP],expected[SHZ_FILE_PATH_CAP],digits[11],profile[SHZ_FILE_PATH_CAP];
    shz_auth_reply reply;DWORD attrs;LONG st;
    if(!out){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    out[0]=0;
    if(!ShzFileDocumentsPathW(candidate))return FALSE;
    memset(&reply,0,sizeof reply);
    st=NtShzToken(SHZ_AUTH_QUERY,0,sizeof reply,(ULONG_PTR)&reply);
    if(st||reply.version!=SHZ_AUTH_VERSION||reply.reserved||reply.subject.reserved||
       reply.accounts>SHZ_ACCOUNT_LIMIT){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    if(!reply.subject.uid){
        /* Concrete anonymous legacy subject, no enrolled realm accounts.
         * Sealed-store/write policy is still enforced by every real NT call. */
        if(reply.accounts||reply.subject.session||reply.subject.roles||reply.subject.flags||
           reply.subject.auth_id!=0x4e7||reply.subject.integrity!=0x2000||
           !equal(candidate,L"E:\\SHZ\\DOCUMENTS")){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
        copy(profile,L"E:\\SHZ");
    }else{
        if(reply.subject.uid<1000||reply.subject.uid>=1000+reply.accounts||
           !reply.subject.session||reply.subject.auth_id!=(((uint64_t)reply.subject.uid<<32)|reply.subject.session)||
           (create&&(reply.subject.flags||reply.subject.integrity<0x2000))){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
        decimal(digits,reply.subject.uid);copy(profile,L"E:\\Users\\");append(profile,digits);
        copy(expected,profile);append(expected,L"\\Documents");
        if(!equal(candidate,expected)){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    }
    if (!(GetLogicalDrives() & (1u << ('E'-'A')))) { SetLastError(ERROR_PATH_NOT_FOUND); return FALSE; }
    if(create){
        if(!ensure_directory(profile)||!ensure_directory(candidate)||!flush_path(candidate,TRUE))return FALSE;
    }else{
        attrs=GetFileAttributesW(candidate);
        if(attrs==INVALID_FILE_ATTRIBUTES)return FALSE;
        if(!(attrs&FILE_ATTRIBUTE_DIRECTORY)||(attrs&FILE_ATTRIBUTE_REPARSE_POINT)){SetLastError(ERROR_DIRECTORY);return FALSE;}
    }
    return copy(out,candidate);
}
BOOL ShzFileDefaultDocumentsW(WCHAR out[SHZ_FILE_PATH_CAP]) {
    return ShzFileResolveDocumentsW(out,TRUE);
}
BOOL ShzFileTrashDirectoryW(const WCHAR *source, WCHAR out[SHZ_FILE_PATH_CAP]) {
    return parent_path(source, out) && append(out, TRASH_DIR) && ShzFilePathValidW(out);
}
static BOOL cancelled(SHZ_FILE_JOB *job) { return job && InterlockedCompareExchange(&job->cancel,0,0); }
static void progress(SHZ_FILE_JOB *job, ULONGLONG total, ULONGLONG done) {
    if (job) { EnterCriticalSection(&job->lock); job->result.total_bytes = total;
        job->result.completed_bytes = done; LeaveCriticalSection(&job->lock); }
}
static ULONGLONG hash_bytes(ULONGLONG h, const void *bytes, size_t n) {
    const BYTE *p = bytes; while (n--) { h ^= *p++; h *= 1099511628211ull; } return h;
}
static BOOL seek_zero(HANDLE h) { LARGE_INTEGER zero; zero.QuadPart = 0; return SetFilePointerEx(h, zero, NULL, FILE_BEGIN); }
static BOOL write_full(HANDLE h, const BYTE *bytes, DWORD count) {
    DWORD at = 0;
    while (at < count) { DWORD put = 0;
        if (!WriteFile(h, bytes + at, count-at, &put, NULL)) return FALSE;
        if (!put || put > count-at) { SetLastError(ERROR_WRITE_FAULT); return FALSE; }
        at += put;
    }
    return TRUE;
}
static BOOL read_full(HANDLE h, BYTE *bytes, DWORD count) {
    DWORD at = 0;
    while (at < count) { DWORD got = 0;
        if (!ReadFile(h, bytes+at, count-at, &got, NULL)) return FALSE;
        if (!got || got > count-at) { SetLastError(ERROR_HANDLE_EOF); return FALSE; }
        at += got;
    }
    return TRUE;
}
static BOOL missing(const WCHAR *path) {
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) { SetLastError(ERROR_FILE_EXISTS); return FALSE; }
    return GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND;
}
static BOOL remove_checked(const WCHAR *path) {
    if (!DeleteFileW(path)) return FALSE;
    if (!missing(path)) { SetLastError(ERROR_DELETE_PENDING); return FALSE; }
    return TRUE; /* Namespace gone. Current NT backend does not promise reclaimed disk blocks/ShareAccess isolation. */
}
static HANDLE open_regular(const WCHAR *path, BOOL writable, BY_HANDLE_FILE_INFORMATION *info) {
    HANDLE h = CreateFileW(path, GENERIC_READ | (writable ? GENERIC_WRITE : 0), FILE_SHARE_READ,
                          NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    DWORD e = 0;
    if (h == INVALID_HANDLE_VALUE) return h;
    if (!GetFileInformationByHandle(h, info)) e = GetLastError();
    else if (info->dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) e = ERROR_NOT_SUPPORTED;
    if (e) { CloseHandle(h); SetLastError(e); return INVALID_HANDLE_VALUE; }
    return h;
}
static ULONGLONG info_size(const BY_HANDLE_FILE_INFORMATION *info) {
    return ((ULONGLONG)info->nFileSizeHigh << 32) | info->nFileSizeLow;
}
static BOOL same_version(const BY_HANDLE_FILE_INFORMATION *a, const BY_HANDLE_FILE_INFORMATION *b) {
    return a->dwVolumeSerialNumber == b->dwVolumeSerialNumber && a->nFileIndexHigh == b->nFileIndexHigh &&
           a->nFileIndexLow == b->nFileIndexLow && info_size(a) == info_size(b) &&
           a->ftLastWriteTime.dwHighDateTime == b->ftLastWriteTime.dwHighDateTime &&
           a->ftLastWriteTime.dwLowDateTime == b->ftLastWriteTime.dwLowDateTime;
}
static void hex8(WCHAR *s, DWORD value) {
    static const WCHAR hex[] = L"0123456789abcdef"; unsigned i;
    for (i = 0; i < 8; ++i) s[i] = hex[(value >> (28-i*4)) & 15];
    s[8] = 0;
}
static BOOL unique_path(const WCHAR *parent, const WCHAR *prefix, const WCHAR *suffix, WCHAR out[SHZ_FILE_PATH_CAP]) {
    WCHAR id[9];
    if (!copy(out,parent) || !append(out,prefix)) return FALSE;
    hex8(id,GetCurrentProcessId()); if (!append(out,id) || !append(out,L"-")) return FALSE;
    hex8(id,(DWORD)InterlockedIncrement(&sequence));
    return append(out,id) && append(out,suffix) && ShzFilePathValidW(out);
}
static HANDLE temp_sibling(const WCHAR *destination, WCHAR temp[SHZ_FILE_PATH_CAP]) {
    WCHAR parent[SHZ_FILE_PATH_CAP]; unsigned attempts;
    if (!parent_path(destination,parent)) return INVALID_HANDLE_VALUE;
    for (attempts=0; attempts<32; ++attempts) {
        HANDLE h;
        if (!unique_path(parent,L".shz-",L".tmp",temp)) return INVALID_HANDLE_VALUE;
        h = CreateFileW(temp, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) return h;
        if (GetLastError()!=ERROR_FILE_EXISTS && GetLastError()!=ERROR_ALREADY_EXISTS) return h;
    }
    SetLastError(ERROR_FILE_EXISTS); return INVALID_HANDLE_VALUE;
}
static BOOL publish(const WCHAR *temp, const WCHAR *destination, BOOL replace, SHZ_FILE_RESULT *r) {
    DWORD attrs = GetFileAttributesW(destination);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        if (!replace) { SetLastError(ERROR_FILE_EXISTS); return FALSE; }
        if (attrs & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_REPARSE_POINT)) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    } else if (!missing(destination)) return FALSE;
    /* Only the currently implemented flag is passed. COPY_ALLOWED / delayed
     * moves / WRITE_THROUGH are never sent to the backend that ignores them. */
    if (!MoveFileExW(temp, destination, replace ? MOVEFILE_REPLACE_EXISTING : 0)) return FALSE;
    r->namespace_committed=TRUE; copy(r->result_path,destination);
    if (!flush_path(destination,FALSE)) return FALSE;
    return TRUE;
}
static void failure(SHZ_FILE_RESULT *r, DWORD error, const WCHAR *recovery) {
    r->error = error ? error : ERROR_GEN_FAILURE;
    r->state = r->namespace_committed ? SHZ_FILE_PARTIAL : error==ERROR_REQUEST_ABORTED ? SHZ_FILE_CANCELLED : SHZ_FILE_FAILED;
    if (recovery && *recovery) copy(r->recovery_path,recovery);
}
static BOOL write_verified(const WCHAR *path, const void *bytes, DWORD count, BOOL replace,
                           SHZ_FILE_RESULT *r, SHZ_FILE_JOB *job) {
    WCHAR temp[SHZ_FILE_PATH_CAP] = {0}; BYTE *check = NULL;
    HANDLE h = INVALID_HANDLE_VALUE; DWORD e = 0, at = 0; BOOL own_temp = FALSE;
    memset(r,0,sizeof *r); r->state=SHZ_FILE_RUNNING; r->total_bytes=count;
    if ((!bytes && count) || count>SHZ_FILE_BLOB_CAP) { e=ERROR_INVALID_PARAMETER; goto done; }
    if (!ShzFilePathValidW(path)) { e=GetLastError(); goto done; }
    h=temp_sibling(path,temp); if(h==INVALID_HANDLE_VALUE){e=GetLastError();goto done;}
    own_temp=TRUE;
    check=HeapAlloc(GetProcessHeap(),0,CHUNK); if(!check){e=ERROR_NOT_ENOUGH_MEMORY;goto done;}
    while(at<count) {
        DWORD n=count-at>CHUNK?CHUNK:count-at;
        if(cancelled(job)){e=ERROR_REQUEST_ABORTED;goto done;}
        if(!write_full(h,(const BYTE *)bytes+at,n)){e=GetLastError();goto done;}
        at+=n; progress(job,count,at); r->completed_bytes=at;
    }
    if(!FlushFileBuffers(h)||!seek_zero(h)){e=GetLastError();goto done;}
    at=0;
    while(at<count) {
        DWORD n=count-at>CHUNK?CHUNK:count-at;
        if(cancelled(job)){e=ERROR_REQUEST_ABORTED;goto done;}
        if(!read_full(h,check,n)){e=GetLastError();goto done;}
        if(memcmp(check,(const BYTE *)bytes+at,n)){e=ERROR_CRC;goto done;}
        at+=n;
    }
    if(!CloseHandle(h)){h=INVALID_HANDLE_VALUE;e=GetLastError();goto done;} h=INVALID_HANDLE_VALUE;
    if(cancelled(job)){e=ERROR_REQUEST_ABORTED;goto done;}
    if(!publish(temp,path,replace,r)){e=GetLastError();goto done;}
    r->state=SHZ_FILE_DONE;
done:
    if(h!=INVALID_HANDLE_VALUE&&!CloseHandle(h)&&!e)e=GetLastError();
    if(check)HeapFree(GetProcessHeap(),0,check);
    if(e) {
        if(own_temp&&!r->namespace_committed&&!remove_checked(temp))r->cleanup_error=GetLastError();
        failure(r,e,r->cleanup_error?temp:NULL);
    }
    return !e;
}
BOOL ShzFileWriteVerifiedW(const WCHAR *path,const void *bytes,DWORD count,BOOL replace,SHZ_FILE_RESULT *r) {
    BOOL ok;
    if(!r){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    InterlockedIncrement(&active_operations);
    ok=write_verified(path,bytes,count,replace,r,NULL);
    if(r->namespace_committed)InterlockedIncrement(&file_generation);
    InterlockedDecrement(&active_operations);
    if(!ok)SetLastError(r->error);
    return ok;
}
static BOOL file_hash(const WCHAR *path, ULONGLONG *size, ULONGLONG *hash, SHZ_FILE_JOB *job) {
    BY_HANDLE_FILE_INFORMATION before,after; BYTE *buffer=NULL; HANDLE h=INVALID_HANDLE_VALUE;
    ULONGLONG at=0, digest=14695981039346656037ull; DWORD e=0;
    h=open_regular(path,FALSE,&before); if(h==INVALID_HANDLE_VALUE)return FALSE;
    *size=info_size(&before); buffer=HeapAlloc(GetProcessHeap(),0,CHUNK);
    if(!buffer){e=ERROR_NOT_ENOUGH_MEMORY;goto done;}
    while(at<*size) {
        DWORD n=*size-at>CHUNK?CHUNK:(DWORD)(*size-at);
        if(cancelled(job)){e=ERROR_REQUEST_ABORTED;goto done;}
        if(!read_full(h,buffer,n)){e=GetLastError();goto done;}
        digest=hash_bytes(digest,buffer,n);at+=n;progress(job,*size,at);
    }
    if(!GetFileInformationByHandle(h,&after)){e=GetLastError();goto done;}
    if(!same_version(&before,&after)){e=ERROR_SHARING_VIOLATION;goto done;}
    *hash=digest;
done:
    if(buffer)HeapFree(GetProcessHeap(),0,buffer);
    if(!CloseHandle(h)&&!e)e=GetLastError();
    if(e){SetLastError(e);return FALSE;}return TRUE;
}
static BOOL copy_file(SHZ_FILE_JOB *job, SHZ_FILE_RESULT *r) {
    WCHAR temp[SHZ_FILE_PATH_CAP]={0}; BYTE *a=NULL,*b=NULL; HANDLE from=INVALID_HANDLE_VALUE,to=INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION before,after; ULONGLONG size=0,at=0;DWORD e=0;BOOL own_temp=FALSE;
    if(!ShzFilePathValidW(job->source)||!ShzFilePathValidW(job->destination)){e=GetLastError();goto done;}
    if(equal(job->source,job->destination)){e=ERROR_SHARING_VIOLATION;goto done;}
    from=open_regular(job->source,FALSE,&before);if(from==INVALID_HANDLE_VALUE){e=GetLastError();goto done;}
    size=info_size(&before); r->total_bytes=size;progress(job,size,0);
    to=temp_sibling(job->destination,temp);if(to==INVALID_HANDLE_VALUE){e=GetLastError();goto done;}
    own_temp=TRUE;
    a=HeapAlloc(GetProcessHeap(),0,CHUNK);b=HeapAlloc(GetProcessHeap(),0,CHUNK);
    if(!a||!b){e=ERROR_NOT_ENOUGH_MEMORY;goto done;}
    while(at<size) {
        DWORD n=size-at>CHUNK?CHUNK:(DWORD)(size-at);
        if(cancelled(job)){e=ERROR_REQUEST_ABORTED;goto done;}
        if(!read_full(from,a,n)||!write_full(to,a,n)){e=GetLastError();goto done;}
        at+=n;r->completed_bytes=at;progress(job,size,at);
    }
    if(!FlushFileBuffers(to)||!seek_zero(from)||!seek_zero(to)){e=GetLastError();goto done;}
    at=0;
    while(at<size) {
        DWORD n=size-at>CHUNK?CHUNK:(DWORD)(size-at);
        if(cancelled(job)){e=ERROR_REQUEST_ABORTED;goto done;}
        if(!read_full(from,a,n)||!read_full(to,b,n)){e=GetLastError();goto done;}
        if(memcmp(a,b,n)){e=ERROR_CRC;goto done;}at+=n;
    }
    if(!GetFileInformationByHandle(from,&after)){e=GetLastError();goto done;}
    if(!same_version(&before,&after)){e=ERROR_SHARING_VIOLATION;goto done;}
    if(!CloseHandle(from)){from=INVALID_HANDLE_VALUE;e=GetLastError();goto done;}from=INVALID_HANDLE_VALUE;
    if(!CloseHandle(to)){to=INVALID_HANDLE_VALUE;e=GetLastError();goto done;}to=INVALID_HANDLE_VALUE;
    if(cancelled(job)){e=ERROR_REQUEST_ABORTED;goto done;}
    if(!publish(temp,job->destination,FALSE,r)){e=GetLastError();goto done;}
    r->state=SHZ_FILE_DONE;
done:
    if(from!=INVALID_HANDLE_VALUE&&!CloseHandle(from)&&!e)e=GetLastError();
    if(to!=INVALID_HANDLE_VALUE&&!CloseHandle(to)&&!e)e=GetLastError();
    if(a)HeapFree(GetProcessHeap(),0,a);
    if(b)HeapFree(GetProcessHeap(),0,b);
    if(e){if(own_temp&&!r->namespace_committed&&!remove_checked(temp))r->cleanup_error=GetLastError();failure(r,e,r->cleanup_error?temp:NULL);}
    return !e;
}
static BOOL move_file(SHZ_FILE_JOB *job, SHZ_FILE_RESULT *r) {
    BY_HANDLE_FILE_INFORMATION info; HANDLE h; DWORD e;
    if(!ShzFilePathValidW(job->source)||!ShzFilePathValidW(job->destination))goto fail;
    /* RAM rename currently cannot publish case-only spelling changes. Refuse
     * this unsupported request before changing anything rather than claim it. */
    if(equal(job->source,job->destination)){SetLastError(ERROR_NOT_SUPPORTED);goto fail;}
    /* No cross-volume delete claim until NT close reports actual removal
     * failure. User can copy across volumes; originals remain intact. */
    if(fold(job->source[0])!=fold(job->destination[0])){SetLastError(ERROR_NOT_SAME_DEVICE);goto fail;}
    h=open_regular(job->source,FALSE,&info);if(h==INVALID_HANDLE_VALUE)goto fail;
    e=(info.dwFileAttributes&FILE_ATTRIBUTE_READONLY)?ERROR_ACCESS_DENIED:0;
    if(!CloseHandle(h)&&!e)e=GetLastError();
    if(e){SetLastError(e);goto fail;}
    if(cancelled(job)){SetLastError(ERROR_REQUEST_ABORTED);goto fail;}
    if(!MoveFileExW(job->source,job->destination,0))goto fail;
    r->namespace_committed=TRUE;copy(r->result_path,job->destination);
    if(!missing(job->source)||!flush_path(job->destination,FALSE))goto fail;
    r->state=SHZ_FILE_DONE;return TRUE;
fail: failure(r,GetLastError(),NULL);return FALSE;
}
static BOOL trash_file(SHZ_FILE_JOB *job,SHZ_FILE_RESULT *r) {
    WCHAR dir[SHZ_FILE_PATH_CAP],base[SHZ_FILE_PATH_CAP],data[SHZ_FILE_PATH_CAP],info[SHZ_FILE_PATH_CAP];
    TRASH_RECORD record;SHZ_FILE_RESULT written;DWORD e;unsigned attempt;
    memset(&record,0,sizeof record);memcpy(record.magic,"SHZTRSH1",8);record.version=1;record.bytes=sizeof record;
    if(!ShzFileTrashDirectoryW(job->source,dir)||!copy(base,dir)||!append(base,L"\\")||!ensure_directory(dir))goto fail;
    for(attempt=0;attempt<32;attempt++) {
        if(!unique_path(base,L"",L".bin",data)||!copy(info,data))goto fail;
        {size_t n=length(info);info[n-4]=0;if(!append(info,L".info"))goto fail;}
        if(missing(data)&&missing(info))break;
        if(GetLastError()!=ERROR_FILE_EXISTS)goto fail;
    }
    if(attempt==32){SetLastError(ERROR_FILE_EXISTS);goto fail;}
    if(!file_hash(job->source,&record.file_size,&record.content_hash,job))goto fail;
    if(!copy(record.original,job->source))goto fail;
    record.path_chars=(DWORD)length(record.original);record.record_hash=hash_bytes(14695981039346656037ull,&record,sizeof record);
    if(!write_verified(info,&record,sizeof record,FALSE,&written,job)){*r=written;return FALSE;}
    if(cancelled(job)) {e=ERROR_REQUEST_ABORTED;if(!remove_checked(info))r->cleanup_error=GetLastError();failure(r,e,r->cleanup_error?info:NULL);return FALSE;}
    if(!MoveFileExW(job->source,data,0)) {e=GetLastError();if(!remove_checked(info))r->cleanup_error=GetLastError();failure(r,e,r->cleanup_error?info:NULL);return FALSE;}
    r->namespace_committed=TRUE;copy(r->result_path,data);copy(r->recovery_path,info);
    if(!missing(job->source)||!flush_path(data,FALSE))goto fail;
    {ULONGLONG size,hash;if(!file_hash(data,&size,&hash,NULL))goto fail;
     if(size!=record.file_size||hash!=record.content_hash){SetLastError(ERROR_CRC);goto fail;}}
    r->state=SHZ_FILE_DONE;r->total_bytes=record.file_size;r->completed_bytes=record.file_size;return TRUE;
fail: failure(r,GetLastError(),r->namespace_committed?info:NULL);return FALSE;
}
static BOOL restore_file(SHZ_FILE_JOB *job,SHZ_FILE_RESULT *r) {
    WCHAR info[SHZ_FILE_PATH_CAP],data[SHZ_FILE_PATH_CAP],parent[SHZ_FILE_PATH_CAP],want[SHZ_FILE_PATH_CAP];
    TRASH_RECORD record;HANDLE h=INVALID_HANDLE_VALUE;LARGE_INTEGER actual;DWORD e=0;
    ULONGLONG record_hash,size,hash;size_t n;
    if(!ShzFilePathValidW(job->source)||!copy(info,job->source))goto fail;
    n=length(info);
    if(n>4&&equal(info+n-4,L".bin")){info[n-4]=0;if(!append(info,L".info"))goto fail;}
    n=length(info);
    if(n<5||!equal(info+n-5,L".info")){SetLastError(ERROR_INVALID_NAME);goto fail;}
    if(!copy(data,info))goto fail;
    data[n-5]=0;
    if(!append(data,L".bin"))goto fail;
    h=CreateFileW(info,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE)goto fail;
    if(!GetFileSizeEx(h,&actual)||actual.QuadPart!=sizeof record||!read_full(h,(BYTE *)&record,sizeof record)){e=ERROR_INVALID_DATA;goto close_fail;}
    if(!CloseHandle(h)){h=INVALID_HANDLE_VALUE;goto fail;}h=INVALID_HANDLE_VALUE;
    record_hash=record.record_hash;record.record_hash=0;
    if(memcmp(record.magic,"SHZTRSH1",8)||record.version!=1||record.bytes!=sizeof record||record.reserved||
       record.path_chars<3||record.path_chars>=SHZ_FILE_PATH_CAP||record.original[record.path_chars]||
       length(record.original)!=record.path_chars||record_hash!=hash_bytes(14695981039346656037ull,&record,sizeof record)||
       !ShzFilePathValidW(record.original)){SetLastError(ERROR_INVALID_DATA);goto fail;}
    /* Untrusted sidecar never supplies a payload path. Both payload and
     * destination parent are tied to the real sidecar's same-volume trash. */
    if(!parent_path(info,parent)||!ShzFileTrashDirectoryW(record.original,want)||!append(want,L"\\")||!equal(parent,want)) {
        SetLastError(ERROR_INVALID_DATA);goto fail;
    }
    if(!file_hash(data,&size,&hash,job))goto fail;
    if(size!=record.file_size||hash!=record.content_hash){SetLastError(ERROR_CRC);goto fail;}
    if(cancelled(job)){SetLastError(ERROR_REQUEST_ABORTED);goto fail;}
    if(!MoveFileExW(data,record.original,0))goto fail; /* Collision preserves trash+record and existing document. */
    r->namespace_committed=TRUE;copy(r->result_path,record.original);copy(r->recovery_path,info);
    if(!flush_path(record.original,FALSE)||!file_hash(record.original,&size,&hash,NULL))goto fail;
    if(size!=record.file_size||hash!=record.content_hash){SetLastError(ERROR_CRC);goto fail;}
    if(!remove_checked(info)){r->cleanup_error=GetLastError();goto fail;}
    r->recovery_path[0]=0;r->state=SHZ_FILE_DONE;r->total_bytes=size;r->completed_bytes=size;return TRUE;
close_fail: if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);SetLastError(e);
fail: failure(r,GetLastError(),r->namespace_committed?info:NULL);return FALSE;
}
static void unref(SHZ_FILE_JOB *job) {
    if(!InterlockedDecrement(&job->references)) {
        if(job->blob)HeapFree(GetProcessHeap(),0,job->blob);
        DeleteCriticalSection(&job->lock);HeapFree(GetProcessHeap(),0,job);
    }
}
static DWORD WINAPI worker(void *param) {
    SHZ_FILE_JOB *job=param;SHZ_FILE_RESULT r;memset(&r,0,sizeof r);r.state=SHZ_FILE_RUNNING;
    switch(job->op) {
    case SHZ_FILE_COPY:copy_file(job,&r);break;
    case SHZ_FILE_MOVE:case SHZ_FILE_RENAME:move_file(job,&r);break;
    case SHZ_FILE_TRASH:trash_file(job,&r);break;
    case SHZ_FILE_RESTORE:restore_file(job,&r);break;
    case SHZ_FILE_WRITE:write_verified(job->destination,job->blob,job->blob_size,job->replace,&r,job);break;
    case SHZ_FILE_MKDIR:
        if(cancelled(job))failure(&r,ERROR_REQUEST_ABORTED,NULL);
        else if(!ShzFilePathValidW(job->destination)||!CreateDirectoryW(job->destination,NULL))failure(&r,GetLastError(),NULL);
        else {r.namespace_committed=TRUE;copy(r.result_path,job->destination);
              if(!flush_path(job->destination,TRUE))failure(&r,GetLastError(),NULL);else r.state=SHZ_FILE_DONE;}
        break;
    default:failure(&r,ERROR_INVALID_PARAMETER,NULL);break;
    }
    if(r.namespace_committed)InterlockedIncrement(&file_generation);
    EnterCriticalSection(&job->lock);job->result=r;LeaveCriticalSection(&job->lock);
    unregister_job(job);unref(job);InterlockedDecrement(&active_operations);return 0;
}
SHZ_FILE_JOB *ShzFileJobStart(SHZ_FILE_OPERATION op,const WCHAR *source,const WCHAR *destination,
                            const void *bytes,DWORD count,BOOL replace) {
    SHZ_FILE_JOB *job;DWORD e;
    if(op<SHZ_FILE_COPY||op>SHZ_FILE_WRITE||count>SHZ_FILE_BLOB_CAP||(!bytes&&count)) {SetLastError(ERROR_INVALID_PARAMETER);return NULL;}
    job=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof *job);if(!job){SetLastError(ERROR_NOT_ENOUGH_MEMORY);return NULL;}
    job->references=2;job->op=op;job->replace=replace;job->result.state=SHZ_FILE_RUNNING;job->slot=-1;
    InitializeCriticalSection(&job->lock);
    if((source&&!copy(job->source,source))||(destination&&!copy(job->destination,destination)))goto fail;
    if(count) {job->blob=HeapAlloc(GetProcessHeap(),0,count);if(!job->blob){SetLastError(ERROR_NOT_ENOUGH_MEMORY);goto fail;}
        memcpy(job->blob,bytes,count);job->blob_size=count;}
    if(!register_job(job))goto fail;
    job->thread=CreateThread(NULL,0,worker,job,0,NULL);if(!job->thread)goto fail;
    return job;
fail:e=GetLastError();if(job->slot>=0){unregister_job(job);InterlockedDecrement(&active_operations);}
    job->references=1;unref(job);SetLastError(e);return NULL;
}
void ShzFileJobPoll(SHZ_FILE_JOB *job,SHZ_FILE_RESULT *out) {
    if(!job||!out)return;
    EnterCriticalSection(&job->lock);*out=job->result;LeaveCriticalSection(&job->lock);
}
void ShzFileJobCancel(SHZ_FILE_JOB *job) {if(job)InterlockedExchange(&job->cancel,1);}
void ShzFileJobRelease(SHZ_FILE_JOB *job) {
    if(!job)return;
    ShzFileJobCancel(job);
    if(job->thread)CloseHandle(job->thread);
    unref(job);
}
