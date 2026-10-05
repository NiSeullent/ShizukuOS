/* SPDX-License-Identifier: GPL-2.0-only
 * Runs inside ShizukuOS against its actual NtShzSaw and real PE64 children.
 * Destructive corruption/CHARBOMBA panic paths remain host-injected tests.
 */
#include "../../win64/tests/ipc_test.h"
#include "../../abi/shz_saw.h"
extern LONG WINAPI NtShzSaw(const shz_saw_request *,ULONG,shz_saw_reply *,ULONG);
static shz_saw_reply reply;
static shz_saw_request make_request(unsigned operation)
{
    shz_saw_request q;
    memset(&q,0,sizeof q);q.version=SHZ_SAW_VERSION;q.size=sizeof q;q.operation=operation;
    return q;
}
static int query_pid(DWORD pid,shz_saw_row *out)
{
    shz_saw_request q=make_request(SHZ_SAW_QUERY);
    LONG st=NtShzSaw(&q,sizeof q,&reply,sizeof reply);
    if(st||reply.version!=SHZ_SAW_VERSION||reply.count>SHZ_SAW_MAX_ROWS)return 0;
    for(unsigned i=0;i<reply.count;i++)if(reply.rows[i].pid==pid){*out=reply.rows[i];return 1;}
    return 0;
}
static int child_mode(const char *mode)
{
    if(!strcmp(mode,"--tree")) {
        /* Spawn while the parent races NUKE. Admission must include a child
         * or refuse it after the fence, never leave an escaped running child. */
        for(unsigned i=0;i<8;i++) {
            PROCESS_INFORMATION pi;HANDLE h=ipc_spawn_self("--wait",0,FALSE,0,&pi);
            if(!h)break;
            CloseHandle(pi.hThread);
            CloseHandle(h);Sleep(2);
        }
    }
    for(;;)Sleep(1000);
    return 0;
}
static LONG execute(const shz_saw_row *target,unsigned operation)
{
    shz_saw_request q=make_request(operation);
    q.pid=target->pid;q.generation=target->generation;q.wait_ms=SHZ_SAW_MAX_WAIT_MS;
    return NtShzSaw(&q,sizeof q,&reply,sizeof reply);
}
static void test_single(void)
{
    PROCESS_INFORMATION pi;
    HANDLE child=ipc_spawn_self("--wait",CREATE_SUSPENDED,FALSE,0,&pi);
    shz_saw_row row;memset(&row,0,sizeof row);
    CHECK(child!=0,"create actual suspended PE64 child");if(!child)return;
    CloseHandle(pi.hThread);
    CHECK(query_pid(pi.dwProcessId,&row),"query actual process identity and generation");
    if(!row.generation){TerminateProcess(child,1);WaitForSingleObject(child,2000);CloseHandle(child);return;}
    CHECK(row.classification==SHZ_SAW_NORMAL,"suspended process is not classified as zombie");
    shz_saw_request stale=make_request(SHZ_SAW_SINGLE);stale.pid=row.pid;stale.generation=row.generation+1;
    CHECK(NtShzSaw(&stale,sizeof stale,&reply,sizeof reply)==(LONG)0xc000000b,"generation mismatch rejects mutation");
    CHECK(WaitForSingleObject(child,0)==WAIT_TIMEOUT,"stale identity leaves real child alive");
    LONG st=execute(&row,SHZ_SAW_SINGLE);
    CHECK(st==0&&reply.targets==1&&reply.completed==1&&!(reply.flags&SHZ_SAW_REPLY_PENDING),"SAW acknowledges real teardown completion");
    CHECK(WaitForSingleObject(child,0)==WAIT_OBJECT_0,"actual process handle is signaled after SAW");
    CHECK(query_pid(pi.dwProcessId,&row)&&row.classification==SHZ_SAW_ADMISSED&&row.reasons&SHZ_SAW_REASON_WAIT_REFS,
          "held exit-status handle is intentional ADMISSED residual");
    st=execute(&row,SHZ_SAW_SINGLE);
    CHECK(st==0&&(reply.flags&SHZ_SAW_REPLY_ADMITTED)&&!reply.completed,"SAW preserves legitimate NT exit-status object");
    CloseHandle(child);
}
static void test_tree(void)
{
    PROCESS_INFORMATION pi;HANDLE child=ipc_spawn_self("--tree",0,FALSE,0,&pi);
    shz_saw_row row;int found=0;DWORD start=GetTickCount();memset(&row,0,sizeof row);
    CHECK(child!=0,"create actual process tree spawner");if(!child)return;
    CloseHandle(pi.hThread);
    do {
        if(query_pid(pi.dwProcessId,&row))for(unsigned i=0;i<reply.count;i++)
            if(reply.rows[i].parent_pid==pi.dwProcessId){found=1;break;}
        if(!found)Sleep(1);
    }while(!found&&GetTickCount()-start<3000);
    CHECK(found,"observe actual child relationship before NUKE");
    if(!found){TerminateProcess(child,1);WaitForSingleObject(child,2000);CloseHandle(child);return;}
    LONG st=execute(&row,SHZ_SAW_NUKE);
    CHECK(st==0&&reply.targets>=2&&reply.completed==reply.targets&&!(reply.flags&SHZ_SAW_REPLY_PENDING),
          "NUKE completes actual descendants and root");
    CHECK(WaitForSingleObject(child,0)==WAIT_OBJECT_0,"tree root actual process handle signaled");
    for(unsigned i=0;i<reply.count;i++)CHECK(reply.rows[i].lifecycle==SHZ_SAW_EXITED&&reply.rows[i].status==0,
                                         "acquired tree target actually exited");
    CloseHandle(child);
}
static void test_protection_if_present(void)
{
    shz_saw_request q=make_request(SHZ_SAW_QUERY);
    if(NtShzSaw(&q,sizeof q,&reply,sizeof reply))return;
    shz_saw_row protected_row;int found=0;
    for(unsigned i=0;i<reply.count;i++)if(reply.rows[i].protection&&reply.rows[i].pid!=GetCurrentProcessId()) {
        protected_row=reply.rows[i];found=1;break;
    }
    if(!found){printf("SKIP: no protected kernel-owned desktop process in this autorun profile\n");return;}
    CHECK(execute(&protected_row,SHZ_SAW_SINGLE)==(LONG)0xc0000022&&reply.flags&SHZ_SAW_REPLY_PROTECTED,
          "ordinary SAW refuses actual protected desktop boundary");
}
int main(int argc,char **argv)
{
    if(argc>1)return child_mode(argv[1]);
    test_single();test_tree();test_protection_if_present();
    printf("T_SAW_NATIVE: result %s failures=%d\n",g_bad?"FAIL":"PASS",g_bad);
    return g_bad;
}
