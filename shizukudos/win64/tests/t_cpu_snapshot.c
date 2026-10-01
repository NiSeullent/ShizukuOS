/* SPDX-License-Identifier: GPL-2.0-only; genuine private CPU snapshot boundary. */
#include "k32test.h"
LONG NTAPI NtQuerySystemInformation(ULONG,PVOID,ULONG,PULONG);
static ULONGLONG value(FILETIME f){return ((ULONGLONG)f.dwHighDateTime<<32)|f.dwLowDateTime;}
int main(void)
{
    ULONGLONG times[3]={0},guard[4]={11,22,33,44};ULONG required=0;LONG status;FILETIME idle,kernel,user;
    status=NtQuerySystemInformation(0x102,times,sizeof times,&required);
    CHECK(status==0&&required==24,"private CPU snapshot reports exact 24-byte extent");
    CHECK(times[1]>=times[0],"snapshot includes idle in actual kernel time");
    required=0;status=NtQuerySystemInformation(0x102,guard,23,&required);
    CHECK(status==(LONG)0xc0000004&&required==24,"short snapshot reports INFO_LENGTH_MISMATCH and actual extent");
    CHECK(guard[0]==11&&guard[1]==22&&guard[2]==33&&guard[3]==44,"short snapshot never writes partial CPU data");
    required=0;status=NtQuerySystemInformation(0x102,(void*)1,24,&required);
    CHECK(status==(LONG)0xc0000005&&required==24,"invalid snapshot output is access violation, not kernel fault");
    status=NtQuerySystemInformation(0x102,times,sizeof times,(ULONG*)1);
    CHECK(status==(LONG)0xc0000005,"invalid return-length output is access violation");
    CHECK(GetSystemTimes(&idle,NULL,NULL),"GetSystemTimes supports only idle output");
    CHECK(GetSystemTimes(NULL,&kernel,NULL),"GetSystemTimes supports only kernel output");
    CHECK(GetSystemTimes(NULL,NULL,&user),"GetSystemTimes supports only user output");
    CHECK(value(kernel)>=value(idle),"mixed optional output calls retain actual kernel/idle ordering");
    CHECK(GetSystemTimes(NULL,NULL,NULL),"all optional outputs absent is a valid snapshot");
    return k32t_finish("T_CPU_SNAPSHOT");
}
