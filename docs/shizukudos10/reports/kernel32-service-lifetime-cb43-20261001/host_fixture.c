/* SPDX-License-Identifier: GPL-2.0-only
 * Host adapters for actual Kernel32 main.c/ipc.c. No DOS/Windows/VM execution.
 * Only CPU setup, scheduler sleeps and hypercalls are substituted. IPC channel
 * initialization, frame validation, both rings and all handlers remain real.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>
#include <sys/mman.h>
#include "source/shizukudos/abi/shz_ipc.h"

#define K32_H
#define KVER "Kernel32 host-production fixture"
#define VEC_TIMER 0x20
#define VEC_DOORBELL 0x21
#define TICK_US 1000u
typedef uint32_t hcreg_t;
typedef struct { int unused; } thread_t;
typedef struct { int count; } ksem_t;
static jmp_buf kernel_stop, server_pause;
static thread_t host_thread;
static void (*host_server)(void *);
static unsigned host_server_pass;
static unsigned qa_runs, reports, arch_calls, query_calls, wrong_query_target;
static unsigned failures, reply_count, end_replies, echo_replies, sum_replies, crc_replies, time_replies;
static int exit_code, end_reply_status, scenario;
static uint64_t virtual_ms;
static uint32_t stop_state;
static long query_status;
static uint64_t stop_at;
static int send_end, send_late, sent_end, sent_late;
static shz_ring_hdr_t *host_client_tx, *host_client_rx;
static shz_channel_hdr_t *host_channel;

#define CHECK(c, name) do { if (!(c)) { ++failures; fprintf(stderr, "FAIL %s\n", name); } } while (0)
static void host_panic(const char *file, unsigned line)
{ fprintf(stderr,"production KASSERT %s:%u\n",file,line); exit_code=96; longjmp(kernel_stop,1); }
#define KASSERT(c) do { if (!(c)) host_panic(__FILE__, __LINE__); } while (0)
static void shz_exit(unsigned code) __attribute__((noreturn));
static void shz_exit(unsigned code) { exit_code=(int)code; longjmp(kernel_stop,1); }
static void arch_init(void) { ++arch_calls; }
static void mem_init(const shz_bootinfo_t *bi) { (void)bi; }
static void sched_init(void) { }
static long shz_timer_set(unsigned vector, uint32_t us) { return vector==0x20 && us==1000 ? 0 : -1; }
static void sti(void) { }
static void kprintf(const char *fmt, ...) { (void)fmt; }
static void sem_init(ksem_t *s, int count) { s->count=count; }
static void sem_post(ksem_t *s) { ++s->count; }
static int sem_wait_timeout(ksem_t *s, uint32_t ms)
{ (void)s; (void)ms; if (host_server_pass++) longjmp(server_pause,1); return -1; }
static uint32_t shz_doorbell_ack(void) { return 0; }
static long shz_set_doorbell_vector(unsigned vector) { return vector==0x21 ? 0 : -1; }
static long shz_notify(unsigned domain, uint32_t mask) { return domain==4 && mask==1 ? 0 : -1; }
/* Synthetic 32-bit hypercall value, deliberately no hardware-clock assertion. */
static uint64_t shz_time_ns(void) { return 0x76543210u; }
static long __attribute__((unused)) shz_hcall(hcreg_t op, hcreg_t a, hcreg_t b, hcreg_t *value)
{
    ++query_calls;
    if (op!=SHZ_HC_DOMAIN_STATE || a!=5 || b!=0) ++wrong_query_target;
    if (value) *value = virtual_ms < stop_at ? (virtual_ms/100 % 2 ? 2u : 1u) : stop_state;
    return query_status;
}
static thread_t *thread_create(const char *name, void (*fn)(void *), void *arg)
{ CHECK(!strcmp(name,"ipc-server") && !arg,"real IPC server was selected"); host_server=fn; return &host_thread; }
static void run_self_tests(const shz_bootinfo_t *bi) { (void)bi; ++qa_runs; }
static void report_final(void) { ++reports; }
static unsigned tests_failed(void) { return 0; }
static void thread_sleep_ms(uint32_t ms);

#include "source/shizukudos/kernel32/ipc.c"
#include "source/shizukudos/kernel32/main.c"

static void queue_request(uint32_t opcode, const void *payload, uint16_t len, uint64_t off, uint32_t bytes)
{
    shz_msg_hdr_t m;
    memset(&m,0,sizeof m);
    m.opcode=opcode; m.request_id=opcode; m.src_domain=4; m.dst_domain=3; m.generation=1;
    m.payload_length=len; m.buffer_offset=off; m.buffer_length=bytes;
    if (bytes) m.flags=SHZ_MSGF_BUFFER;
    CHECK(shz_ring_push(host_client_tx,&m,payload)==0,"actual request ring accepted frame");
}

static void drain_replies(void)
{
    shz_msg_hdr_t m;
    uint8_t payload[192];
    int reason, rc;
    while ((rc=shz_ring_pop(host_client_rx,&m,payload,sizeof payload,&reason))!=SHZ_E_NOENT) {
        CHECK(rc==0 && (m.flags&SHZ_MSGF_REPLY) && m.src_domain==3 && m.dst_domain==4,
              "actual reply ring returned valid peer frame");
        ++reply_count;
        switch (m.opcode) {
        case 0x1f0: ++end_replies; end_reply_status=m.status; break;
        case 0x100: ++echo_replies; CHECK(m.status==0 && m.payload_length==10 && !memcmp(payload,"after20sec",10),
                                        "late ECHO payload remained usable"); break;
        case 0x101: { uint32_t n=0; memcpy(&n,payload,4); ++sum_replies;
                     CHECK(m.status==0 && m.payload_length==4 && n==11,"late SUM32 used real owned pool"); break; }
        case 0x102: { uint32_t n=0; memcpy(&n,payload,4); ++crc_replies;
                     CHECK(m.status==0 && m.payload_length==4 && n==0xcbf43926,"late CRC32 used real owned pool"); break; }
        case 0x103: { uint64_t n=0; memcpy(&n,payload,8); ++time_replies;
                     CHECK(m.status==0 && m.payload_length==8 && n==0x76543210,"TIME returned actual handler clock sample"); break; }
        default: CHECK(0,"known reply opcode");
        }
    }
}

static void thread_sleep_ms(uint32_t ms)
{
    uint64_t off;
    virtual_ms+=ms;
    if (send_end && !sent_end && virtual_ms>=50) {
        sent_end=1; queue_request(0x1f0,0,0,0,0);
    }
    if (send_late && !sent_late && virtual_ms>=25000) {
        static const uint32_t words[3]={1,3,7};
        sent_late=1;
        queue_request(0x100,"after20sec",10,0,0);
        off=shz_pool_alloc(host_channel,host_channel,4,12);
        CHECK(off!=0,"real pool allocated SUM32 words");
        memcpy((uint8_t *)host_channel+off,words,12); queue_request(0x101,0,0,off,12);
        off=shz_pool_alloc(host_channel,host_channel,4,9);
        CHECK(off!=0,"real pool allocated CRC32 bytes");
        memcpy((uint8_t *)host_channel+off,"123456789",9); queue_request(0x102,0,0,off,9);
        queue_request(0x103,0,0,0,0);
    }
    if (host_server) {
        host_server_pass=0;
        if (!setjmp(server_pause)) host_server(0);
        drain_replies();
    }
}

int main(int argc, char **argv)
{
    shz_bootinfo_t bi;
    void *map;
    if (argc!=2) return 2;
    scenario=atoi(argv[1]);
    map=mmap((void *)(uintptr_t)0xe0000000,1048576,PROT_READ|PROT_WRITE,
             MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    if (map==MAP_FAILED) { perror("bounded fixture IPC mmap"); return 2; }
    memset(&bi,0,sizeof bi);
    bi.magic=SHZ_BOOTINFO_MAGIC; bi.abi_major=1; bi.abi_minor=1; bi.size=472;
    bi.domain_id=3; bi.generation=1; bi.channel_count=1;
    bi.channel[0].gpa=0xe0000000; bi.channel[0].size=1048576;
    bi.channel[0].peer_domain=4; bi.channel[0].channel_id=0;
    host_channel=map;
    CHECK(shz_channel_init(map,1048576,0,3,4,32,1)==0,"real IPC channel initialized");
    host_client_tx=shz_channel_ring_tx(map,host_channel,4);
    host_client_rx=shz_channel_ring_rx(map,host_channel,4);
    stop_state=3; stop_at=30000; query_status=0;
    if (scenario!=1 && scenario!=2 && scenario!=3) {
        memcpy(bi.cmdline,"shz.k32-service=win98",22); bi.cmdline_size=21;
    }
    if (scenario==0) { send_end=1; send_late=1; }
    if (scenario==2) send_end=1;
    if (scenario==3) { bi.size=176; memcpy(bi.cmdline,"shz.k32-service=win98",22); bi.cmdline_size=21; }
    if (scenario==4) { stop_state=4; stop_at=500; }
    if (scenario==5) { stop_state=0; stop_at=0; }
    if (scenario==6) { stop_state=7; stop_at=0; }
    if (scenario==7) query_status=SHZ_E_UNSUPPORTED;
    if (scenario==8) bi.size=225;
    if (scenario==9) bi.cmdline_size=256;
    if (scenario==10) bi.cmdline[21]='!';
    if (scenario==11) { memcpy(bi.cmdline,"shz.k32-service=win98x",23); bi.cmdline_size=22; }
    if (scenario==12) bi.channel_count=0;
    if (scenario==13) bi.channel[0].peer_domain=5;
    if (scenario==14) bi.channel_count=5;
    if (scenario==15) { bi.channel[1]=bi.channel[0]; bi.channel_count=2; }
    if (scenario==16) bi.flags=1;
    if (scenario==17) bi.generation=0;
    if (scenario==18) bi.abi_minor=0;
    if (scenario==19) bi.channel[0].channel_id=4;
    if (scenario==20) host_channel->generation=2;
    if (scenario==21) host_channel->domain_b=5;
    if (scenario==22) bi.channel[0].gpa+=4096;
    if (scenario==23) bi.channel[0].size-=4096;
    if (scenario==24) bi.cmdline_size=0;
    if (!setjmp(kernel_stop)) kmain(&bi);
    if (scenario==0) {
        CHECK(exit_code==0 && virtual_ms>=30000,"persistent native service lived beyond QA20second cap");
        CHECK(!qa_runs && !reports,"native service did not report unexecuted QA completion");
        CHECK(!ipc_session_end && end_replies==1 && end_reply_status==SHZ_E_UNSUPPORTED,
              "SESSION_END honestly refused and did not end persistent service");
        CHECK(echo_replies==1 && sum_replies==1 && crc_replies==1 && time_replies==1,
              "all four real services answered after20seconds and QA-session request");
        CHECK(query_calls>200 && !wrong_query_target,"actual lifecycle queried Win98 domain5");
    } else if (scenario==1 || scenario==3) {
        CHECK(exit_code==0 && virtual_ms==20020 && qa_runs==1 && reports==1 && !query_calls,
              "default/legacy QA kept original20second completion behavior");
    } else if (scenario==2) {
        CHECK(exit_code==0 && virtual_ms==70 && qa_runs==1 && reports==1 && !query_calls,
              "default QA ended on actual peer SESSION_END");
        CHECK(ipc_session_end==1 && end_replies==1 && end_reply_status==0,"QA acknowledged actual session termination");
    } else if (scenario<=7) {
        CHECK(!qa_runs && !reports && query_calls && !wrong_query_target,"native terminal/error did not masquerade as QA");
        CHECK(exit_code==(scenario==4 ? 1 : 98),"native failure/unknown/unavailable owner state failed closed");
    } else if (scenario==20 || scenario==21) {
        CHECK(exit_code==96 && arch_calls==1 && !host_server && !qa_runs && !reports,
              "real channel generation/domain mismatch refused before server creation");
    } else {
        CHECK(exit_code==97 && !arch_calls && !host_server && !qa_runs && !reports,
              "malformed native policy rejected before hardware/service/QA initialization");
    }
    if (scenario<=7) CHECK(arch_calls==1,"production kernel initialization executed once");
    CHECK(munmap(map,1048576)==0,"bounded fixture mapping released");
    printf("scenario=%d failures=%u exit=%d virtual_ms=%llu replies=%u qa=%u reports=%u queries=%u\n",
           scenario,failures,exit_code,(unsigned long long)virtual_ms,reply_count,qa_runs,reports,query_calls);
    return failures ? 1 : 0;
}
