/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise the production observer body with paused, modeled VMCS fields.
 * No VMX instruction, guest, original media or networking is executed here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#define SHZ_CPU_H
static unsigned reads;
static unsigned long long fields[0x7000];
static unsigned long long mock_read(unsigned field) { ++reads; return fields[field]; }
#define vmread mock_read
static unsigned long long mock_tsc;
static unsigned long long rdtsc(void) { return mock_tsc; }
#include "../win98.c"
#undef G
domain_t g_dom[SHZ_MAX_DOMAINS];
guest_t G;
shz_info_t *g_info;
uint64_t g_tsc_hz;
volatile int dev_a20_dirty;
void (*dev_uart_tx_hook)(uint8_t);
static char trace_output[32768];
static unsigned length, checks;
#define CHECK(v) do { ++checks; if (!(v)) { fprintf(stderr,"FAIL %u: %s\n",__LINE__,#v); exit(2); } } while (0)
void kprintf(const char *fmt,...) {
    va_list ap; va_start(ap,fmt);
    int n=vsnprintf(trace_output+length,sizeof trace_output-length,fmt,ap); va_end(ap);
    CHECK(n>=0 && (unsigned)n<sizeof trace_output-length);length+=(unsigned)n;
}
void dev_native_win98_enable(void){}
static dev_native_observation_t mock_observation;static int mock_observation_enabled;
const dev_native_observation_t *dev_native_observation(void){return mock_observation_enabled?&mock_observation:NULL;}
int dev_a20_get(void) { return 1; }
uint8_t *dom_gpa_ptr(domain_t *d,uint64_t gpa,uint64_t size) {
    if(gpa>d->ram_size || size>d->ram_size-gpa) return NULL;
    return (uint8_t *)(uintptr_t)(d->ram_base+gpa);
}
int ept_remap_page(ept_t *e,uint64_t gpa,uint64_t hpa,uint64_t flags){(void)e;(void)gpa;(void)hpa;(void)flags;return 0;}
void ept_invalidate(void){}
void video_render(void){}
void dom_fail(domain_t *d,const char *fmt,...){(void)d;(void)fmt;CHECK(0);}
int main(void) {
    domain_t d={0},other={0};
    uint8_t *ram=calloc(1,0x100000),*bios=calloc(1,0x40000);
    shz_blob_t blob={0}; CHECK(ram && bios);
    d.kind=DK_WIN98; d.ram_base=(uintptr_t)ram;d.ram_size=0x100000;
    blob.base=(uintptr_t)bios;blob.size=0x40000;rom=&blob;w98=&d;
    /* Actual housekeeping prints neither before terminal observation nor before
     * ten seconds, then emits exactly once outside the calibration I/O path. */
    G.tsc_hz=1000000000ull;mock_observation_enabled=1;mock_observation.pit_count=1;
    mock_observation.pit[0].port=0x61;mock_observation.pit[0].count=1000;
    mock_tsc=11000000000ull;win98_housekeeping();CHECK(!length);
    mock_observation.pit2_terminal_seen=1;mock_observation.pit2_interval_open=1;win98_housekeeping();CHECK(!length);
    mock_observation.pit2_restored_after_terminal=1;mock_observation.pit2_interval_open=0;mock_tsc=9000000000ull;win98_housekeeping();CHECK(!length);
    mock_tsc=11000000000ull;win98_housekeeping();CHECK(strstr(trace_output,"W98DEVICE passive") && strstr(trace_output,"count=1000"));
    unsigned emitted=length;win98_housekeeping();CHECK(length==emitted);
    length=0;mock_observation_enabled=0;devices_emitted=0;mock_tsc=0;
    fields[VMCS_GUEST_CR0]=0x31;fields[VMCS_GUEST_CS_SEL]=8;
    fields[VMCS_GUEST_CS_BASE]=0;fields[VMCS_GUEST_RIP]=0xe002a;
    fields[VMCS_GUEST_RSP]=0x7000;fields[VMCS_GUEST_GDTR_BASE]=0x6000;
    fields[VMCS_GUEST_GDTR_LIMIT]=23;fields[VMCS_GUEST_IDTR_BASE]=0x6100;
    fields[VMCS_GUEST_IDTR_LIMIT]=0;ram[0xe002a]=0xf4;
    unsigned r=reads;win98_observe_exit(&other,EXIT_IO);CHECK(reads==r && !length);
    for(unsigned n=0;n<40;++n) {
        fields[VMCS_EXIT_QUAL]=(0xcf8ull<<16);fields[VMCS_GUEST_RIP]=0xe0000+n;
        win98_observe_exit(&d,EXIT_IO);CHECK(!length);
    }
    fields[VMCS_GUEST_RIP]=0xe002a;win98_observe_exit(&d,EXIT_TRIPLE_FAULT);
    CHECK(strstr(trace_output,"W98TRACE paused-VMCS reason=2")!=NULL);
    CHECK(strstr(trace_output,"seq=10 ")!=NULL && strstr(trace_output,"seq=9 ")==NULL);
    CHECK(strstr(trace_output,"seq=41 ")!=NULL);
    CHECK(strstr(trace_output,"code gpa=e002a bytes=64 f4")!=NULL);
    CHECK(strstr(trace_output,"gdt gpa=6000 bytes=24")!=NULL);
    CHECK(strstr(trace_output,"idt gpa=6100 bytes=1")!=NULL);
    CHECK(strstr(trace_output,"stack gpa=7000 bytes=64")!=NULL);
    unsigned prior=length;win98_observe_exit(&d,EXIT_TRIPLE_FAULT);CHECK(length==prior);
    CHECK(trace_read(&d,0x100000000ull,1)==NULL);
    CHECK(trace_read(&d,0xffffffffffffffffull,1)==NULL);
    CHECK(trace_read(&d,0xfffff,2)==NULL);
    CHECK(trace_read(&d,0xfffc0000ull,64)==bios);
    CHECK(trace_read(&d,0xffffffffull,2)==NULL);
    CHECK(trace_read(&d,0,65)==NULL);
    fields[VMCS_GUEST_CR0]|=0x80000000ull;length=0;trace_memory(&d,"paged",0xe002a,64);
    CHECK(strstr(trace_output,"paging-unsupported")!=NULL);
    fields[VMCS_GUEST_CR0]=0x31;length=0;trace_memory(&d,"bad",0xfffff,64);
    CHECK(strstr(trace_output,"unmapped")!=NULL);
    free(bios);free(ram);printf("PASS %u bounded observer/ring/mapping/paused modeled-VMCS checks; no VM\n",checks);
    return 0;
}
