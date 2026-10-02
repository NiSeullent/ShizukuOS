/* SPDX-License-Identifier: GPL-2.0-only
 * Execute actual native constructor/entry/stop control. VMX and the selected
 * native storage boundary are mocked; no PCI/MMIO/DMA/physical I/O is executed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#define w98_persistence_attach_native mock_native_attach
#define w98_persistence_finish mock_finish
#include "../win98.c"
#undef w98_persistence_attach_native
#undef w98_persistence_finish
#undef G
static unsigned checks,vmcs_calls,attach_calls,page_count;
static unsigned finish_calls __attribute__((unused));
static int vmcs_failure,attach_failure;
#ifdef WIN98_PERSISTENCE_HOOKS
static int finish_failure,finish_ack=1;
#endif
static uint8_t pages[5][4096] __attribute__((aligned(4096)));
domain_t g_dom[SHZ_MAX_DOMAINS];guest_t G;shz_info_t *g_info;uint64_t g_tsc_hz;
volatile int dev_a20_dirty;void (*dev_uart_tx_hook)(uint8_t);
#define CHECK(v) do {++checks;if(!(v)){fprintf(stderr,"FAIL group%u line%u: %s\n",group,__LINE__,#v);exit(2);}}while(0)
static unsigned group;
void kprintf(const char *format,...){(void)format;}
void log_capture(char *out,unsigned n,const char *format,...){(void)format;if(n)out[0]=0;}
void serial_putc(char c){(void)c;}
void dev_irq_raise(unsigned n){CHECK(n==14);}
void dev_init(uint64_t hz,uint64_t bytes){CHECK(hz==1000000000ull && bytes==(128ull<<20));}
void dev_native_win98_enable(void){}
const dev_native_observation_t *dev_native_observation(void){return NULL;}
int dev_a20_get(void){return 1;}
void video_render(void){CHECK(0);}
int dev_pio_in(uint16_t port,int bytes,uint32_t *value)
{(void)port;(void)bytes;(void)value;CHECK(0);return 0;}
void *pool_alloc_pages(unsigned n){CHECK(n==1 && page_count<5);return pages[page_count++];}
int ept_init(ept_t *e){memset(e,0,sizeof *e);return 0;}
int ept_map(ept_t *e,uint64_t g,uint64_t h,uint64_t n,uint64_t f,int four)
{(void)e;(void)g;(void)h;(void)n;(void)f;CHECK(four==1);return 0;}
uint64_t ept_pointer(const ept_t *e){(void)e;return 0x1234501e;}
int vmx_vcpu_init(vcpu_t *v,shz_info_t *info,const shz_caps_t *caps,const vmx_cfg_t *cfg)
{(void)info;(void)caps;++vmcs_calls;CHECK(!attach_calls && cfg->mode==VMODE_REAL);v->vmcs_pa=(uintptr_t)cfg->vmcs;v->owner_cpu=0;v->domain_id=SHZ_DOM_WIN98;v->cpu_binding_valid=1;return vmcs_failure?-1:0;}
#ifdef WIN98_PERSISTENCE_HOOKS
int mock_native_attach(w98_persistence_t *s,w98_ata_t *a,const w98_persist_config_t *c,uint64_t n,const shz_info_t *info)
{++attach_calls;CHECK(vmcs_calls==1 && n==192 && c && a==&ata && a->status==0x50 && info==G.info);CHECK(g_dom[SHZ_DOM_WIN98].state!=SHZ_DS_RUNNABLE);s->device.owned=1;s->device.ready=1;s->ata=a;s->attached=!attach_failure;return attach_failure?-1:0;}
int mock_finish(w98_persistence_t *s)
{++finish_calls;CHECK(s->ata==&ata && w98->state!=SHZ_DS_RUNNABLE && w98->state!=SHZ_DS_WAITING);s->device.reset_acknowledged=finish_ack;s->attached=0;return finish_failure?-1:0;}
#endif
int main(int argc,char **argv)
{
    CHECK(argc==2);group=(unsigned)strtoul(argv[1],NULL,10);
    shz_info_t info={0};shz_caps_t caps={0};
    uint8_t *ram=aligned_alloc(4096,128u<<20),*bios=aligned_alloc(4096,256u<<10);
    uint8_t *disk=mmap(0,2ull<<30,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(ram && bios && disk!=MAP_FAILED);
    memset(bios,0,256u<<10);info.loader_flags=SHZ_LOADER_NATIVE_WIN98;
    info.guest_ram_base=(uintptr_t)ram;info.guest_ram_size=128ull<<20;
    info.disk_base=(uintptr_t)disk;info.disk_size=2ull<<30;info.tsc_hz=1000000000ull;
    memcpy(info.blobs[0].name,"SEABIOS.BIN",12);info.blobs[0].base=(uintptr_t)bios;info.blobs[0].size=256u<<10;
    uint8_t config[192] __attribute__((aligned(8)))={0};
    if(group){memcpy(info.blobs[1].name,"W98PERS.BIN",12);info.blobs[1].base=(uintptr_t)config;info.blobs[1].size=192;}
    caps.hypervisor_bit=1;G.info=g_info=&info;g_tsc_hz=info.tsc_hz;
    if(group==1)info.blobs[1].size--;
    if(group==2)info.blobs[2]=info.blobs[1];
    if(group==3)info.blobs[1].base++;
    if(group==4)caps.hypervisor_bit=0;
    if(group==5)attach_failure=1;
    if(group==6)vmcs_failure=1;
    if(group>=1 && group<=6){
        CHECK(win98_domain_create(&info,&caps)==-1);
        CHECK(g_dom[SHZ_DOM_WIN98].state!=SHZ_DS_RUNNABLE);
#ifdef WIN98_PERSISTENCE_HOOKS
        CHECK(attach_calls==(group==5));
        if(group==5){unsigned before=vmcs_calls;CHECK(win98_domain_create(&info,&caps)==-1 && vmcs_calls==before && attach_calls==1);}
#endif
    }else{
        CHECK(!win98_domain_create(&info,&caps));domain_t *d=&g_dom[SHZ_DOM_WIN98];(void)d;
#ifdef WIN98_PERSISTENCE_HOOKS
        if(!group){CHECK(!attach_calls);CHECK(!win98_execution_begin(d) && !win98_execution_end(d));d->state=SHZ_DS_EXITED;win98_housekeeping();CHECK(!finish_calls);}
        else{
            CHECK(attach_calls==1 && d->state==SHZ_DS_RUNNABLE && !finish_calls);
            if(group==8){CHECK(!win98_execution_begin(d));d->state=SHZ_DS_FAILED;win98_housekeeping();CHECK(!finish_calls);CHECK(!win98_execution_end(d));}
            else if(group==9){d->state=SHZ_DS_FAILED;} /* load failed before any entry */
            else if(group==10){CHECK(!win98_execution_begin(d));CHECK(!win98_execution_end(d));d->state=SHZ_DS_FAILED;} /* actual entry returned VMfail */
            else if(group==11){d->state=SHZ_DS_EXITED;++d->vc.owner_cpu;win98_housekeeping();CHECK(!finish_calls);--d->vc.owner_cpu;}
            else if(group==12){d->state=SHZ_DS_EXITED;finish_failure=1;finish_ack=0;}
            else if(group==13){domain_t other={0};other.kind=DK_KERNEL64;CHECK(!win98_execution_begin(&other) && !win98_execution_end(&other));CHECK(!finish_calls);d->state=SHZ_DS_EXITED;}
            else if(group==14){CHECK(!win98_execution_begin(d));CHECK(win98_execution_begin(d)==-1);CHECK(!win98_execution_end(d));CHECK(win98_execution_end(d)==-1);d->state=SHZ_DS_EXITED;}
            else if(group==15){domain_t other=*d;CHECK(!win98_execution_begin(d));CHECK(win98_execution_end(&other)==-1);d->state=SHZ_DS_FAILED;win98_housekeeping();CHECK(!finish_calls);CHECK(!win98_execution_end(d));}
            else{CHECK(!win98_execution_begin(d) && !win98_execution_end(d));d->state=SHZ_DS_EXITED;}
            win98_housekeeping();CHECK(finish_calls==1);win98_housekeeping();CHECK(finish_calls==1);
            CHECK(win98_execution_begin(d)==-1);unsigned before=vmcs_calls;CHECK(win98_domain_create(&info,&caps)==-1 && vmcs_calls==before);
            if(group==12)CHECK(d->state==SHZ_DS_FAILED);
        }
#endif
    }
    munmap(disk,2ull<<30);free(bios);free(ram);
    printf("PASS %u actual constructor/entry/stop controls group%u; native storage and VMX mocked, no VM\n",checks,group);return 0;
}
