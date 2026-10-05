/* SPDX-License-Identifier: GPL-2.0-only
 * Private Kernel64 seam. No Win98/VMM interception, no fault-time allocation.
 * A retained GOP/BGA mapping is bound by that real backend during normal probe.
 * Virtio command submission and uninitialised input are deliberately unsupported.
 */
#include "native.h"
#include "../kernel64/k64.h"
#include "../kernel64/pci.h"
#ifdef DS_NATIVE_HOST_TEST
/* Compile-time host I/O model only; absent from the linked native candidate. */
extern uint8_t ds_test_inb(uint16_t);
extern void ds_test_outb(uint16_t,uint8_t);
extern uint64_t ds_test_cr2(void),ds_test_cr3(void),ds_test_flags(void);
extern void ds_test_halt(void) __attribute__((noreturn));
extern void ds_test_iteration(const ds_state *);
#define k_inb ds_test_inb
#define k_outb ds_test_outb
#define read_cr2 ds_test_cr2
#define read_cr3 ds_test_cr3
#define cli() ((void)0)
#endif

static ds_state state;
static ds_surface framebuffer;
static unsigned initialised,keyboard_ready,timer_ready,capturing,force_text,force_nyan,audio_limit=3;
static uint32_t context_cpu,context_pid,context_tid,context_valid;
static char panic_reason[DS_REASON];
static unsigned panic_length;
static unsigned fallback_depth;
/* One physical CPU owns every shared fatal write. Other CPUs stop locally;
 * this is first-record protection, not peer-CPU stop or SMP recovery. */
static uint32_t fatal_owner; /* 0 unclaimed, physical CPU identity + 1 */
_Static_assert(__atomic_always_lock_free(sizeof(uint32_t),0),"fatal owner must be lock-free");
#ifdef SHZ_STANDALONE
static unsigned serial_ready,serial_failed;
#endif

static void halt(void) __attribute__((noreturn));
static void fallback(void) __attribute__((noreturn));
static void halt(void) {
#ifdef DS_NATIVE_HOST_TEST
    ds_test_halt();
#else
    for(;;) __asm__ volatile("cli; hlt" ::: "memory");
#endif
}
static uint32_t fatal_enter(unsigned capture_continuation)
{
    const uint32_t cpu=sched_cpu_identity();
    uint32_t expected=0;
    if(cpu==UINT32_MAX)halt(); /* No verified physical owner: touch no shared record. */
    if(!__atomic_compare_exchange_n(&fatal_owner,&expected,cpu+1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
        if(expected!=cpu+1)halt(); /* Secondary CPU never renders or changes fallback depth. */
        if(state.latched)fallback();
        /* Only capture_begin -> panic is a valid pre-latch continuation.
         * Recursive formatting/capture/exception entry must not replace it. */
        if(!capture_continuation || !capturing)halt();
    }
    return cpu;
}
static int console(void *context,const char *bytes,size_t count)
{
    (void)context;
#ifdef SHZ_STANDALONE
    if(serial_failed)return -1;
    if(!serial_ready) {
        if(k_inb(0x3fd)==0xff) return -1;
        k_outb(0x3f9,0);k_outb(0x3fb,0x80);k_outb(0x3f8,1);k_outb(0x3f9,0);
        k_outb(0x3fb,3);k_outb(0x3fa,0xc7);k_outb(0x3fc,3);serial_ready=1;
    }
    for(size_t i=0;i<count;++i) {
        unsigned n;
        for(n=0;n<1000000 && !(k_inb(0x3fd)&0x20);++n) __asm__ volatile("pause");
        if(n==1000000) {serial_failed=1;return -1;}
        k_outb(0x3f8,(uint8_t)bytes[i]);
    }
    return 0;
#else
    /* Hypercall accepts guest-physical kernel-image storage only. Copy each
     * bounded fragment to our static buffer; never translate a stack pointer. */
    static char buffer[128];
    while(count) {
        const size_t n=count<sizeof buffer?count:sizeof buffer;
        for(size_t i=0;i<n;++i)buffer[i]=bytes[i];
        if(shz_console_write(kimage_v2p((uint64_t)buffer),(uint32_t)n))return -1;
        bytes+=n;count-=n;
    }
    return 0;
#endif
}
void ds_native_init(void)
{
    if(initialised)return;
    ds_init(&state);initialised=1;
}
void ds_native_bind(volatile uint32_t *pixels,uint32_t width,uint32_t height,
                    uint32_t pitch_bytes,size_t mapped_bytes,unsigned rgbx)
{
    ds_surface f={pixels,width,height,pitch_bytes/4,mapped_bytes/4,rgbx};
    ds_native_init();
    if(!state.latched && !(pitch_bytes&3) && !(mapped_bytes&3) && ds_surface_storage_valid(&f))framebuffer=f;
}
void ds_native_keyboard_ready(unsigned ready) {keyboard_ready=!!ready;}
void ds_native_timer_ready(void) {timer_ready=1;}
void ds_native_force_text(void) {if(!state.latched)force_text=1;}
void ds_native_context(uint32_t cpu,uint32_t pid,uint32_t tid)
{ if(!__atomic_load_n(&fatal_owner,__ATOMIC_ACQUIRE) && !state.latched) {context_cpu=cpu;context_pid=pid;context_tid=tid;context_valid=1;} }
void ds_native_force_nyan(unsigned limit) {if(!state.latched){force_nyan=1;audio_limit=limit>3?3:limit;}}
/* Strong AC97 hooks use only DMA buffers retained during healthy boot. Never
 * probe/allocate/schedule or call the normal WinMM/stream service after panic. */
int __attribute__((weak)) ds_pcm_panic_begin(void) {return -1;}
int __attribute__((weak)) ds_pcm_panic_poll(void) {return -1;}
void __attribute__((weak)) ds_pcm_panic_stop(void) { }
static const uint16_t fatal_notes[]={659,784,988,784,659,523,587,659,784,659,587,523};
#ifdef SHZ_STANDALONE
static int speaker_gate(unsigned on)
{
    uint8_t v=k_inb(0x61);
    if(v==0xff)return 0;
    k_outb(0x61,(uint8_t)((v&~3u)|(on?3u:0u)));
    return (k_inb(0x61)&3u)==(on?3u:0u);
}
static int speaker_pitch(unsigned hz)
{
    uint16_t d=(uint16_t)(1193182u/hz),now;
    k_outb(0x43,0xb6);k_outb(0x42,(uint8_t)d);k_outb(0x42,(uint8_t)(d>>8));
    if(!speaker_gate(1))return 0;
    /* Verify that the programmed channel counts, not just a writable gate.
     * No claim of audible output follows from register readback. */
    for(unsigned i=0;i<20000;i++) {
        k_outb(0x43,0x80);now=k_inb(0x42);now|=(uint16_t)k_inb(0x42)<<8;
        if(now && now<d)return 1;
        __asm__ volatile("pause");
    }
    return 0;
}
static int speaker_fixed(void)
{
    /* A gate write alone cannot prove a timer exists. Require actual channel-2
     * output transitions; unsupported/lifeless ports remain SILENT. */
    k_outb(0x43,0xb6);k_outb(0x42,0xa9);k_outb(0x42,4);
    if(!speaker_gate(1))return 0;
    const uint8_t first=k_inb(0x61)&0x20;
    for(unsigned i=0;i<100000;i++) {
        if((k_inb(0x61)&0x20)!=first)return 1;
        __asm__ volatile("pause");
    }
    (void)speaker_gate(0);return 0;
}
static void fatal_pause(void)
{for(unsigned i=0;i<1500000;i++)__asm__ volatile("pause");} /* bounded coarse pace; not a calibrated clock */
#endif
static void fallback(void)
{
    cli();
    /* If the framebuffer write itself faults, the next takeover skips it.
     * One additional serial-only attempt is allowed; further fault recursion
     * stops immediately. The first latched record is never replaced. */
    if(fallback_depth>=2)halt();
    const unsigned depth=fallback_depth++;
    enum ds_fatal_audio audio=DS_AUDIO_SILENT;
    if(!depth && !force_text) {
#ifdef SHZ_STANDALONE
        const unsigned pcm=audio_limit>=3 && ds_pcm_panic_begin()==0;
        const unsigned pitched=!pcm && audio_limit>=2 && speaker_pitch(659) && speaker_pitch(784);
        const unsigned fixed=!pcm && !pitched && audio_limit>=1 && speaker_fixed();
        audio=ds_nyan_audio_select(pcm,pitched,fixed);
#endif
        (void)ds_nyan_framebuffer(&state,&framebuffer,audio);
    } else if(!depth)(void)ds_fallback_framebuffer(&state,&framebuffer);
    (void)ds_fallback(&state,console,0);
#ifdef SHZ_STANDALONE
    if(!depth && !force_text) {
        const char *name=ds_nyan_audio_name(audio);
        size_t n=0;while(name[n])++n;
        (void)console(0,"NYAN AUDIO: ",12);(void)console(0,name,n);(void)console(0,"\n",1);
        for(unsigned note=0;;++note) {
            if(audio==DS_AUDIO_PCM && ds_pcm_panic_poll()) {
                ds_pcm_panic_stop();
                const unsigned pitched=audio_limit>=2 && speaker_pitch(659) && speaker_pitch(784);
                audio=ds_nyan_audio_select(0,pitched,!pitched && audio_limit>=1 && speaker_fixed());
                (void)ds_nyan_framebuffer(&state,&framebuffer,audio);
                name=ds_nyan_audio_name(audio);n=0;while(name[n])++n;
                (void)console(0,"NYAN AUDIO: ",12);(void)console(0,name,n);(void)console(0,"\n",1);
            }
            if(audio==DS_AUDIO_PITCHED && !speaker_pitch(fatal_notes[note%12])) {
                audio=ds_nyan_audio_select(0,0,speaker_fixed());
                (void)ds_nyan_framebuffer(&state,&framebuffer,audio);
                name=ds_nyan_audio_name(audio);n=0;while(name[n])++n;
                (void)console(0,"NYAN AUDIO: ",12);(void)console(0,name,n);(void)console(0,"\n",1);
            }
            if(audio==DS_AUDIO_FIXED && !speaker_gate(note&1)) {
                (void)speaker_gate(0); /* Best effort only; failed hardware is not claimed silent. */
                audio=DS_AUDIO_SILENT;
                (void)ds_nyan_framebuffer(&state,&framebuffer,audio);
                name=ds_nyan_audio_name(audio);n=0;while(name[n])++n;
                (void)console(0,"NYAN AUDIO: ",12);(void)console(0,name,n);(void)console(0,"\n",1);
            }
            if(audio==DS_AUDIO_SILENT)halt();
#ifdef DS_NATIVE_HOST_TEST
            ds_test_iteration(&state);
#endif
            fatal_pause();
        }
    }
#endif
    halt();
}
void ds_native_capture_begin(void)
{
    cli();(void)fatal_enter(0);
    panic_length=0;panic_reason[0]=0;capturing=1;
}
void ds_native_capture_char(char ch)
{
    const uint32_t owner=__atomic_load_n(&fatal_owner,__ATOMIC_ACQUIRE);
    if(!owner)return; /* Healthy printf must not need a physical-owner lookup. */
    const uint32_t cpu=sched_cpu_identity();
    if(cpu==UINT32_MAX || owner!=cpu+1)return;
    if(capturing && panic_length<DS_REASON-1) {panic_reason[panic_length++]=ch;panic_reason[panic_length]=0;}
}
static void enter(const ds_fault *f) __attribute__((noreturn));
static void enter(const ds_fault *f)
{
    cli();
    ds_native_init();
    if(ds_latch(&state,DS_KERNEL_FATAL,f)!=1) fallback();
    /* The framebuffer includes the real trace. The exact textual fallback is
     * used when rendering/load prerequisites fail, or on recursive fault. */
    if(force_text || force_nyan || ds_render(&state,&framebuffer)) fallback();
#ifdef SHZ_STANDALONE
    uint32_t elapsed=0;
    uint16_t previous=0;
    if(timer_ready) {
        k_outb(0x43,0);previous=k_inb(0x40);previous|=(uint16_t)k_inb(0x40)<<8;
    }
    for(;;) {
        enum ds_key key=DS_NONE;
        int changed=0;
        /* At most one keyboard byte and one serial byte per iteration. AUX and
         * parity/timeout bytes are discarded; E1/break sequences are bounded. */
        if(keyboard_ready) {
            const uint8_t st=k_inb(0x64);
            if(st&1) { const uint8_t b=k_inb(0x60);if(!(st&0xe0))key=ds_scan1(&state,b); }
        }
        if(key!=DS_NONE) {ds_key_event(&state,key);changed=1;}
        const uint8_t serial_status=k_inb(0x3fd);
        if(serial_status&1) {
            const uint8_t byte=k_inb(0x3f8);
            key=!(serial_status&0x9e)?ds_serial_key(byte):DS_NONE;
            if(key!=DS_NONE) {ds_key_event(&state,key);changed=1;}
        }
        if(timer_ready) {
            k_outb(0x43,0);
            uint16_t now=k_inb(0x40);now|=(uint16_t)k_inb(0x40)<<8;
            /* Existing sa_timer_set(TICK_US=1000) mode-2 divisor is 1193. A
             * delayed poll can miss wraps: pacing is conservative, never an
             * invented TSC frequency or interrupt-driven clock after CLI. */
            if(now<=1193 && previous<=1193) {
                elapsed+=previous>=now?previous-now:previous+1193-now;
                if(elapsed>=19886) {elapsed-=19886;ds_tick(&state);changed=1;}
            }
            previous=now;
        }
        if(changed && ds_render(&state,&framebuffer)) fallback();
#ifdef DS_NATIVE_HOST_TEST
        ds_test_iteration(&state);
#endif
        __asm__ volatile("pause");
    }
#else
    /* No native device access in Supervisor profile. Prepared device rendering
     * is absent, so normally enter() already selected textual fallback. */
    halt();
#endif
}
void ds_native_panic(uint64_t ip,uint64_t sp,uint64_t bp)
{
    static ds_fault f;
    cli();const uint32_t cpu=fatal_enter(1);capturing=0;
    memset(&f,0,sizeof f);
    f.ip=ip;f.sp=sp;f.bp=bp;f.cr2=read_cr2();f.cr3=read_cr3();
#ifdef DS_NATIVE_HOST_TEST
    f.flags=ds_test_flags();
#else
    __asm__ volatile("pushfq; popq %0":"=r"(f.flags));
#endif
    f.vector=UINT64_MAX;f.frames[0]=ip;f.frame_count=1;
    f.cpu=cpu;
    if(context_valid && context_cpu==cpu) {f.pid=context_pid;f.tid=context_tid;f.context_valid=1;}
    for(unsigned i=0;i<DS_REASON;++i)f.reason[i]=panic_reason[i];
    enter(&f);
}
void ds_native_exception(const struct regs *r)
{
    static ds_fault f;
    cli();const uint32_t cpu=fatal_enter(0);capturing=0;
    memset(&f,0,sizeof f);
    f.ip=r->rip;f.sp=r->rsp;f.bp=r->rbp;f.flags=r->rflags;
    f.vector=r->vector;f.error=r->error;f.cr2=read_cr2();f.cr3=read_cr3();
    const uint64_t values[DS_REGS]={r->rax,r->rbx,r->rcx,r->rdx,r->rsi,r->rdi,r->rbp,
        r->r8,r->r9,r->r10,r->r11,r->r12,r->r13,r->r14,r->r15,r->cs};
    for(unsigned i=0;i<DS_REGS;++i)f.reg[i]=values[i];
    f.registers_valid=1;f.frames[0]=r->rip;f.frame_count=1;
    f.cpu=cpu;
    if(context_valid && context_cpu==cpu) {f.pid=context_pid;f.tid=context_tid;f.context_valid=1;}
    const char reason[]="Unhandled Shizuku Kernel exception; captured interrupt frame";
    for(unsigned i=0;i<sizeof reason;++i)f.reason[i]=reason[i];
    enter(&f);
}
