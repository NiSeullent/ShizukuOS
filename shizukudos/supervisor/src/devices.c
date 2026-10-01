/* SPDX-License-Identifier: GPL-2.0-only */
#include "devices.h"
#include "cpu.h"

static uint64_t g_tsc_hz, g_start_tsc, g_ram_bytes;
static int native_win98;
static dev_native_observation_t native_observation;
volatile int dev_a20_dirty;
void (*dev_uart_tx_hook)(uint8_t byte);

const dev_native_observation_t *dev_native_observation(void)
{
    return native_win98?&native_observation:0;
}
static void native_observe(uint16_t port,int width,int write,uint32_t value,uint64_t now)
{
    dev_native_io_record_t *records,*record;uint32_t *count,*dropped,key=value;
    if(!native_win98)return;
    if(port==0x42 || port==0x61 || (port==0x43 && write && (value>>6)==2)) {
        records=native_observation.pit;count=&native_observation.pit_count;dropped=&native_observation.pit_dropped;
        /* Ignore refresh toggle for coalescing, retaining actual first/last values. */
        if(port==0x61 && !write)key&=~0x10u;
    } else if(port==0x60 || port==0x64) {
        records=native_observation.kbc;count=&native_observation.kbc_count;dropped=&native_observation.kbc_dropped;
    } else return;
    if(*count) {
        record=&records[*count-1];uint32_t previous=record->last_value;
        if(port==0x61 && !write)previous&=~0x10u;
        if(record->port==port && record->width==width && record->write==write && previous==key) {
            if(record->count!=UINT32_MAX)++record->count;
            record->last_tsc=now;record->last_value=value;return;
        }
    }
    const unsigned capacity=records==native_observation.pit?DEV_NATIVE_PIT_RECORDS:DEV_NATIVE_KBC_RECORDS;
    if(*count>=capacity){if(*dropped!=UINT32_MAX)++*dropped;return;}
    record=&records[(*count)++];record->first_tsc=record->last_tsc=now;
    record->first_value=record->last_value=value;record->count=1;
    record->port=port;record->width=(uint8_t)width;record->write=(uint8_t)write;
}

uint64_t dev_uptime_us(void)
{
    return (rdtsc() - g_start_tsc) / (g_tsc_hz / 1000000);
}

/* ---------------------------------------------------------------- 8259A */
struct pic {
    uint8_t irr, isr, imr, base;
    uint8_t icw_step, icw4_needed, read_isr, cascade_or_id;
    uint8_t auto_eoi, init_done;
};
static struct pic pic[2];
static int external_irq_enabled;
static void pic_refresh_cascade(void);

static void pic_reset(struct pic *p, uint8_t base)
{
    p->irr = p->isr = 0;
    p->imr = 0xff;
    p->base = base;
    p->icw_step = 0;
    p->read_isr = 0;
    p->init_done = 0;
    p->auto_eoi = 0;
}

static void irq_raise(int line)
{
    if (line < 8)
        pic[0].irr |= (uint8_t)(1u << line);
    else
        pic[1].irr |= (uint8_t)(1u << (line - 8));
}

/* Highest-priority unmasked request that outranks anything in service. */
static int pic_pick(const struct pic *p)
{
    int i;
    for (i = 0; i < 8; ++i) {
        const uint8_t bit = (uint8_t)(1u << i);
        if (p->isr & bit)
            return -1;                      /* an equal/higher priority is in service */
        if ((p->irr & bit) && !(p->imr & bit))
            return i;
    }
    return -1;
}

static void pic_refresh_cascade(void)
{
    if (!external_irq_enabled) return;
    if (pic_pick(&pic[1]) >= 0) pic[0].irr |= 4u;
    else pic[0].irr &= (uint8_t)~4u;
}
void dev_irq_raise(unsigned line)
{
    if (line >= 16) return;
    external_irq_enabled = 1;
    irq_raise((int)line);
    pic_refresh_cascade();
}

int dev_irq_pending(void)
{
    int m = pic_pick(&pic[0]);
    if (m == 2) {
        const int s = pic_pick(&pic[1]);
        return s >= 0;
    }
    return m >= 0;
}

int dev_ack_irq(void)
{
    int m = pic_pick(&pic[0]);
    if (m < 0)
        return -1;
    if (m == 2) {
        const int s = pic_pick(&pic[1]);
        if (s < 0)
            return -1;
        pic[1].irr &= (uint8_t)~(1u << s);
        if (!external_irq_enabled || !pic[1].auto_eoi) pic[1].isr |= (uint8_t)(1u << s);
        pic[0].irr &= (uint8_t)~4u;
        if (!external_irq_enabled || !pic[0].auto_eoi) pic[0].isr |= 4u;
        pic_refresh_cascade();
        return pic[1].base + s;
    }
    pic[0].irr &= (uint8_t)~(1u << m);
    if (!pic[0].auto_eoi)
        pic[0].isr |= (uint8_t)(1u << m);
    return pic[0].base + m;
}

static void pic_eoi(struct pic *p, int specific, int line)
{
    int i;
    if (specific) {
        p->isr &= (uint8_t)~(1u << line);
        return;
    }
    for (i = 0; i < 8; ++i)
        if (p->isr & (1u << i)) {
            p->isr &= (uint8_t)~(1u << i);
            return;
        }
}

static void pic_write(int n, int a0, uint8_t v)
{
    struct pic *p = &pic[n];
    if (!a0) {
        if (v & 0x10) {                     /* ICW1 */
            const uint8_t keep = p->base;
            pic_reset(p, keep);
            p->icw4_needed = v & 1;
            p->icw_step = 1;
        } else if (!(v & 0x08)) {           /* OCW2 */
            const int cmd = v >> 5;
            if (cmd == 1)
                pic_eoi(p, 0, 0);
            else if (cmd == 3)
                pic_eoi(p, 1, v & 7);
            /* rotation and priority commands are not modelled */
        } else {                            /* OCW3 */
            if (v & 2)
                p->read_isr = v & 1;
        }
    } else {
        switch (p->icw_step) {
        case 1: p->base = v & 0xf8; p->icw_step = 2; break;
        case 2: p->cascade_or_id = v; p->icw_step = p->icw4_needed ? 3 : 0; if (!p->icw_step) p->init_done = 1; break;
        case 3: p->auto_eoi = (v >> 1) & 1; p->icw_step = 0; p->init_done = 1; break;
        default: p->imr = v; break;         /* OCW1 */
        }
    }
    pic_refresh_cascade();
}

static uint8_t pic_read(int n, int a0)
{
    struct pic *p = &pic[n];
    if (a0)
        return p->imr;
    return p->read_isr ? p->isr : p->irr;
}

/* ---------------------------------------------------------------- 8254 PIT */
#define PIT_HZ 1193182ull
struct pit_ch {
    uint32_t reload;                /* 1..65536 */
    uint8_t mode, access;           /* access: 1 lo, 2 hi, 3 lo/hi */
    uint8_t write_hi, read_hi;
    uint8_t latched, have_latch;
    uint16_t latch_value;
    uint16_t pending_lo;
    uint64_t start_tsc;             /* when counting started */
    uint8_t gate;
    uint64_t next_irq_tsc;          /* channel 0 only */
    uint8_t running;
    uint64_t mode0_elapsed_tsc;      /* native PIT2 only: accumulated gated time */
};
static struct pit_ch pit[3];
static uint8_t port61;

static uint64_t pit_period_tsc(const struct pit_ch *c)
{
    return (uint64_t)c->reload * g_tsc_hz / PIT_HZ;
}
/* Original arithmetic implements the mode0 boundary without overflow or a
 * 128-bit compiler runtime. ticks<=PIT_HZ and remainder<PIT_HZ bound products.
 * SeaBIOS rel-1.17.0 hw/timer.c waits for terminal OUT after 0x800 PIT2 clocks. */
static uint64_t native_pit_ticks_tsc(uint32_t ticks)
{
    const uint64_t whole=g_tsc_hz/PIT_HZ,remainder=g_tsc_hz%PIT_HZ;
    return ticks*whole+(ticks*remainder+PIT_HZ-1)/PIT_HZ;
}
static uint64_t native_pit_elapsed(const struct pit_ch *c,uint64_t now)
{
    if(!c->running)return 0;
    const uint64_t used=c->mode0_elapsed_tsc;
    if(!c->gate)return used;
    const uint64_t elapsed=now-c->start_tsc;
    return elapsed>UINT64_MAX-used?UINT64_MAX:used+elapsed;
}
static uint16_t native_pit_ticks_mod(uint64_t elapsed)
{
    const uint64_t whole=(elapsed/g_tsc_hz)%65536,remainder=elapsed%g_tsc_hz;
    uint32_t lo=0,hi=(uint32_t)PIT_HZ-1;
    while(lo<hi) {
        const uint32_t mid=lo+(hi-lo+1)/2;
        if(native_pit_ticks_tsc(mid)<=remainder)lo=mid;else hi=mid-1;
    }
    return (uint16_t)(whole*(PIT_HZ%65536)+lo);
}
static void native_pit_gate(uint8_t gate,uint64_t now)
{
    struct pit_ch *c=&pit[2];gate=gate!=0;
    if(native_win98 && c->mode==0 && native_observation.pit2_terminal_seen) {
        native_observation.pit2_interval_open=0;
        native_observation.pit2_restored_after_terminal=1;
    }
    if(native_win98 && c->mode==0 && gate!=c->gate) {
        c->mode0_elapsed_tsc=native_pit_elapsed(c,now);
        c->start_tsc=now;
    }
    c->gate=gate;
}

static uint16_t pit_counter(const struct pit_ch *c, uint64_t now)
{
    if(native_win98 && c==&pit[2] && c->mode==0) {
        if(!c->running)return (uint16_t)c->reload;
        const uint64_t elapsed=native_pit_elapsed(c,now);
        /* Mode0 OUT stays high after terminal count, while the 16-bit counter
         * continues wrapping. Gate-low freezes both pre/post-terminal count. */
        return (uint16_t)(c->reload-native_pit_ticks_mod(elapsed));
    }
    uint64_t ticks = (now - c->start_tsc) * PIT_HZ / g_tsc_hz;
    if (!c->running)
        return (uint16_t)c->reload;
    if (c->mode == 3)                       /* square wave: counts down by two */
        return (uint16_t)(c->reload - ((ticks * 2) % c->reload));
    return (uint16_t)(c->reload - (ticks % c->reload));
}

static void pit_load(int n, uint32_t value)
{
    struct pit_ch *c = &pit[n];
    c->reload = value ? value : 65536;
    c->start_tsc = rdtsc();
    if(native_win98 && n==2) {
        c->mode0_elapsed_tsc=0;
        if(c->mode==0){native_observation.pit2_interval_open=1;native_observation.pit2_terminal_seen=0;}
    }
    c->running = 1;
    if (n == 0)
        c->next_irq_tsc = c->start_tsc + pit_period_tsc(c);
}

static void pit_write_ctrl(uint8_t v)
{
    const int n = v >> 6;
    if (n == 3)
        return;                             /* read-back not modelled */
    struct pit_ch *c = &pit[n];
    const int access = (v >> 4) & 3;
    if (access == 0) {                      /* counter latch */
        c->latch_value = pit_counter(c, rdtsc());
        c->have_latch = 1;
        c->read_hi = 0;
        return;
    }
    c->access = (uint8_t)access;
    c->mode = (v >> 1) & 7;
    if (c->mode >= 6)
        c->mode -= 4;
    c->write_hi = 0;
    c->read_hi = 0;
    c->running = 0;
    if(native_win98 && n==2) {
        c->mode0_elapsed_tsc=0;c->have_latch=0;
        native_observation.pit2_interval_open=c->mode==0;
        native_observation.pit2_terminal_seen=0;
    }
}

static void pit_write_data(int n, uint8_t v)
{
    struct pit_ch *c = &pit[n];
    switch (c->access) {
    case 1: pit_load(n, v); break;
    case 2: pit_load(n, (uint32_t)v << 8); break;
    default:
        if (!c->write_hi) {
            c->pending_lo = v;
            c->write_hi = 1;
        } else {
            c->write_hi = 0;
            pit_load(n, (uint32_t)c->pending_lo | ((uint32_t)v << 8));
        }
    }
}

static uint8_t pit_read_data(int n)
{
    struct pit_ch *c = &pit[n];
    uint16_t v = c->have_latch ? c->latch_value : pit_counter(c, rdtsc());
    uint8_t out;
    switch (c->access) {
    case 2: out = (uint8_t)(v >> 8); c->have_latch = 0; break;
    case 3:
        if (!c->read_hi) {
            out = (uint8_t)v;
            c->read_hi = 1;
        } else {
            out = (uint8_t)(v >> 8);
            c->read_hi = 0;
            c->have_latch = 0;
        }
        break;
    default: out = (uint8_t)v; c->have_latch = 0;
    }
    return out;
}

/* ---------------------------------------------------------------- CMOS */
static uint8_t cmos_index;
static uint8_t cmos_ram[128];

uint8_t dev_cmos_read(uint8_t index)
{
    index &= 0x7f;
    if (index <= 0x0d || index == 0x32) {
        /* Time, date and status registers come straight from the platform RTC. */
        outb(0x70, index);
        return inb(0x71);
    }
    return cmos_ram[index];
}

static void cmos_init(uint64_t ram_bytes)
{
    const uint64_t ext_kb = ram_bytes > (1ull << 20) ? (ram_bytes - (1ull << 20)) >> 10 : 0;
    const uint64_t above16_64k = ram_bytes > (16ull << 20) ? (ram_bytes - (16ull << 20)) >> 16 : 0;
    cmos_ram[0x0e] = 0;
    cmos_ram[0x0f] = 0;
    cmos_ram[0x10] = 0;                     /* no diskettes */
    cmos_ram[0x12] = 0xf0;                  /* hard disk 0 present (type: extended) */
    cmos_ram[0x14] = 0x22;                  /* equipment: 80x25 color, coprocessor */
    cmos_ram[0x15] = 0x7f;                  /* base memory 639 KiB */
    cmos_ram[0x16] = 0x02;
    cmos_ram[0x17] = (uint8_t)(ext_kb > 0xfc00 ? 0xfc00 : ext_kb);
    cmos_ram[0x18] = (uint8_t)((ext_kb > 0xfc00 ? 0xfc00 : ext_kb) >> 8);
    cmos_ram[0x30] = cmos_ram[0x17];
    cmos_ram[0x31] = cmos_ram[0x18];
    cmos_ram[0x34] = (uint8_t)above16_64k;
    cmos_ram[0x35] = (uint8_t)(above16_64k >> 8);
}

/* ---------------------------------------------------------------- 8042 / A20 */
static uint8_t kbc_out, kbc_cmd_pending, kbc_cmd, kbc_config = 0x45;
static uint8_t kbc_out_full;
static uint8_t a20_gate = 1;
static uint8_t kbc_fifo[16],kbc_fifo_head,kbc_fifo_count;
static uint8_t keyboard_pending,keyboard_scanset,keyboard_scanning,keyboard_leds,keyboard_typematic;

void dev_native_win98_enable(void)
{
    native_win98=1;
    memset(&native_observation,0,sizeof native_observation);
    native_observation.start_tsc=g_start_tsc;
    kbc_fifo_head=kbc_fifo_count=0;kbc_cmd_pending=0;kbc_out_full=0;kbc_config=0x45;
    keyboard_pending=0;keyboard_scanset=2;keyboard_scanning=1;keyboard_leds=0;keyboard_typematic=0x2b;
}
static void native_keyboard_irq(void)
{
    if(kbc_fifo_count && (kbc_config&1) && !(kbc_config&0x10))dev_irq_raise(1);
}

int dev_a20_get(void) { return a20_gate; }
void dev_a20_set(int enabled)
{
    if ((a20_gate != 0) != (enabled != 0)) {
        a20_gate = enabled != 0;
        dev_a20_dirty = 1;
    }
}

static uint8_t kbc_read(uint16_t port)
{
    if(native_win98) {
        if(port==0x64)return (uint8_t)(0x14|(kbc_fifo_count?1:0));
        if(!kbc_fifo_count)return 0;
        const uint8_t value=kbc_fifo[kbc_fifo_head];
        kbc_fifo_head=(uint8_t)((kbc_fifo_head+1)%sizeof kbc_fifo);--kbc_fifo_count;
        native_keyboard_irq();return value;
    }
    if (port == 0x64)
        return (uint8_t)(0x14 | (kbc_out_full ? 1 : 0));
    kbc_out_full = 0;
    return kbc_out;
}

static void kbc_reply(uint8_t v)
{
    if(!native_win98){kbc_out=v;kbc_out_full=1;return;}
    if(kbc_fifo_count==sizeof kbc_fifo) {
        if(native_observation.kbc_reply_dropped!=UINT32_MAX)++native_observation.kbc_reply_dropped;
        return;
    }
    kbc_fifo[(kbc_fifo_head+kbc_fifo_count)%sizeof kbc_fifo]=v;++kbc_fifo_count;
    native_keyboard_irq();
}
static void native_keyboard_command(uint8_t value)
{
    if(keyboard_pending) {
        const uint8_t command=keyboard_pending;keyboard_pending=0;
        if(command==0xf0) {
            if(value==0){kbc_reply(0xfa);kbc_reply(keyboard_scanset);}
            else if(value<=3){keyboard_scanset=value;kbc_reply(0xfa);}else kbc_reply(0xfe);
        } else if(command==0xed) {
            if(value<=7){keyboard_leds=value;kbc_reply(0xfa);}else kbc_reply(0xfe);
        } else if(command==0xf3) {
            if(value<128){keyboard_typematic=value;kbc_reply(0xfa);}else kbc_reply(0xfe);
        }
        return;
    }
    switch(value) {
    case 0xff: /* Genuine keyboard wire reset: ACK then BAT, no host keystroke. */
        keyboard_scanset=2;keyboard_scanning=1;keyboard_leds=0;keyboard_typematic=0x2b;
        kbc_reply(0xfa);kbc_reply(0xaa);break;
    case 0xf2:kbc_reply(0xfa);kbc_reply(0xab);kbc_reply(0x83);break;
    case 0xee:kbc_reply(0xee);break;
    case 0xf0:case 0xed:case 0xf3:keyboard_pending=value;kbc_reply(0xfa);break;
    case 0xf4:keyboard_scanning=1;kbc_reply(0xfa);break;
    case 0xf5:case 0xf6:
        keyboard_scanset=2;keyboard_leds=0;keyboard_typematic=0x2b;
        keyboard_scanning=value==0xf6;kbc_reply(0xfa);break;
    default:kbc_reply(0xfe);break; /* Unsupported command must not claim ACK. */
    }
}
static void native_kbc_write(uint16_t port,uint8_t value)
{
    if(port==0x64) {
        kbc_cmd_pending=0;
        switch(value) {
        case 0x20:kbc_reply(kbc_config);break;
        case 0x60:case 0xd1:case 0xd4:kbc_cmd=value;kbc_cmd_pending=1;break;
        case 0xaa:kbc_reply(0x55);break;
        case 0xab:kbc_reply(0);break;
        case 0xa9:kbc_reply(1);break; /* Explicitly no auxiliary mouse. */
        case 0xad:kbc_config|=0x10;break;
        case 0xae:kbc_config&=(uint8_t)~0x10;native_keyboard_irq();break;
        case 0xa7:kbc_config|=0x20;break;
        case 0xa8:kbc_config&=(uint8_t)~0x20;break;
        case 0xd0:kbc_reply((uint8_t)(1|(a20_gate?2:0)));break;
        case 0xdd:dev_a20_set(0);break;
        case 0xdf:dev_a20_set(1);break;
        default:break; /* Reset pulse and unknown controller commands unmodelled. */
        }
    } else if(kbc_cmd_pending) {
        kbc_cmd_pending=0;
        if(kbc_cmd==0x60){kbc_config=value;native_keyboard_irq();}
        else if(kbc_cmd==0xd1)dev_a20_set((value>>1)&1);
        /* D4 has no auxiliary device, and deliberately produces no ACK. */
    } else native_keyboard_command(value);
}

static void kbc_write(uint16_t port, uint8_t v)
{
    if(native_win98){native_kbc_write(port,v);return;}
    if (port == 0x64) {
        switch (v) {
        case 0x20: kbc_reply(kbc_config); break;
        case 0xaa: kbc_reply(0x55); break;              /* self test */
        case 0xab: kbc_reply(0x00); break;              /* interface test */
        case 0xd0: kbc_reply((uint8_t)(0x01 | (a20_gate ? 2 : 0))); break;
        case 0xdd: dev_a20_set(0); break;
        case 0xdf: dev_a20_set(1); break;
        case 0xfe: break;                               /* CPU reset: ignored (no reset modelled) */
        default: kbc_cmd = v; kbc_cmd_pending = 1; break;
        }
    } else if (kbc_cmd_pending) {
        kbc_cmd_pending = 0;
        if (kbc_cmd == 0xd1)
            dev_a20_set((v >> 1) & 1);
        else if (kbc_cmd == 0x60)
            kbc_config = v;
    } else {
        kbc_reply(0xfa);                                /* keyboard ACK for host commands */
    }
}

/* ---------------------------------------------------------------- UART */
static uint8_t uart_ier, uart_lcr, uart_mcr, uart_lsr_extra, uart_scr, uart_dll = 1, uart_dlm;
static uint8_t uart_rx[64];
static unsigned uart_rx_head, uart_rx_tail;

void dev_uart_rx_push(uint8_t byte)
{
    const unsigned next = (uart_rx_head + 1) % sizeof uart_rx;
    if (next != uart_rx_tail) {
        uart_rx[uart_rx_head] = byte;
        uart_rx_head = next;
    }
}

static uint8_t uart_read(unsigned reg)
{
    switch (reg) {
    case 0:
        if (uart_lcr & 0x80)
            return uart_dll;
        if (uart_rx_head != uart_rx_tail) {
            const uint8_t b = uart_rx[uart_rx_tail];
            uart_rx_tail = (uart_rx_tail + 1) % sizeof uart_rx;
            return b;
        }
        return 0;
    case 1: return (uart_lcr & 0x80) ? uart_dlm : uart_ier;
    case 2: return 0x01;                                /* no interrupt pending */
    case 3: return uart_lcr;
    case 4: return uart_mcr;
    case 5: return (uint8_t)(0x60 | (uart_rx_head != uart_rx_tail ? 1 : 0) | uart_lsr_extra);
    case 6: return 0xb0;                                /* CTS|DSR|DCD */
    default: return uart_scr;
    }
}

static void uart_write(unsigned reg, uint8_t v)
{
    switch (reg) {
    case 0:
        if (uart_lcr & 0x80)
            uart_dll = v;
        else if (dev_uart_tx_hook)
            dev_uart_tx_hook(v);
        break;
    case 1: if (uart_lcr & 0x80) uart_dlm = v; else uart_ier = v; break;
    case 3: uart_lcr = v; break;
    case 4: uart_mcr = v; break;
    case 7: uart_scr = v; break;
    default: break;
    }
}

/* ---------------------------------------------------------------- VGA status / CRTC */
static uint8_t crtc_index;
static uint8_t crtc[32];

uint16_t dev_crtc_cursor(void) { return (uint16_t)((crtc[0x0e] << 8) | crtc[0x0f]); }

static uint8_t vga_status(void)
{
    /* Toggle display-enable (bit 0) and vertical retrace (bit 3) on a ~60 Hz schedule
     * so programs that wait for retrace terminate. */
    const uint64_t t = (rdtsc() - g_start_tsc) / (g_tsc_hz / 60000);   /* 1/60 ms units */
    const uint32_t phase = (uint32_t)(t % 1000);
    return (uint8_t)((phase >= 950 ? 8 : 0) | ((phase % 40) < 4 ? 1 : 0));
}

/* ---------------------------------------------------------------- dispatch */
void dev_init(uint64_t tsc_hz, uint64_t ram_bytes)
{
    native_win98=0;
    external_irq_enabled = 0;
    g_tsc_hz = tsc_hz;
    g_ram_bytes = ram_bytes;
    g_start_tsc = rdtsc();
    memset(pic, 0, sizeof pic);
    pic_reset(&pic[0], 0x08);
    pic_reset(&pic[1], 0x70);
    memset(pit, 0, sizeof pit);
    pit[0].mode = pit[1].mode = pit[2].mode = 3;
    pit[0].access = pit[1].access = pit[2].access = 3;
    pit[0].reload = pit[1].reload = pit[2].reload = 65536;
    pit[0].start_tsc = pit[1].start_tsc = pit[2].start_tsc = g_start_tsc;
    pit[0].running = 1;
    pit[0].next_irq_tsc = g_start_tsc + pit_period_tsc(&pit[0]);
    cmos_init(ram_bytes);
    a20_gate = 1;
    port61 = 0;
}

static uint32_t pack(uint32_t v, int size) { return size == 1 ? (v & 0xff) : size == 2 ? (v & 0xffff) : v; }

int dev_pio_in(uint16_t port, int size, uint32_t *value)
{
    uint32_t v = 0xffffffffu;
    int handled = 1;
    if (port == 0x20 || port == 0x21) v = pic_read(0, port & 1);
    else if (port == 0xa0 || port == 0xa1) v = pic_read(1, port & 1);
    else if (port >= 0x40 && port <= 0x42) v = pit_read_data(port - 0x40);
    else if (port == 0x43) v = 0xff;
    else if (port == 0x61) {
        const uint64_t now=rdtsc(),t = (now - g_start_tsc) * 66667ull / g_tsc_hz;   /* ~15 us toggle */
        unsigned out=pit[2].running;
        if(native_win98 && pit[2].mode==0)
            out=pit[2].running && native_pit_elapsed(&pit[2],now)>=native_pit_ticks_tsc(pit[2].reload);
        if(native_win98 && pit[2].mode==0 && out)native_observation.pit2_terminal_seen=1;
        v = (port61 & 0x0f) | ((t & 1) << 4) | (out ? 0x20 : 0);
    } else if (port == 0x60 || port == 0x64) v = kbc_read(port);
    else if (port == 0x92) v = (uint32_t)(a20_gate ? 2 : 0);
    else if (port == 0x70) v = cmos_index;
    else if (port == 0x71) v = dev_cmos_read(cmos_index);
    else if (port >= 0x3f8 && port <= 0x3ff) v = uart_read(port - 0x3f8);
    else if (port == 0x3da || port == 0x3ba) v = vga_status();
    else if (port == 0x3d4) v = crtc_index;
    else if (port == 0x3d5) v = crtc[crtc_index & 31];
    else if (port >= 0xcf8 && port <= 0xcff) v = 0xffffffffu;         /* PCI: no devices */
    else handled = 0;
    if (handled) {
        *value = pack(v, size);
        native_observe(port,size,0,*value,rdtsc());
    }
    return handled;
}

int dev_pio_out(uint16_t port, int size, uint32_t value)
{
    const uint8_t b = (uint8_t)value;
    (void)size;
    if (port == 0x20 || port == 0x21) pic_write(0, port & 1, b);
    else if (port == 0xa0 || port == 0xa1) pic_write(1, port & 1, b);
    else if (port >= 0x40 && port <= 0x42) pit_write_data(port - 0x40, b);
    else if (port == 0x43) pit_write_ctrl(b);
    else if (port == 0x61) { port61 = b; native_pit_gate(b&1,rdtsc()); }
    else if (port == 0x60 || port == 0x64) kbc_write(port, b);
    else if (port == 0x92) dev_a20_set((b >> 1) & 1);
    else if (port == 0x70) cmos_index = b & 0x7f;
    else if (port == 0x71) { if (cmos_index > 0x0d) cmos_ram[cmos_index] = b; }
    else if (port >= 0x3f8 && port <= 0x3ff) uart_write(port - 0x3f8, b);
    else if (port == 0x3d4) crtc_index = b;
    else if (port == 0x3d5) crtc[crtc_index & 31] = b;
    else if ((port >= 0x3c0 && port <= 0x3df) || port == 0x80 || (port >= 0xcf8 && port <= 0xcff) ||
             (port <= 0x0f) || (port >= 0x80 && port <= 0x8f) ||
             (port >= 0xc0 && port <= 0xdf) || port == 0xed)
        ;                                   /* accepted and ignored: VGA, POST code, DMA, delay */
    else
        return 0;
    native_observe(port,size,1,value,rdtsc());
    return 1;
}

void dev_poll(uint64_t now)
{
    struct pit_ch *c = &pit[0];
    if (c->running && (c->mode == 2 || c->mode == 3) && now >= c->next_irq_tsc) {
        const uint64_t period = pit_period_tsc(c);
        irq_raise(0);
        /* Coalesce missed ticks like a real edge-triggered line would. */
        do
            c->next_irq_tsc += period;
        while (c->next_irq_tsc <= now);
    }
}

uint64_t dev_next_event_tsc(void)
{
    return pit[0].running ? pit[0].next_irq_tsc : rdtsc() + g_tsc_hz / 100;
}
