/* SPDX-License-Identifier: GPL-2.0-only
 * Virtual legacy platform for a DOS/real-mode domain: 8259A PIC pair, 8254 PIT,
 * MC146818 CMOS/RTC (time fields read through), 8042 KBC + port 92 A20 gate,
 * 16550 UART (COM1) and the few VGA status registers DOS programs poll.
 * Everything is time-driven from the host TSC.
 */
#ifndef SHZ_DEVICES_H
#define SHZ_DEVICES_H
#include <stdint.h>
#include "../../../drivers/common/device.h"

void dev_init(uint64_t tsc_hz, uint64_t ram_bytes);
/* Opt-in actual-Windows98 firmware contracts; dev_init keeps the DOS profile. */
#define DEV_NATIVE_PIT_RECORDS 32
#define DEV_NATIVE_KBC_RECORDS 64
typedef struct {
    uint64_t first_tsc,last_tsc;
    uint32_t first_value,last_value,count;
    uint16_t port;
    uint8_t width,write;
} dev_native_io_record_t;
typedef struct {
    uint64_t start_tsc;
    uint32_t pit_count,kbc_count,pit_dropped,kbc_dropped,kbc_reply_dropped,pit2_terminal_seen;
    uint32_t pit2_interval_open,pit2_restored_after_terminal;
    dev_native_io_record_t pit[DEV_NATIVE_PIT_RECORDS],kbc[DEV_NATIVE_KBC_RECORDS];
} dev_native_observation_t;
void dev_native_win98_enable(void);
/* Serialized trusted native pointer owner. validate is checked at every
 * publication/read boundary; poll runs only from the scheduler's dev_poll,
 * never from a guest port/IRQ callback. No attach happens without a real source.
 * Detach removes queued AUX bytes and never stops/frees the source transport. */
struct dev_native_pointer_ops {
    void *context;
    int (*validate)(void *);
    int (*poll)(void *);
};
int dev_native_pointer_attach(const struct dev_native_pointer_ops *);
int dev_native_pointer_detach(void *context);
/* Input uses HID coordinates (positive Y down), converted to PS/2 positive Y up.
 * Full movement is retained across FIFO pressure. Failure publishes nothing. */
int dev_native_pointer_input(void *context,int32_t x,int32_t y,uint8_t buttons);
/* Passive bounded numeric I/O evidence, valid until the next dev_init. */
const dev_native_observation_t *dev_native_observation(void);
/* Port I/O. Return 1 if the port belongs to a modelled device. size is 1, 2 or 4. */
int dev_pio_in(uint16_t port, int size, uint32_t *value);
int dev_pio_out(uint16_t port, int size, uint32_t value);
/* Advance timers; raises IRQ lines. */
void dev_poll(uint64_t now_tsc);
/* Highest-priority pending unmasked interrupt vector, or -1. Marks it in service. */
int dev_ack_irq(void);
int dev_irq_pending(void);
/* Real additive peripheral edge request; first use enables slave cascade modelling. */
void dev_irq_raise(unsigned line);
/* TSC value of the next timer event (for the VMX preemption timer). */
uint64_t dev_next_event_tsc(void);
/* Guest-visible A20 gate changes must reach the EPT layer. */
int dev_a20_get(void);
void dev_a20_set(int enabled);
/* Set by device code when the A20 state changed and EPT must be refreshed. */
extern volatile int dev_a20_dirty;
/* Serial: bytes the guest wrote to COM1 and input the host supplies. */
void dev_uart_rx_push(uint8_t byte);
extern void (*dev_uart_tx_hook)(uint8_t byte);
/* CRTC cursor registers written through ports 3D4/3D5 (index 0Eh/0Fh). */
uint16_t dev_crtc_cursor(void);
uint64_t dev_uptime_us(void);
uint8_t dev_cmos_read(uint8_t index);
#endif
