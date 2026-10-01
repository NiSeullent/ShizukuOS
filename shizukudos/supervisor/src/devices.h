/* SPDX-License-Identifier: GPL-2.0-only
 * Virtual legacy platform for a DOS/real-mode domain: 8259A PIC pair, 8254 PIT,
 * MC146818 CMOS/RTC (time fields read through), 8042 KBC + port 92 A20 gate,
 * 16550 UART (COM1) and the few VGA status registers DOS programs poll.
 * Everything is time-driven from the host TSC.
 */
#ifndef SHZ_DEVICES_H
#define SHZ_DEVICES_H
#include <stdint.h>

void dev_init(uint64_t tsc_hz, uint64_t ram_bytes);
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
