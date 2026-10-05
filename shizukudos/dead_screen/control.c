/* SPDX-License-Identifier: GPL-2.0-only
 * PRIVATE opt-in native acceptance profile, called only from the patched copy.
 * Preparing the existing WM/input tables is normal init, before any fault.
 * Neither token changes an ordinary boot. Native execution remains queued.
 */
#include "../kernel64/k64.h"
#include "native.h"
extern int ds_native_control_prepare_gui(void); /* private wrapper around actual wm_init */
#ifdef DS_NATIVE_HOST_TEST
extern void ds_test_ud(void) __attribute__((noreturn));
#endif
int __attribute__((weak)) ds_pcm_control_prepare(void) {return -1;}
void ds_native_control(void)
{
    const int panic=k64_cmdline_has("shz.dead-screen-panic-control");
    const int exception=k64_cmdline_has("shz.dead-screen-ud-control");
    const int text=k64_cmdline_has("shz.dead-screen-text-control");
    const int nyan=k64_cmdline_has("shz.nyan-control");
    if(!panic && !exception && !text && !nyan)return;
#ifdef SHZ_STANDALONE
    {
        const int status=ds_native_control_prepare_gui();
        kprintf("DEAD SCREEN CONTROL: normal GUI preparation status=%x; synthetic own-kernel fault next\n",status);
    }
#endif
    if(nyan && k64_cmdline_has("shz.nyan-pcm-prepare"))
        kprintf("NYAN CONTROL: healthy PCM prepare rc=%d\n",ds_pcm_control_prepare());
    if(text)ds_native_force_text();
    if(nyan)ds_native_force_nyan(k64_cmdline_has("shz.nyan-silent")?0:
        k64_cmdline_has("shz.nyan-fixed")?1:k64_cmdline_has("shz.nyan-beep")?2:3);
    if(exception) {
        kprintf("DEAD SCREEN CONTROL: deliberate own-kernel #UD, not a Win98/VMM fault\n");
#ifdef DS_NATIVE_HOST_TEST
        ds_test_ud();
#else
        __asm__ volatile("ud2" ::: "memory");
#endif
        kpanic("DEAD SCREEN CONTROL: #UD unexpectedly returned");
    }
    kpanic("DEAD SCREEN CONTROL: requested own-kernel panic; not a Win98/VMM fault");
}
