/* SPDX-License-Identifier: GPL-2.0-only
 * Strong fs_notify for test_file_io_failures_host.c: replaces fs.c's weak no-op (ipc_notify.c in the kernel) at link
 * time so the fixture can count directory change notifications without editing production code.
 */
#include <stdint.h>
struct fsnode;
extern unsigned host_notify_count;
void fs_notify(struct fsnode *n, uint32_t action, uint32_t what)
{
    (void)n; (void)action; (void)what;
    ++host_notify_count;
}
