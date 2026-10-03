# SPDX-License-Identifier: GPL-2.0-only
"""One guarded readiness wait; the caller retains all transport and authority.

The owner must supply its actual custody/resource/cancellation checks, including
any additional immutable exchange deadline. This helper neither establishes
ownership nor accepts, reads, writes, closes, resumes or grants a device.
"""
import os
import selectors
import time


def _poll_select(readers, writers, errors, timeout):
    """Poll original descriptors; never duplicate, consume or close them."""
    if errors:
        raise ValueError('exceptional readiness is not used by this transport')
    read_rows = [(item, item if isinstance(item, int) else item.fileno()) for item in readers]
    write_rows = [(item, item if isinstance(item, int) else item.fileno()) for item in writers]
    requests = {}
    for rows, event in ((read_rows, selectors.EVENT_READ), (write_rows, selectors.EVENT_WRITE)):
        for _, fd in rows:
            requests[fd] = requests.get(fd, 0) | event
    with selectors.PollSelector() as waiter:
        for fd, event in requests.items():
            # PollSelector maps POLLNVAL to readiness; retain select's EBADF refusal.
            os.fstat(fd)
            waiter.register(fd, event)
        events = waiter.select(timeout)
        for fd in requests:
            os.fstat(fd)
    ready = {key.fd: event for key, event in events}
    return ([item for item, fd in read_rows if ready.get(fd, 0) & selectors.EVENT_READ],
            [item for item, fd in write_rows if ready.get(fd, 0) & selectors.EVENT_WRITE], [])


def checked_select(readers, writers, deadline_ns, guard):
    """Check the owner guard around one <=25ms poll under an absolute deadline.

    Readiness is refused if the deadline expires during the wait or postguard.
    A readiness exception remains primary if postguard also fails; that later
    refusal is retained as its explicit cause. No wait is retried or renewed.
    """
    if type(deadline_ns) is not int:
        raise TypeError("an absolute integer monotonic deadline is required")
    if not callable(guard):
        raise TypeError("the actual owner guard is required")
    guard()
    remaining_ns = deadline_ns - time.monotonic_ns()
    if remaining_ns <= 0:
        raise TimeoutError("the original wait deadline expired")
    timeout = min(25_000_000, remaining_ns) / 1_000_000_000
    try:
        ready = _poll_select(readers, writers, [], timeout)
    except BaseException as first_error:
        try:
            guard()
        except BaseException as guard_error:
            raise first_error from guard_error
        raise
    guard()
    if time.monotonic_ns() >= deadline_ns:
        raise TimeoutError("the original wait deadline expired")
    return ready
