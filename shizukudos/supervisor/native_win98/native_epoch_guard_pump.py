# SPDX-License-Identifier: GPL-2.0-only
"""One guarded readiness wait; the caller retains all transport and authority.

The owner must supply its actual custody/resource/cancellation checks, including
any additional immutable exchange deadline. This helper neither establishes
ownership nor accepts, reads, writes, closes, resumes or grants a device.
"""
import select
import time


def checked_select(readers, writers, deadline_ns, guard):
    """Check the owner guard around one <=25ms select under an absolute deadline.

    Readiness is refused if the deadline expires during the wait or postguard.
    A select exception remains primary if postguard also fails; that later
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
        ready = select.select(readers, writers, [], timeout)
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
