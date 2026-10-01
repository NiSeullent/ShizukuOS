# SPDX-License-Identifier: GPL-2.0-only
"""Validate a query-kvm reply obtained from the current owned QMP connection.

The caller must obtain the reply from its primary live monitor and bind this
record to its child PID and epoch. Configuration and archived logs are not a
substitute. See the installed QEMU QMP reference, Accelerators/KvmInfo.
"""


def validate_kvm_reply(reply, owned_qemu_pid):
    if type(owned_qemu_pid) is not int or owned_qemu_pid <= 0:
        raise ValueError("Current owned QEMU process identity is required")
    if not isinstance(reply, dict) or set(reply) != {"enabled", "present"}:
        raise ValueError("Complete bounded current query-kvm reply is required")
    if reply["enabled"] is not True or reply["present"] is not True:
        raise ValueError("Current owned QEMU must report active KVM acceleration")
    return {"status": "PASS", "owned_qemu_pid": owned_qemu_pid,
            "query_kvm_reply": dict(reply),
            "scope": "CURRENT_OWNED_QEMU_QUERY_NOT_CONFIGURATION"}
