# SPDX-License-Identifier: GPL-2.0-or-later
"""Reviewed allocation gate copied unchanged from iewebkit_verify_wtf.py.
Pattern source SHA: efeb4c9c75d933ef1217ad8b1d96a67e71131227d098e6d830f8f69a290372fc.
Reads saved observations only; no VM, disk or process mutations.
"""
import re

def allocation_gate(result: dict, entry: dict) -> bool:
    budget = result['sparse_budget']
    quota = budget['dirty_budget_bytes']
    reserve = budget['reserve_bytes']
    review = entry['cow_allocation_review']
    baseline, latest, final = budget['cow_baseline'], budget['cow_latest'], review['observation']
    observations = (baseline, latest, final)
    identity = ('device', 'inode', 'file_bytes', 'block_bytes', 'helper_sha256')
    helper = entry['cow_accounting_helper_sha256']
    if not isinstance(helper, str) or not re.fullmatch(r'[0-9a-f]{64}', helper):
        return False
    for item in observations:
        if (item.get('schema') != 'xfs-fiemap-exclusive-data-v1' or item.get('filesystem') != 'xfs'
                or item.get('stable_scans') != 2
                or item.get('helper_sha256') != entry['cow_accounting_helper_sha256']
                or any(type(item.get(key)) is not int or item[key] <= 0 for key in identity[:-1])
                or any(item.get(key) != baseline.get(key) for key in identity)
                or type(item.get('exclusive_bytes')) is not int or item['exclusive_bytes'] < 0):
            return False
    latest_growth = latest['exclusive_bytes'] - baseline['exclusive_bytes']
    final_growth = final['exclusive_bytes'] - baseline['exclusive_bytes']
    peak = budget['cow_peak_net_exclusive_growth_bytes']
    if (type(quota) is not int or quota != 128 * 1024 * 1024
            or entry.get('private_dirty_allocation_quota_mib') != 128
            or type(reserve) is not int or reserve < 20 * 1024 ** 3
            or budget.get('cow_net_exclusive_growth_bytes') != latest_growth
            or review.get('net_exclusive_growth_bytes') != final_growth
            or type(peak) is not int or peak < max(0, latest_growth, final_growth)
            or peak > quota or final_growth > quota
            or type(budget.get('cow_quiescent_samples')) is not int or budget['cow_quiescent_samples'] < 1):
        return False
    return all(type(value) is int and value >= reserve for value in (
        result.get('minimum_free_bytes'), result.get('free_after_run'), budget.get('free_before_vm')))
