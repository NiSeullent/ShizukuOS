# SPDX-License-Identifier: GPL-2.0-or-later
import importlib.util
from pathlib import Path
import unittest

P=Path(__file__).resolve().parents[1]/'run_original_dos_control.py'
spec=importlib.util.spec_from_file_location('control_budget_test',P)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class WriteBudget(unittest.TestCase):
    def stats(self,value):return [{'device':'unrelated','stats':{'wr_bytes':99999999}},{'device':'win98','stats':{'wr_bytes':value}}]
    def test_actual_device_counter_not_shared_allocation_growth(self):
        self.assertEqual(m.check_write_budget(self.stats(1024*1024),0),1024*1024)
        # Existing shared blocks can be overwritten without st_blocks growth;
        # the guest device counter must still reject an excessive total.
        with self.assertRaises(RuntimeError):m.check_write_budget(self.stats(m.DIRTY_BUDGET+1),0)
        self.assertEqual(m.check_write_budget(self.stats(m.DIRTY_BUDGET),10),m.DIRTY_BUDGET)
    def test_missing_duplicate_reset_and_invalid_counters_fail_closed(self):
        bad=[[],{},[{'device':'other','stats':{'wr_bytes':0}}],self.stats(True),self.stats(-1),self.stats('1'),self.stats(4),[{'device':'win98','stats':{}}],self.stats(7)+[{'device':'win98','stats':{'wr_bytes':7}}]]
        for stats in bad:
            with self.subTest(stats=stats),self.assertRaises((ValueError,RuntimeError)):m.check_write_budget(stats,5)
if __name__=='__main__':unittest.main()
