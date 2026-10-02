# SPDX-License-Identifier: GPL-2.0-only
"""Parse a complete actual public Q35 observation; no Windows guest data."""
import importlib.util,json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('q35_host',ROOT/'native_epoch_host.py')
host=importlib.util.module_from_spec(spec);sys.modules[spec.name]=host;spec.loader.exec_module(host)
RAW=json.loads((Path(__file__).parent/'fixtures/public-q35-flatview-6970.json').read_text())['transcript']
class ActualQ35(unittest.TestCase):
 def test_actual_qemu_crlf_uppercase_acceleration_and_ecam_name(self):
  flat=host.parse_flatview(RAW)
  self.assertEqual(flat['ecam'],(0xe0000000,0xf0000000))
  self.assertEqual(sum(b-a for a,b in flat['ram']),4*1024**3-0x60000)
 def test_missing_terminator_and_unknown_ecam_are_refused(self):
  for bad in (RAW.rstrip(),RAW.replace('pcie-mmcfg-mmio','unknown-device'),RAW.replace('\r\n','\r',1)):
   with self.assertRaises(ValueError):host.parse_flatview(bad)
if __name__=='__main__':unittest.main()
