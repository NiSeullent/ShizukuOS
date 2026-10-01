import importlib.util
from pathlib import Path
import unittest
s=importlib.util.spec_from_file_location('composition_verifier',Path(__file__).with_name('verify.py'));v=importlib.util.module_from_spec(s);s.loader.exec_module(v)
N='0123456789abcdef'*2
def fixture():
    lines=['COMPOSITION_LOG_VERSION=1','BEGIN_NONCE='+N]
    for style in ['CLASSIC','MODERN']:
        lines+=['COMPOSE_STYLE='+style,'COMPOSE_API_STAGE=0','MEMORY_VALID=1','MEMORY_BACKGROUND_SAMPLES=28','MEMORY_BACKGROUND_MISMATCHES=0','MEMORY_READS_INVALID=0']
        for name in v.REGIONS:lines+=['COMPOSE_REGION='+name,'REFERENCE_INK=100','ACTUAL_INK=100','TEXT_PIXEL_MISMATCHES=0']
        lines+=['FULL_SCENE_TRANSFER=1','SCREEN_BPP=32','SCREEN_SAMPLES=21','SCREEN_MISMATCHES=0','SCREEN_READS_INVALID=0','COMPOSE_CLEANUP_ISSUES=0','SCREEN_VERDICT=DIAGNOSTIC-SAMPLES-ONLY']
    return ('\r\n'.join(lines+['RUN_NONCE='+N,'RESULT=PASS'])+'\r\n').encode()
class Tests(unittest.TestCase):
    def test_valid_does_not_establish_visibility_or_exit(self):
        r=v.parse(fixture(),N);self.assertTrue(r['offscreen_pixels_verified']);self.assertFalse(r['complete_visible_scene_verified']);self.assertFalse(r['native_process_exit_verified'])
    def test_partial_text_is_not_accepted(self):
        r=v.parse(fixture().replace(b'ACTUAL_INK=100',b'ACTUAL_INK=30',1),N);self.assertFalse(r['offscreen_pixels_verified'])
    def test_screen_mismatch_remains_separate(self):
        r=v.parse(fixture().replace(b'SCREEN_MISMATCHES=0',b'SCREEN_MISMATCHES=8',1),N);self.assertTrue(r['offscreen_pixels_verified']);self.assertEqual(r['events'][0]['screen_sample_verdict'],'MISMATCH')
    def test_screen_unavailable_remains_separate(self):
        r=v.parse(fixture().replace(b'SCREEN_READS_INVALID=0',b'SCREEN_READS_INVALID=21',1),N);self.assertTrue(r['offscreen_pixels_verified']);self.assertEqual(r['events'][0]['screen_sample_verdict'],'UNAVAILABLE')
    def test_fresh_nonce_duplicates_and_missing_regions_refused(self):
        for b in [fixture().replace(N.encode(),b'f'*32,1),fixture()+('RUN_NONCE='+N+'\r\n').encode(),fixture().replace(b'COMPOSE_REGION=CAPTION',b'COMPOSE_REGION=NORMAL',1)]:
            with self.assertRaises(ValueError):v.parse(b,N)
    def test_missing_style_is_incomplete(self):
        b=fixture();start=b.index(b'COMPOSE_STYLE=MODERN');end=b.index(b'RUN_NONCE=');r=v.parse(b[:start]+b[end:],N);self.assertFalse(r['offscreen_pixels_verified'])
if __name__=='__main__':unittest.main()
