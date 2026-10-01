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
def foreground_fixture(api=1,match=1,owned=1,visible=1,requested=1):
    return ('FOREGROUND_LOG_VERSION=1\r\nFOREGROUND_TRIGGER=INITIAL-SHOWN\r\nFOREGROUND_STYLE=CLASSIC\r\nFOREGROUND_SWITCH=1\r\n'+
            ''.join('%s=%s\r\n'%(key,value) for key,value in [('FOREGROUND_OWNED',owned),('FOREGROUND_VISIBLE',visible),('FOREGROUND_REQUESTED',requested),('FOREGROUND_API_RETURN',api),('FOREGROUND_MATCH',match)])+
            'FOREGROUND_VERDICT=DIAGNOSTIC-ONLY\r\n').encode()+fixture()
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
    def test_v13_without_foreground_is_not_retroactively_upgraded(self):
        r=v.parse(fixture(),N);self.assertFalse(r['foreground']['observed'])
    def test_foreground_return_and_actual_handle_remain_independent(self):
        for api,match in [(0,0),(1,0),(0,1),(1,1)]:
            r=v.parse(foreground_fixture(api,match),N);f=r['foreground'];self.assertEqual(f['records'][0]['FOREGROUND_MATCH'],match)
            self.assertFalse(f['complete_visible_scene_verified']);self.assertTrue(r['offscreen_pixels_verified'])
    def test_foreign_hidden_or_contradictory_foreground_evidence_refused(self):
        for b in [foreground_fixture(owned=0),foreground_fixture(visible=0),foreground_fixture()+b'FOREGROUND_MATCH=1\r\n',foreground_fixture().replace(b'FOREGROUND_LOG_VERSION=1',b'FOREGROUND_LOG_VERSION=2')]:
            with self.assertRaises(ValueError):v.parse(b,N)
        self.assertTrue(v.parse(foreground_fixture(api=0,match=0,owned=1,visible=0,requested=0),N)['offscreen_pixels_verified'])
if __name__=='__main__':unittest.main()
