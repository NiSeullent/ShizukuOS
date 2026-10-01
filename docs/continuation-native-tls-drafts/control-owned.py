"""One visually reviewed action, restricted to this root-owned corrected TLS clone."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys

OUT = Path(__file__).resolve().parent
RUN = Path('/root/Win98-Modern-boot/build/shizukudos/csm/run-win98-gop-tls13-i486-5abe-native-v1')
def require(ok, message):
    if not ok: raise ValueError(message)

seq = int(sys.argv[1])
capture = RUN / sys.argv[2]
actions = {
    1: dict(name='continue own observed original missing-driver prompt', keys=[['ret']]),
    2: dict(name='close own observed Windows98 Welcome', keys=[['alt', 'f4']]),
    3: dict(name='open own observed Windows98 desktop Run dialog', keys=[['meta_l', 'r']]),
    4: dict(name='launch original own corrected TLS observer', keys=[['ctrl', 'a']], text='C:\\GOPLAB\\T13RUN.EXE', enter=True),
}
require(seq in actions and capture.name.startswith('screen-') and capture.suffix == '.png', "Own process/control/capture identity gate failed")
require(capture.resolve(strict=True) == capture and capture.parent == RUN, "Own process/control/capture identity gate failed")
capture_raw = capture.read_bytes()
w = json.loads((OUT / 'watcher-owned-vm.json').read_bytes())
def check():
    proc = Path('/proc') / str(w['actual_pid'])
    require((proc / 'comm').read_text().strip().startswith('qemu'), "Own process/control/capture identity gate failed")
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    require(int(fields[19]) == w['actual_start_ticks'], "Own process/control/capture identity gate failed")
    targets = set()
    for fd in (proc / 'fd').iterdir():
        try:
            targets.add(os.readlink(fd))
        except FileNotFoundError:
            pass
    require(w['actual_open_image'] == str(RUN / 'windows-uefi.raw') and w['actual_open_image'] in targets, "Own process/control/capture identity gate failed")
check()
receipt = RUN / 'gui-control-receipt.json'
if seq > 1:
    require(json.loads(receipt.read_bytes())['sequence'] == seq - 1, "Own process/control/capture identity gate failed")
else:
    require(not receipt.exists(), "Own process/control/capture identity gate failed")
action = dict(sequence=seq, **actions[seq])
tmp = RUN / ('gui-control.5abe-action-' + str(seq) + '.tmp')
with tmp.open('x') as stream:
    stream.write(json.dumps(action) + '\n')
check()
require(capture.read_bytes() == capture_raw, "Own process/control/capture identity gate failed")
os.replace(tmp, RUN / 'gui-control.json')
record = dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    actual_pid=w['actual_pid'], actual_start_ticks=w['actual_start_ticks'],
    actual_open_image=w['actual_open_image'], original_capture=str(capture),
    original_capture_sha256=hashlib.sha256(capture_raw).hexdigest(),
    action=action, actual_image_fd_verified=True, native_component_acceptance=False, peer_control=False)
with (OUT / ('gui-action-' + str(seq) + '.json')).open('x') as stream:
    stream.write(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
