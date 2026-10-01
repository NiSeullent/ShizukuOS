# VLC 3.0.24 native Windows 98 trial

The official x86 VLC package and a small Qt/GDI/local-media closure are frozen.
The native prerequisite installer succeeded on a private genuine GOP/Windows 98
clone. The first cold application trial then **failed at startup**, displaying
the original VLC invalid-options/no-plugins dialog for both video and audio.
The video's actual child exit was zero after dismissing that error; no functional
GUI or playback was established. Audio was unfinished when the bounded VM ended.
The earlier prelaunch disk-reserve failure remains preserved.

Actual prerequisite evidence exists: 33 file/font/window controls, 26 locale
controls and 35 process/context controls passed on genuine Windows 98 with the
GOP driver. The suite observed all three native child process exits as zero.
Its own process exit was not independently observed. These 94 controls do not
prove that VLC launches or plays media.

## Frozen inputs and preserved failure

Paths below are relative to this repository; these are private trial artifacts.

| Artifact | Path | SHA-256 |
|---|---|---|
| Official VLC archive | `benchmarks/media/vlc-3.0.24/vlc-3.0.24-win32.zip` | `8511356afd680817f3aea624c63032d0936f3d77b2175fb36c8fc16adf9744e8` |
| Independently reviewed 94 native controls | `build/vlc-native-independent-review-20260930T1934/result.json` | `42cc9b0631ca14a2e8f4100623b3201a11f997b7beab165b88b309d7d58af889` |
| First self-contained 47-input manifest | `build/vlc-trial-owned-20260930T2126/manifest.json` | `2fbf931e9dbf141c0999dc4d6fa0c4ecdc8e7a9af34dc072378b5a1700b1a58e` |
| Setup prelaunch failure | `build/shizukudos/csm/run-win98-gop-vlc-setup-20260930T2128/result.json` | `e2349e7fbad66ad18eeb215c813793abb6040bfe29662ed0b90576a14cde1134` |
| Host staging and 47 exact readbacks | `build/shizukudos/csm/run-win98-gop-vlc-setup-20260930T2128/app-stage-result.json` | `6750ff3f760f5e9275e8095040e92bdb6fcd9c0aedad0f46f6c4d222a4ccc9f4` |
| Successful native setup review | `build/shizukudos/csm/run-win98-gop-vlc-setup-20260930T2240/native-vlc-setup-review.json` | `d7311462d27177b8f916661aa02a0b983add40714e3e2a82f0362a2eae8eb03f` |
| First cold application raw receipt | `build/shizukudos/csm/run-win98-gop-vlc-video-20260930T2250/result.json` | `49592049aee85b8a080e4fed11869a2cbaecfff0e05eb23d064d5dfbc7b9b41b` |
| Independent startup failure review | `build/vlc-first-trial-independent-review-l6eeblga/result.json` | `c9c9e9faae54f2efa64af7700087695f75b06c150b24c4c128101a3a0dbeb635` |
| Corrected 47-input candidate, native execution pending | `build/vlc-trial-file-logger-20260930T2313/manifest.json` | `3c87c7bc7fa9064fc22f6af57083562ba65a7fe4b554240a6866c5ee55f840e0` |

The first payload selected `plugins/misc/liblogger_plugin.dll`, an obsolete
interface stub. The watcher's `--file-logging` and `--logfile` options are owned
by the omitted `plugins/logger/libfile_logger_plugin.dll`, as registered in
[VLC 3.0.24's file logger source](https://raw.githubusercontent.com/videolan/vlc/3.0.24/modules/logger/file.c).
The [core's full option parse](https://raw.githubusercontent.com/videolan/vlc/3.0.24/src/libvlc.c)
runs before logger initialization. Both media logs
were independently absent from the first trial's quiescent FAT volume.
This establishes a packaging defect, not proof that it was the sole runtime
blocker. VLC's [original Windows entry point](https://raw.githubusercontent.com/videolan/vlc/3.0.24/bin/winvlc.c)
itself returns zero after reporting initialization failure, so an observed zero
process exit is insufficient.

The corrected candidate replaces only the obsolete plugin with the exact
official file logger (66,496 bytes, SHA-256
`d7ba17e37a9b494c58748c69f144f17f641f4cf34806eeae650d2b1b785f6644`)
and rebuilds the mode helper for that one changed image path. Forty-five inputs,
CORE, all three providers, installer and process observer remain byte-identical.
Sixteen host guards passed, including real-module and missing/stub/truncated
controls; static import availability has no unresolved entries. Actual plugin
loading, GUI, media and exit acceptance require the next separate guest trial.

The source is the quiescent owned image in
`build/shizukudos/csm/run-win98-gop-vlc-native-api-20260930T1830`, with SHA-256
`ddc5972b7d5e784dbae81289787ccc63ccff507d656345c970bd50f744d5b31a`.
It retains the native GOP driver, installed KernelEx and proven Notepad++ files.
`VLCLAB` is absent there. Never boot this retained source directly.

The first finalizer manifest (`2122`) was rejected because original inputs lay
outside its own folder. Its receipt remains unchanged. The current finalizer
copies every input into the new output and invokes the unchanged production
stager validator. A fresh positive result is under
`build/vlc-trial-reproducible-20260930T2141`; a real escaping-input/no-output
negative control is under `build/vlc-finalizer-guard-evidence-20260930T2150`.

## Setup on a new owned clone

Retain the selected 16 GiB reserve, the dirty-write budget, sparse-copy policy,
private firmware variables and source/licensed-input hash gates. Stage only the
corrected candidate manifest above into the genuinely absent `C:\VLCLAB` tree. Do not overwrite the
existing `NPPLAB` tree or transplant another VM's state.

Run these fixed native commands in the guest:

```text
C:\VLCLAB\VLCINST.EXE apply
C:\VLCLAB\VLCINST.EXE verify
C:\VLCLAB\VLCMODE.EXE inspect
C:\VLCLAB\VLCMODE.EXE apply
C:\VLCLAB\VLCMODE.EXE verify
```

The installer checks the actual original CORE digest, all three source-provider
digests and absent destination files before writing. It creates an independent
`C:\VLCLAB\CORE.BAK` with CREATE_NEW, verifies it, then copies only M98VLC,
M98LOC and M98CTX into `C:\WINDOWS\KernelEx`. Every copy checks write, flush,
close and full digest. CORE changes only after the original backup and provider
copies verify. Failure restores the saved CORE and deletes only destinations
the helper itself created; failed restoration remains an explicit failure.
A failed partial backup is retained while the original CORE stays untouched.

The mode helper updates only 21 exact original VLC image paths to WINXP/flags0.
It rejects existing entries, rechecks before writing, flushes and reads back
every value, and rolls back only its own entries on failure. The stager and
independent post-run readbacks establish the official image identities.

After a quiescent finish, independently read and hash:

- Fresh `INSTALLA.LOG`, `INSTALLV.LOG`, `MODEI.LOG`, `MODEA.LOG`, `MODEV.LOG`
  (each bounded to 64 KiB).
- Original CORE backup: `022289408799526d71661d2c9367b84030de5aadeb7fa5681466655b5acf30ec`.
- Installed new CORE: `e44d24dcc845490cfb91e7352f59cfb1c7781fa890a245bdbcbee70bd599bc3d`.
- M98VLC: `ec2581cf4e5934224aac58f2f9e7d558b437b8336b0209b1206647ea7679800e`.
- M98LOC: `3c593ad138b4890f04e5024e58f5620e9a66416762d7e4175bd5409fa587d538`.
- M98CTX: `db121411ccd7641ebfa89dc7779e3c8d1ca96f7d6ac9f85d0e05c5801347009d`.
- All original official VLC images, 21 registry mode entries and preserved
  Notepad++/COM/driver/provider files. Exempt only the explicitly changed CORE
  from the old unchanged-file set.

## Cold application acceptance

Create another receipt-verified owned cold clone after successful setup. KernelEx
configuration must reload; do not infer this from a warm setup process. Run:

```text
C:\VLCLAB\VLCWATCH.EXE video
C:\VLCLAB\VLCWATCH.EXE audio
```

The observer creates the exact official VLC child, records its native PID and
visible window identity, waits for its actual exit, and never sends WM_CLOSE.
Interact with VLC normally, confirm original guest screenshots of its real GUI
and changing GDI-rendered video, then close it normally. The process must exit0.
A 600-second deadline triggers bounded termination and remains a failure.
Observer write/flush/close failures exit31 and cannot establish valid acceptance.

`MEDIA\VIDEO.AVI` is a standard 30-second, 160x120, 2fps raw AVI with 60 distinct
frames. `MEDIA\TONE.WAV` is a standard five-second mono PCM440Hz fixture. Both
were independently decoded on the host. The held VM has **no sound device or
audio backend**, so this profile cannot establish audible playback. Preserve
actual waveout errors and any native runtime failure.

Read fresh `VIDWATCH.LOG`/`AUDWATCH.LOG` (64 KiB each) and `VIDEO.LOG`/`AUDIO.LOG`
(1 MiB each) after quiescence. The application stager remains assets-only with
`outputs=[]`; these logs need separate bounded manual readback. A loader,
dependency preflight, first visible window or original API-probe PASS cannot
replace actual VLC GUI/media/normal-exit evidence.
