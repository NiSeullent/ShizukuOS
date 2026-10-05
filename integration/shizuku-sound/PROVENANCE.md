# ShizukuOS original event sound candidate

The ten WAVs in `assets/` are newly generated in this Codex task from the explicit
event scores and mathematical oscillator in `synthesize.py`. No recordings,
third-party samples, NAS WAV bytes, historical Windows melody transcription,
Apple assets, or external sound libraries enter the generator. Event filenames
and scores are specific to ShizukuOS; shared musical intervals and elementary
sine synthesis are functional building blocks.

The new event score, generator, audit script, WAV data, manifests and
documentation are designated **CC0-1.0**, to the extent copyright or related
rights exist. No human composer or third-party copyright owner is invented here.
This designation does not apply to project-source context in the integration
diff, referenced project source files, NAS assets, or third-party license text.
The integration diff retains the respective existing project source licenses;
existing source license notices must remain on any later integration changes.

The full unmodified CC0 legal text is retained as `CC0-1.0.txt`, retrieved from
the [Creative Commons canonical legal code](https://creativecommons.org/publicdomain/zero/1.0/legalcode.txt).
This records a reuse designation for the newly authored candidate, not a claim
that the historical NAS recordings have public-distribution rights.

NAS inventory was checked read-only at `/volume1/shizukuossound`: ten historical
Windows-named WAVs and ten Synology metadata streams, with no license/provenance
file in the two-level bounded inventory. The existing source integration tree
contained no additional WAV/OGG assets. Those historical recordings remain
internal and are not copied or modified in this candidate.

Target format is the existing Core/AC97 and WINMM supported PCM path: 22050 Hz,
signed 16-bit mono. Event duration is 0.16–2.38 seconds; no looping, abrupt sample
boundaries, or full-scale clipping. Peaks reserve 9–17 dB of digital headroom.
Host waveform/parser checks are byte/format evidence only. No audible review,
speaker playback, guest execution, installer boot, or public release is claimed.

Pre-implementation classification: existing Core/AC97/WINMM pipeline PARTIAL;
NAS sound REUSABLE for existing internal tests only; distributable original
ShizukuOS event assets MISSING; current closed-name staging policy REQUIRES
REFACTOR; complete event lifecycle hooks PARTIAL. The generated files establish
actual candidate audio data, not completion of the sound experience.

The audio-design skill was inspected but its game mixer/bus workflow does not
apply to this bounded event-asset task. No new mixer, driver, shell, or audio
subsystem is introduced.
