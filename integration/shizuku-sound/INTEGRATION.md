# Apply only after current guest custody is closed

This candidate changes data and known filename sets within the existing sound
architecture. It adds no audio subsystem or placeholder executable. Nothing in
LIVE, current media, VM inputs, or the running guest was modified.

The unapplied `integration-proposal.patch` is bound to the six current source
files in `result.json`: production stager, installer profile, existing Start
menu, and Slade/Flute/Jade theme files. Review source pins again before use.

1. Place `synthesize.py`, original audio assets, `SHZSOUND.INI`, provenance and
   unmodified CC0 text in an appropriate existing integration data directory.
   Regenerate there if desired, binding the new exact source/output pins.
2. Apply the six-file proposal after the current guest completes. Both closed
   name sets replace the historical 10-WAV set wholesale, retaining exact-count,
   path, PCM, byte and digest validation. `mkpayload.py` already imports the same
   `SOUND_PATHS` and needs no separate filename database. The Start menu's real
   Muzik launch uses `ShizukuStartup.wav`, retaining its existing 8000 ms bound.
3. Produce a fresh Shell receipt for the three changed theme inputs and Start
   source. Its original producer receipt must not be relabeled. Use the existing
   `--sound-manifest` and `--scheme-manifest` staging options with their new pins.
4. Run the real guest and installer against the resulting new cohort. Confirm
   Core AC97 identity, actual PCM capture, Muzik completion, native theme events,
   sound files surviving installation, and installed UEFI boot.

The existing WINMM alias parser is reused: this scheme explicitly supplies all
14 currently recognized event aliases. Its compiled historical default filename
strings remain fallback references only; they do not contain recordings. This
candidate does not change or rebuild WINMM. A missing/unloaded override can
therefore cause a real missing-file refusal and must be checked in the guest.

All ten event references in the three themes are data-ready, but the actual shell currently
dispatches only startup, launch notification, error and theme navigation events.
Shutdown currently stops playback; login/logout, warning and device lifecycle
hooks are not completed by generating assets. Add those hooks to existing
services only when their real events are available, retaining actual provider
completion semantics. No hearing, device output, GUI audio control, mixer,
complete sound system, ISO or publication success is asserted here.

The current eight-second Muzik shortcut exceeds the candidate startup's actual
2.38-second PCM duration. Digital peaks are below full-scale with smooth zero
boundaries; loudness and listening quality remain pending actual audible review.
