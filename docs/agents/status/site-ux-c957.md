# c957 bilingual distribution website

Source commit: `7050f3e335f7de7e29ad4d126def6fa1d9e9b507`.
This is verified website source and local staging, not public deployment or
Windows98-on-ShizukuDOS/final ISO acceptance.

The project home now connects Korean and English download, setup, app support
and development pages. Download cards retain the actual five ZIP identities,
byte sizes, checksums, prerequisites and licenses. The ten frozen application
targets keep their recorded failures and execution scope. Final1.0.0
installation remains pending. A separately admitted development ISO can fill
one explicit slot on each home/download page; publisher privacy, bounds,
locking and rollback rules remain intact.

The frozen v2 stage is `build/pma-c957-site-ux-stage-v2/site`:100 files,
5,181,666 bytes, canonical path-map SHA256
`7aaa38a841112284831e2ccd2ca4fda16146f16c1f84cf69517e0d31c02a3d0f`.
All92 existing public paths are present and75 immutable project artifacts are
byte-identical. The13 recorded collections,48 original frames, both JSON
manifests, JavaScript viewers, WASM and historical downloads are unchanged.
The earlier frozen v1 stage and browser evidence are preserved; v2 changes
only the two localized preview HTML pages to provide no-JavaScript access.

Independent source review found no additional blocker. The54 regression tests
passed in28.439 seconds after an actual missing-fallback RED result. Log:
`build/pma-c957-site-ux-stage-v2/tests/full54-green.log`, SHA256
`33728888b563220e5320c69acb411edc8655b18621a5f88acbea83b81bb7feae`.
All123 captured site source identities remained stable after those tests and
were independently rechecked before the source commit. Publisher SHA256:
`4afdc390a1af058f5e25fdc7c963fdc6f178ae338ed1d7ada953e1b0bf9f3a7e`.
Refactor test SHA256:
`21032de7e3840601ec72ed9edd0e52673266d23e1b061065cd5f4022cab19dc0`.

Actual Chrome ran against only the prepared public files on loopback. Evidence
is retained under `output/playwright/` and summarized in
`build/pma-c957-site-ux-stage-v2/browser-result.json`:

- 32 route/viewport checks at1440 and375 pixels passed, with correct language,
one main heading/landmark, no horizontal overflow and loaded visible images.
- All100 v2 HTTP bodies match their frozen byte sizes and SHA256 values. Its
two changed preview pages also pass all four desktop/mobile JS checks.
- All five actual browser downloads match their original ZIP bytes and hashes.
- The first keyboard tab reaches the skip link and Enter reaches the main area.
- Each localized viewer traverses all48 frames across13 collections. Previous,
next, range, timeline, timed play/stop and original-image dialog controls pass;
displayed original links and proof hashes match the immutable records. The
live guest remains explicitly disconnected.
- Actual WASM Tetris keyboard/drop, Suika touch buttons, restart and text-screen
fallback/restore pass. These are browser design/game previews only.
- JavaScript-disabled contexts expose usable downloads/setup and both preview
fallbacks. Their actual1280x800 original PNG loads, matches manifest SHA256,
and has localized JSON links without375-pixel overflow.

Real HTTPS public baseline at20:51 UTC returned a Cloudflare security challenge
(HTTP403), preserved in `output/playwright/public-baseline-challenge.png`.
TLS validation stayed enabled; no challenge bypass was attempted. Local checks
do not establish public delivery. The live nginx release, console route and
client-global configuration were not changed. Deployment is coordinated with
the existing release owner; final ISO/native acceptance and public download
verification remain open.
