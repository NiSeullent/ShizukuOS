# c957 bilingual distribution website

Source commit: `7050f3e335f7de7e29ad4d126def6fa1d9e9b507`.
The reviewed static website is deployed on the official nginx origin and
verified through normal headed Chrome at public HTTPS m98.nyase.kr. Actual
Windows98-on-ShizukuDOS and final ISO acceptance remain unfinished.

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

## Actual nginx and public HTTPS delivery

c957 was the named single actor for the bounded static activation, coordinated
through the shared peer mailbox. Both existing publication locks were held;
the previous92-file current release,123 source identities and freshly prepared
100-file map were checked before the reviewed publisher changed the current
symlink to `/srv/m98/releases/20261001T213716`. Previous release
`/srv/m98/releases/20261001T152940` remains byte-identical. Both existing nginx
configuration files are unchanged. No ISO, native proof or private media was
added. The large ISO/continuation/native resource floors remain intact.

All100 saved origin HTTPS response bodies match the frozen v2 map. Publisher
receipt `build/m98-self-host/release-20261001T213716.json`, SHA256
`d6090207da3f868109aeace0e5384df8bb5f67708535c8e8176c46e68ca420fe`.
Guard receipt `build/pma-c957-site-ux-stage-v2/activation-guard-result-v2.json`,
SHA256 `933c054f332c75b15e9a8387f6371a5eb54516869103b5ae84ed2c94b7705c34`.
These origin checks use the existing loopback publisher transport and remain
explicitly separate from public certificate validation.

Normal headed Chrome153 subsequently loaded Korean and English homes at
`https://m98.nyase.kr/` with HTTP200 and certificate validation enabled. Its
actual100 public response bodies match the frozen sizes and hashes; all five
browser-clicked ZIP downloads were saved and independently matched by byte
size and SHA256. Browser TLS records WE1, nyase.kr and QUIC. No custom user
agent, proxy, host mapping or TLS-ignore setting was supplied. The installed
Weston compositor provided a private temporary display without system
configuration or package changes.

Public browser receipt `output/playwright/public-headed-result.json`, SHA256
`e07822916b75c4ebd4c5c2d4c22196fcac3172bbafb7b0181bbcee4b4c3e068a`.
An independent read-only reviewer checked all100 live/prepared/public body
identities, five saved ZIP files (3,548,192 bytes total), configuration hashes
and preserved challenge evidence. Old `/vnc.html` and `/vnc_lite.html` both
redirect to the new public home. Both localized375-pixel homes fit the viewport
and all four images per home decode successfully after actual scrolling.
The first mobile probe incorrectly classified unloaded offscreen lazy images
as broken; its failed record is retained separately. No site source repair was
required. Consolidated later receipt:
`build/pma-c957-site-ux-stage-v2/public-delivery-result.json`, SHA256
`5c89d101f19c78a66cee4c66a39586d1e77c7bd0b2c31d13b5467712fb6daf93`.
Owned browser sessions and the temporary Weston compositor ended normally.
Its scope is the actual normal headed client and static website/downloads.
The earlier public headless Cloudflare403 challenges remain preserved in
`public-baseline-challenge.png` and `public-v2-challenge.png`; those attempts
are not delivery successes. Generic headless/direct-HTTP access and final ISO
download are not inferred from the headed result. Console and VM execution
remain separate from this static publication.
