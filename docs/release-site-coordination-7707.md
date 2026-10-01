# Intermediate evaluation site preparation — chat 7707

Chat `01a0f3d1-7707-7d10-962d-26c937d2743b` owns only the new isolated
`/root/Win98-Modern-release-7707/` staging directory and this coordination file.
The native desktop/runtime owner retains the dirty boot checkout's `site/`,
preview exporter, static publisher, VM disks and all app/driver source files.
No peer-owned file or live route is edited by this preparation.

The user explicitly requested an intermediate evaluation release on the
project's dedicated website, with `독자 사이트` and
`정품인증을 제공하지 않습니다` clearly stated. The actual destination is the
existing `https://m98.nyase.kr` self-hosted static origin. The separate Sites
project `appgprj_6ab3fdb7af9c8191967969bd5afc648d` remains owner-only: read-only
Sites discovery confirmed one allowed owner and zero viewers/editors/groups.
Its audience and content are not changed.

Preparation starts from the immutable current release
`/srv/m98/releases/20261001T055610`, verified against all 54 exact body hashes in
the boot owner's successful receipt. The latest VLC/Notepad++ evidence and all
existing driver/application component ZIP bytes are preserved. The new
`M98EVAL20261001.zip` aggregates those two unchanged component ZIPs and dated
evaluation/setup/license documentation; it adds no experimental TLS or theme
binary and no Windows, target app, Microsoft redistributable, key or VM media.

Root reviews `/root/Win98-Modern-release-7707/review-manifest.json` and the
isolated diff before publication. This sub-agent does not publish. Any later
publisher must acquire `/srv/m98/.publish.lock`, verify the complete expected
current release path and file-hash map immediately before switching, and abort
if the live site advanced. Existing legacy publishers do not acquire this new
advisory lock; the desktop/site owner must also avoid overlapping a publication
with the brief root handoff. Preserve unrelated live changes; never rebuild a
release from the dirty shared checkout. No Nginx reload, DNS change, other
service/route change or client-global configuration change is required.

Theme direct-call/static-import native child logs establish only their API
test success, not an OS-wide theme. The TLS GUI native result remains pending
until root supplies its independently reviewed receipt. The full application,
theme and OS TLS 1.3 goal remains active.

## Browser direction follow-up — 2026-10-01

Latest user direction: a full WebKit engine port is not a prerequisite. A
Trident-based engine may instead be extended/adapted toward HTML5,
WebAssembly/WASM and2026-era modern JavaScript/web standards. This is a design
requirement change, not verified standards support. Chromium/Electron-based
application execution remains a separate required target.

New isolated website preparation belongs only to
`/root/Win98-Modern-release-7707-v2`, copied from actual successfully published
immutable `/srv/m98/releases/20261001T061806266026-eval7707`. Four existing
assets change (index/browser direction, evaluationREADME, rebuiltZIP,checksum);
all53 other assets and the original componentZIP bytes/sources/licenses are
preserved. No peer site/source/VM or live state is changed by preparation.
Root reviews exact manifests/diffs before any further publication.

### Root review correction: preserve distinct evaluation versions

The browser direction update now uses version M98EVAL-20261001-R2 with new
R2 ZIP/README/checksum filenames. The three original v1 evaluation files retain
their original bytes and URLs. Only index.html changes among existing files;
three new R2 assets are added. All 56 other assets remain byte-exact. The owned
v2 review directory remains unpublished pending exact root review.
