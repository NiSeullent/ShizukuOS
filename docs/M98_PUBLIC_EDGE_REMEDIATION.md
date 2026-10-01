# m98.nyase.kr public route and HTML preservation

The user's2026-10-01 direction is to serve the existing hostname on this server
and change only scoped Nginx routing/response behavior. No Cloudflare account,
DNS record, other virtual host or client-global configuration was changed.

## Actual routing and earlier observations

The running master is PID116330, binary `/srv/opt/nginx/sbin/nginx`, config
`/srv/conf.d/nginx/nginx.conf`. Active `nginx -T` and listen inspection confirm
that this master serves port80/443 and includes the exact `m98.nyase.kr` virtual
host plus `/srv/m98/nginx/locations.conf`. The exact hostname selects the static
vhost, ahead of wildcard names. Origin `/` uses `/srv/m98/current/site/index.html`;
`/vnc.html` and `/vnc_lite.html` redirect to `/`. `/legacy-console/` is an explicit
separate legacy console. No default page embeds a VNC canvas/script.

Earlier defaultcurl and defaultheadlessChrome153 requests received403
`cf-mitigated: challenge`, title `Just a moment...`, Ray IDs
`a43bd3170b65b0a3-YYZ` and `a43bd5687b1b35ae`. This is a specific automated-request
observation, not proof that a normal user sees VNC or cannot access the homepage.
The challenge product/rule was not inferred.

Independent peer and fresh standardChrome request User-Agent requests using
ordinary publicDNS HTTPS and normal certificate validation returned200 for the
actual official page. Before the Nginx header fix, Cloudflare appended analytics
and JavaScript detection scripts to HTML; random parameters made the HTML body
hash vary. The JSON/PNG/component ZIP already matched the reviewed bytes exactly.

## Scoped server change and actual verification

Only `site/deploy/m98-locations.conf` and its live
`/srv/m98/nginx/locations.conf` counterpart changed. Add `no-transform` to the six
existing `no-store, max-age=0` response directives and the default static
location, preserving the existing security-header include. This prevents proxy
rewrites of the reviewed HTML and keeps directory-index entry pages under the
same policy. The live file changed fromSHA256
`9f630bcbd25f98f8b9d5a9abf5e1097d043bf5ddc40e4b66493998a66da46392` to
`e5e4cd76b9aad82264bb63101edded8fc95f29251529f89f633951a26dbb86c9`.
Syntax test and scoped graceful reload both returned0; the master PID remained
116330. Original config was retained for rollback. Existing unrelated-host
HTTP2/default-name warnings were preserved and not edited.

Fresh publicDNS HTTPS requests with normal TLS certificate validation and a
standardChrome146 request User-Agent then returned200 and **byte-for-byte exact
reviewed body SHA-256** for all eleven checked routes:

- `/`, `/index.html`, `/en/`
- `/authorship/`, `/authorship/handoff.html`, `/authorship/evidence.json`
- `/authorship/images/chromium-loading.png`
- `/vnc.html`, `/vnc_lite.html` following redirects to the exact homepage
- `/downloads/SHZGOP.zip`, `/downloads/SHZGOP.zip.sha256`

HTML responses carry `Cache-Control: no-store, max-age=0, no-transform`; no
Cloudflare-added scripts or VNC UI are substituted in those exact responses.
Cached immutable component assets can retain previous response headers, but the
checked asset/download bytes remain exact. The actual receipt is retained in
ignored `build/authorship-publication-20261001-v1/public-no-transform-v1`.

This proves the public edge from the build host's network with explicit standard
browser request headers. It is not an independent outside-host proof and does
not erase the earlier defaultheadless challenge. The final ISO's full external
size/hash/range/browser-download checks must run after its separate build and
publication. GitHub-hosted verification is a separate fresh gate.

## Repeat and rollback

Use ordinary hostname DNS resolution and valid public TLS; do not substitute a
loopback `--resolve` response for public verification. Compare each returned body
with the reviewed deployed source or recorded original PNG/download checksum.
Follow both oldVNC redirects and reject a VNC body. Preserve any challenge or
failure without relabelling it as an exact homepage/download result.

If a scoped change fails, restore the recorded previous locations file, run
`/srv/opt/nginx/sbin/nginx -t -c /srv/conf.d/nginx/nginx.conf`, then reload this
same master with `-s reload`. Keep unrelated vhosts unchanged. The static release
publisher retains its separate current-symlink rollback path.

Primary documentation supporting this response-preservation choice:

- [Nginx server-name precedence](https://nginx.org/en/docs/http/server_names.html)
- [Cloudflare analytics automatic injection and no-transform](https://developers.cloudflare.com/web-analytics/faq/)
- [Cloudflare JavaScript detections and no-transform](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/)

A real publicChrome153 headless browser with an explicit standarddesktop request
User-Agent then passed41checks through ordinary publicDNS/TLS: actualpage rendering,
six original-image full decoding/bodySHA,320/390px layouts, continuation links,
currenttarget navigation, botholdVNCredirects and a realcomponentZIPdownload. The
download was1,748,147bytes and SHA256
`6b322139ff1b2417b6a1792f036082f284883d095e4bda57d560c85c57f958e7`, exactly the
reviewed development component bundle. This browser used no resolver override.
Its request-UA context is explicit; the earlier defaultheadless403 is preserved.
The finalISO and independentoutside-host gate remain separately pending.
