# Independent headed Chrome distribution verification

This adds a separate browser acceptance path. The existing strict public HTTP/urllib verifier and its actual Cloudflare 403 failures stay unchanged. A browser result cannot overwrite or relabel them.

The helper uses preinstalled Node with its built-in WebSocket, preinstalled Chrome, and a new owned Xvfb display. It launches headed Chrome with a new private profile. It injects no UA, request headers, cookies, certificate exceptions, DNS overrides or Cloudflare bypass. KO/EN and both legacy VNC routes must render the branded official homepage with a trusted HTTPS 200 main-document response. Iframe responses cannot supply the page status.

An optional ISO is downloaded by Chrome's real native download facility, not by a host HTTP client. Matching frame/URL, one safe GUID and complete monotonic byte events are required. The private regular file is then read through a bounded no-follow FD to verify exact full SHA-256, byte count and ISO9660 primary volume descriptor. This is a distribution proof, not an ISO boot, Windows 98 MS-DOS replacement or modern-application proof.

The native download and profile live in a private temporary directory outside the evidence directory and are removed after owned launcher children are reaped and their process groups are terminated. GitHub artifacts use an explicit JSON/DOM/log allowlist; the workflow never uploads an ISO, USB image or Chrome profile. No npm/browser download or additional dependencies are used.

```
node --test tools/tests/test_public_chrome.mjs
node tools/verify_public_chrome.mjs --out /new/evidence --chrome /installed/google-chrome --xvfb /installed/Xvfb
```

Supply `--iso-path`, `--iso-sha256` and `--iso-bytes` together for an ISO of at most 512 MiB, matching the public publisher limit. Output must be new. Public URLs are limited to canonical HTTPS paths on m98.nyase.kr. An actual 284,164,096-byte sparse synthetic ISO control exercises full file hashing and PVD validation above the old 256 MiB limit; it is not a shipped ISO or boot proof.

Protocol semantics were checked against the [official Browser protocol](https://chromedevtools.github.io/devtools-protocol/tot/Browser/) and [upstream protocol JSON](https://github.com/ChromeDevTools/devtools-protocol/blob/master/json/browser_protocol.json). `allowAndName` names downloads by their GUID; a completed event alone does not guarantee that its file exists, so actual file verification is required. The [Node built-in WebSocket](https://nodejs.org/api/globals.html#class-websocket) avoids a package dependency.

Current local controls validate actual file reads, full hashes, truncation/corruption/type/path/deadline failures, native event contracts, CDP error/close/deadline behavior, expression syntax, iframe isolation, artifact rejection and actual owned process termination. Twenty-one host tests pass, including cleanup of both children when CDP closure fails and invalid CLI rejection before launch.

Separate actual CLI negative controls use temporary stand-ins for launcher processes, with ordinary public DNS lookup: interruption, missing Chrome and missing Xvfb must fail and reap every owned child while removing private directories. The interruption control first reproduced an interrupted cleanup and a surviving launcher; that failure remains recorded. Cleanup now completes even after interruption and attempts both launcher children independently. These are launcher controls, not real browser tests.

The receipt binds the helper's source bytes before and after execution, the workflow commit and Node version, and the optional expected ISO URL/hash/size. Local Chrome exists outside PATH, but Xvfb is absent. No actual headed browser or public ISO acceptance is claimed by local controls; hosted execution remains pending.

Address admission rejects private, shared, loopback, link-local, multicast, documentation and reserved IPv4 space. IPv6 requires allocated global unicast and rejects mapped IPv4, scoped and documentation addresses, and non-global special ranges. This is deliberately narrower than `ipaddress.is_global` alone for mapped, translation, multicast and reserved-but-otherwise-global space. The [Python classification documentation](https://docs.python.org/3/library/ipaddress.html) and [IANA IPv6 global unicast registry](https://www.iana.org/assignments/ipv6-unicast-address-assignments) describe the special ranges and allocation. Every returned DNS address must pass; no address or resolver is overridden.

Canonical JSON receipts use an exclusive same-directory temporary file, complete counted writes, fsync, close and exact byte readback before atomic rename. A real partial valid `PASS` JSON followed by ENOSPC, failed close/fsync, lying or invalid counts, and failed rename cannot leave a canonical success receipt. Temporary failure files are removed, and artifact admission runs before publication. The old direct-write failure remains separate evidence.
