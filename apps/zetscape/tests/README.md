# Zetscape native modern-web fixture v1

These seven small payload files perform 22 real page assertions and two native
input controls. They contain no rendering provider, compatibility polyfill or
mock engine. The independent acceptance plan is
`apps/zetscape/fixtures/modern_web_acceptance.json`. Sources are MIT licensed.

Open `index.html?nonce=<fresh-token>` in the actual standalone browser. Static
HTML, layout, Canvas/SVG and input checks have no external resources. Module
loading must use the actual engine's normal origin/security rules. Current
shared ABI navigation accepts HTTP(S) only, so a later root-owned explicitly
authorized loopback server is needed; none is started by these fixtures.
Serve `.mjs` with `text/javascript`, HTML/JS as UTF-8, and JSON as
`application/json`. Use no security-disable flag or global host-file changes.

Fetch runs only at `http://127.0.0.1:<authorized-port>` with the additional query
`allow-loopback-fetch=<same-token>`. It omits credentials, rejects redirects,
stays on the same origin, caps streamed body bytes at4096 and aborts after five seconds. All other origins or
missing authorization record a failed/unexecuted fetch assertion. Local HTTP
testing does not prove TLS. Modules never fall back to classic scripts.
The native receipt must bind the exact approved origin including port, server
hash, navigation URL and nonce; a matching query token alone does not establish
server ownership or permission.

Click the button three times, then type `Zetscape98` into the input and press
Enter. Script-dispatched events cannot satisfy these controls. The actual host
must separately bind Win98 input, owned HWND/process and visible frame evidence.
Synthetic event ordering is a separate DOM assertion. Unicode byte/codepoint
and normalization checks do not prove readable glyphs without exact font and
native display evidence.

`window.__zetscapeAcceptance` returns a JSON snapshot; the same data appears on
the page. Every expected assertion must occur exactly once. Missing results,
errors, rejected promises or the 120 second deadline prevent subset PASS. The
host must have its own timeout because an engine hang cannot run a page timer.
Freeze every payload hash and bind the fresh nonce to the actual native launch,
returned result and screenshot. The current ABI has no page-result evaluation
callback, so native machine-readable collection is still a provider interface
gap. Visible JSON is ready for a future genuine integration.

Canvas checks use opaque interior RGBA values, actual transforms/paths and PNG
encode/decode. SVG geometry and raster readback are separate. WebGL compiles real
shaders, draws and reads pixels; absent support fails rather than inserting a
substitute. Renderer strings are observations and cannot prove hardware use.
Hardware acceptance additionally requires exact driver/device provenance,
actual command submission/completion, rendering readback and native presentation.
CPU painting or copying pixels to a GOP framebuffer proves a display path only.
A hardware request that falls back to software cannot earn GPU PASS. Repeat the
same fixture on ordinary Win98SE and the actual Shizuku target separately.

The [WPT local runner](https://web-platform-tests.org/running-tests/from-local-system.html)
supports machine-readable reports and screenshot evidence. Our files are custom
representative assertions, not upstream WPT. The acceptance plan requires an
exact WPT commit/manifest/test-ID inventory and complete outcomes before a WPT
subset verdict; those pins and runs do not exist yet. A complete modern-web
target also needs a versioned scope, full test denominator, test262, security,
network, storage, media, accessibility and real application coverage. Twenty-two
assertions cannot justify a 100% claim.

The actual current JSCOnly bring-up profile has WebAssembly disabled, uses the
C_LOOP interpreter and has JIT disabled. WebAssembly execution, SIMD and threads
remain concrete full-target gaps. The fixture also leaves modern CSS features,
media, accessibility and security WPT coverage pending. An optional
`ZetscapeGetExtensionsV1` observation or a `--shizuku` selection is metadata;
actual initialized driver/device submissions and completed frames are still
required for hardware acceptance.

`source_check.py` performs host syntax/resource-inventory checks only. It creates
no object/native binary, starts no server and executes no page/browser/provider.
Source checks, ordinary native acceptance, hardware acceptance and full modern
web acceptance are reported separately.
