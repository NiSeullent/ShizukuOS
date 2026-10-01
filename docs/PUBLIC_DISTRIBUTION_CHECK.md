# Public distribution acceptance

`Public distribution acceptance` runs from a GitHub hosted Ubuntu runner after
the verifier is merged into `main`. It checks the real public address
`https://m98.nyase.kr` through normal DNS and certificate-verified HTTPS, then
uses the runner's installed Google Chrome to inspect rendered HTML. It does
not deploy the site, edit DNS, use origin overrides or require secrets.

The required routes are `/`, `/en/`, `/vnc.html` and `/vnc_lite.html`. The two
old VNC paths must ultimately show the project homepage. HTTP responses must
be 200 HTML, have the Windows 98 / Shizuku branding, and contain neither an
active noVNC interface nor a Cloudflare challenge or browser error. Redirects
handled by the HTTPS client remain on the exact same HTTPS hostname. The
normal resolver must return public addresses and `/etc/hosts` must contain no
override for the target.

The exact legitimate Cloudflare JavaScript-detection resource
`/cdn-cgi/challenge-platform/scripts/jsd/main.js` is permitted on an ordinary
homepage. A visible challenge page, `CF-Mitigated: challenge`, other challenge
routes and non-200 responses still fail. HTTP and Chrome checks run independently
for each route, retaining browser evidence even if the HTTP client is blocked.

Chrome runs headlessly with `--dump-dom` and a fresh temporary profile. The
verifier explicitly chooses the normal Linux Chrome User-Agent for the actual
installed Chrome version, replacing the default `HeadlessChrome` identity.
This policy and exact version/User-Agent are recorded. It evaluates the
homepage under that browser identity; it does not claim that the default
headless identity succeeds. No certificate validation is disabled and no
proxy, DNS mapping, browser package or npm dependency is installed by this
workflow. The retained DOM is checked independently of the HTTP body.
Each browser process has a 45-second limit and 3 MiB combined output limit;
HTML bodies are capped at 2 MiB. Reads check a total deadline between partial
arrivals rather than waiting for a large buffer to fill indefinitely.

## Dispatch after the main merge

In GitHub Actions select **Public distribution acceptance**, choose `main`, and
run it. Other branches are skipped. Leave all ISO inputs empty for homepage
acceptance only. For a published ISO, supply all three fields from the actual
publisher receipt:

| Input | Required value |
| --- | --- |
| `iso_path` | Public `.iso` path on `m98.nyase.kr`, for example `/downloads/release.iso` |
| `iso_sha256` | Exact lowercase 64-character SHA-256 of the published ISO |
| `iso_bytes` | Exact decimal byte count of the published ISO |

Do not infer these values from a filename or homepage link. The checker streams
the entire ISO without storing a disk image, requires exactly the expected
bytes and SHA-256, rejects encoded responses and mismatched `Content-Length`,
and checks the ISO9660 `CD001` descriptor signature and version at sector 16.
Thus a matching hash of an HTML error page cannot count as an ISO download.
The default download bound is 4 GiB and 900 seconds, with a maximum 15-second
socket wait per read. The workflow has a 25-minute outer limit. The source CLI
allows an explicit size limit up to 8 GiB and stream limit up to 1,800 seconds;
change the workflow limits deliberately if a real release needs more time.
This signature check does not establish bootability or Windows/app support.
Those remain separate guest and publication-owner acceptance results.

Artifacts are uploaded on success and failure. The named artifact
`public-distribution-<run_id>-<run_attempt>` contains `receipt.json`, the actual
Chrome DOMs and diagnostic logs, and console/test logs. The receipt binds the
checker source, GitHub revision, repository, run URL, runner context, resolved
public addresses, browser version and every observed result. A Cloudflare
block, bad homepage, wrong ISO, missing Chrome or incomplete run remains FAIL;
it is not replaced with a loopback check.

`homepage_external_acceptance_verified` requires every HTTP and Chrome route
check to pass in the identified GitHub hosted runner. When the ISO inputs are
supplied, `iso_external_acceptance_verified` also requires a complete matching
ISO stream. With no ISO inputs that flag remains false, even if the homepage
passes. The current source/test change alone is not evidence of an external
PASS; inspect the actual dispatched run and retained receipt.

## Local development checks

The offline regression suite mocks network and browser operations. It verifies
URL/redirect rejection, TLS policy, public-vantage claims, challenge/noVNC
rejection, DOM error handling, full-stream byte/hash/ISO-signature failures,
time limits and retained failure receipts. It uses only the Python standard
library and does not access the public site or launch Chrome:

```sh
python3 -B -m unittest discover -s tests -p test_verify_public_distribution.py
```

For an explicitly desired local real-network check with an already installed
Chrome, use a fresh output directory:

```sh
python3 -B tools/verify_public_distribution.py \
  --out /absolute/path/to/fresh-public-check \
  --chrome /absolute/path/to/google-chrome --vantage local
```

A successful local run is labeled `LOCAL_CHECK_PASS`; both external-acceptance
flags remain false. Passing `--vantage github-hosted` outside a real Actions
hosted-runner context is rejected. Local development cannot substitute for the
outside-host workflow evidence requested for publication.
