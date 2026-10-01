# Preserve the official continuation and helper in the primary publisher

This is a **source-only patch proposal**, not a new site release. It has not
modified the primary checkout or index, published the site, built an ISO,
started a VM, or changed nginx. Final ISO/source/archive pins were unavailable
when this proposal was frozen; this package authorizes no artifact activation.

The exact primary source snapshot is
`8508c5e360fe8c24c659b719f1ed21831cbdbd4c`. Its publisher has 719 lines and
41,392 bytes, SHA-256
`5dfd2ffc0bea1006f755c5965c7e6129e3958173239966af310cd96fef18f51f`.
The earlier requested commit
`6a18ee1f4af4261963fd87e7a759e070630ffc5b` contains that same publisher.
The site source was clean when copied. This proposal extends that primary
publisher; it does not replace it with the old root 1f5 publisher.

## Contents and validation

- [primary-continuation.patch](primary-continuation.patch): exact binary-inclusive
  patch, 124,628 bytes, SHA-256
  `d995dbef36a82fa28f1d8e4f12aa0e91f362b32df79a79b8d5e8a206c9b660e3`.
- [preimages.json](preimages.json): five existing-file preimages, identities
  from both committed source epochs, and the nine frozen continuation assets.
- [source-freeze.json](source-freeze.json): exact fifteen-file allowlist and
  resulting byte/hash pins, scope, and identities of the other receipts.
- [test-receipt.json](test-receipt.json): complete actual RED and GREEN logs
  with only local working prefixes normalized, their original and normalized
  hashes, execution scopes, and the separate isolated patch-application check.

The eight new controls first failed against an unchanged copied publisher,
including 52 subtest failures. They reproduced the missing 9-file inventory
and failure to reject missing or changed helper/guide files. The final full
suite passed **34 tests, no skips**; its original log SHA-256 is
`592f12c8489b5c7d6cfb3fd94dba7b319f6bf9a17376df7f64a7ffe45ab2aaea`.
An actual binary patch application to a fresh isolated copy also passed:
all fifteen resulting file sizes and hashes matched the freeze, including
the helper ZIP. The separate case with all nine exact e6 assets already
present also passed, applying only the remaining changes and checking all
fifteen result identities. No live HTTP transport or real site activation
was exercised.

The normalized log placeholders `${CHECKOUT}` and `${FIXTURE}` describe source
and synthetic-test locations. The exact patch also preserves two repository
path examples already published in the historical environment guide. They
identify old project layouts, not private Windows media, VM or staging paths,
and must not be treated as successful reproduction in a different workspace.

## Additive changes

The patch modifies exactly five existing files: the current publisher, its
existing tests, Korean and English home pages, and Authorship handoff. It adds
one new eight-method test module and nine historical continuation/helper files.

The publisher admits those nine files only at their reviewed byte sizes and
SHA-256 values. The helper source commit and manifest scope are checked
separately. The historical development ISO, full source archive and main Git
bundle remain pending with no URLs; a changed JSON state cannot admit a new
artifact. Private media and unverified native/Setup/full-USB claims remain
false. This does not create a new artifact-admission path for the primary
owner's future source archives or Git bundles.

AST comparison confirms every pre-existing function and class is unchanged,
except for one new call inside `prepare_assets`. Current ISO receipt/source
identity, streaming, private-input refusal, shipped-ISO boot evidence, four
download CTAs in each language, HEAD/Range validation, atomic receipts,
publication locks and rollback checks are retained. There is no CSS change.

Preparation includes all 92 public paths. Eighty-nine current public files are
unchanged; the three intentional differences are local navigation and handoff
HTML additions. Existing evidence PNGs, previews, ZIPs, game and other product
branding bytes remain intact.

## Historical helper and product scope

Current branding remains **ShizukuOS 1.0.0 development candidate**. The local
continuation links explicitly describe the preserved **0.9.0-dev source
checkpoint**, not the current ISO download state. Downloaded Markdown links
are relative to the source checkout; current downloads remain on the home page.

The 17,916-byte helper source ZIP retains SHA-256
`f5492becf55ecbfea079c829d473133cbe6073dbcb1b762a94f933f5679d9e54`
and source commit `899c51ec6f4c731fe3181570feec0fa52bfbd591`. It contains only
helper source, documentation, tests and GPL license. It contains no Microsoft
media, product key, project ISO or complete USB installation payload. The ZIP
appears as the only binary patch entry because its public source files were
packaged as ZIP; no native application or OS binary is included here.

ShizukuDOS replacing MS-DOS for actual Windows 98 is the architecture goal.
Kernel32 and Kernel64 are Windows 98 components. Standalone or host results
do not establish that replacement, Windows 98 startup/Setup or full modern-app
operation. GitHub remains the public source/patch channel; official ISO
distribution stays on m98.nyase.kr. This proposal introduces no GitHub ban.

## Integrate through the primary owner

When merging the earlier root **e6 publication changes**, resolve publisher
and current-page conflicts by preserving the primary 719-line publisher and
current ShizukuOS branding first. Do not take the old root 1f5 publisher or
entire old home pages. Keep the nine continuation/helper assets if their
identities match this freeze. Then review this additive proposal.

Compare all five existing files to `preimages.json` before applying. If any
preimage changed, stop and manually rebase the small addition onto the owner's
latest implementation. Retain any newer ISO, private-source/archive, Git-bundle
or publication gates. Do not overwrite a newer publisher with the staged file.

If all ten new paths are absent, the primary owner can check and apply the
exact patch from the repository root:

```sh
git apply --check docs/shizukudos10/reports/official-continuation-primary-20261001/primary-continuation.patch
git apply docs/shizukudos10/reports/official-continuation-primary-20261001/primary-continuation.patch
```

If the e6 merge already brought in **all nine identical continuation/helper
files**, check each existing size/hash against `exact_nine_historical_assets`
first. If the new test file is still absent and the five existing preimages
match, exclude only those already identical nine files during application:

```sh
git apply --check --exclude='site/continuation/*' --exclude='site/downloads/win98-modern-usb-helper.zip*' docs/shizukudos10/reports/official-continuation-primary-20261001/primary-continuation.patch
git apply --exclude='site/continuation/*' --exclude='site/downloads/win98-modern-usb-helper.zip*' docs/shizukudos10/reports/official-continuation-primary-20261001/primary-continuation.patch
```

Mixed or changed new-file states require a deliberate rebase. After application,
compare all fifteen resulting identities with `source-freeze.json` and run:

```sh
python3 -B -m unittest discover -s site/deploy/tests -p 'test_*.py' -v
```

Root and the primary owner control commits and main integration. Do not invoke
the publisher's main entry from this package. Final ISO/source/Git-bundle
activation needs its own exact artifact, corresponding-source and boot review;
the proposal's isolated tests cannot replace that acceptance. Preserve all
92 continuation/helper paths in every future release.
