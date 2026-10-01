# c957 reviewed private replacement preparation

Source commit `a4fcab9` consumes peer f7f1aea's four public source files and
repairs two independently identified readback validation gaps. The constructor
prepares a new private FAT disk using explicit source/payload/receipt hashes,
real Linux source read leases, fixed ke2046 boot-template assembly, original
member backups, independent destination readback and the existing17-GiB plus
capture reserve. Reflink remains mandatory when selected, with no fallback.
The example intentionally contains invalid placeholders.

The recognized producer remains the ordinary dos16-freedos schema; this does
not infer an unrecorded complete kernel compiler closure. The reconciled
Windows-capable DOS/FreeCOM producer and installed-source launch profile are
separate work owned by canonical163f/fada. Actual large NAS/private disk jobs
remain with those owners and their resource/transport gates.

ROOT first materialized the four exact peer git blobs and reproduced all25
existing host controls in2.838seconds. Independent review then identified:

- Final destination hashing covered only the declared prefix and did not check
the actual extent after mcopy. Real synthetic mcopy followed by an appended
byte after each call produced a successful receipt for1064960 bytes while the
file contained1064962 bytes.
- FAT chain start validation occurred only inside the traversal loop. An EOC
start was accepted as an empty directory and as a zero-length file.

All three new rejection assertions actually failed against frozen original
production code in0.137seconds. Receipt
`build/pma-c957-replacement-constructor-host/validation-red-result.json`, SHA256
`92e81af4cc3df0caf96399f925ec72815c9f7668561e0eb2c9499d5bbd097f26`.
The original25-pass receipt and targeted RED inputs/logs remain unchanged.

The successor validates the initial cluster before EOC traversal, retains
legitimate empty-file cluster0, checks actual destination size after payload
tools and hashes the entire actual extent with stable fd/path identity. Its
new real mcopy-append control requires refusal before VBR writes and absence of
a canonical preparation receipt. Fresh30 tests pass in3.559seconds, with all
four sources, seven GPL upstream source/template inputs and five tool hashes
stable. Receipt `build/pma-c957-replacement-constructor-green/result.json`,
SHA256 `df1d3581cd243b43f9ea43669f008ca7fc9e2dfa32558f392cd3040aae908fda`.
Independent source/receipt review closes both findings and approves this scope.

Final production SHA256
`87bdfea2d75a1ffd79690ff90eacb36aafc056964768ed645d450512a21fa3d9`;
test SHA256
`3e5b46d7a698efe898b4321c2f0387b2f6ea31de7078eaa3d34458dcdbeaccd3`.
README/example remain byte-identical to the peer unit. A correction-only patch
from exact f7f1aea is handed back in the shared peer coordination mailbox, so
its owner can apply the two-file repair without an add/add import conflict.

Tests use tiny synthetic FAT12 and40-MiB FAT32 images, mock capacity only for
that fixture admission, and real local NASM/mcopy/lease operations. Upstream
GPL source/templates are read from the existing pinned main-integration build;
the host test currently depends on that explicit fixture path. No downloads,
real Windows media, NAS copy, VM, Windows boot or public artifact was involved.
All Windows replacement/native acceptance flags remain false.
