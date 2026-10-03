# Native installer compiler tools

The private installer build passes source pins and compiler tool role pins
separately. Source inputs, Windows bytes and ordinary tools use the unchanged
`native_payload_ingest.Union.add` boundary, which requires one hard link.

`native_build_tool_custody.BuildToolLeases` retains these four compiler roles
only when the independently reviewed public policy has their exact canonical
path, extent, SHA256 and link count:

| Role | Exact hard links |
| --- | ---: |
| `gcc` | 3 |
| `private-efi-gcc` | 2 |
| `private-efi-as` | 2 |
| `private-efi-ld` | 4 |

The policy map must contain exactly these roles. A missing anchor or a
caller-provided approval field cannot extend it. Other hardlinked tools refuse
admission. MinGW `cc1` and `collect2` are also discovered and held through the
ordinary one-link boundary.

The tool owner borrows the same input Union and does not install another SIGIO
handler. It retains each original read descriptor, read lease and inode/path/
ctime/link identity through compilation and final readback. A writer opening
any hardlink alias breaks the shared custody even if the writer never changes
bytes. Cleanup attempts every tool descriptor's final full hash, lease release
and close, then removes its guard before the input Union releases its FDs.
Private source owner cleanup runs while both source and tool leases remain
held. Successful build receipts follow all mandatory closes.

Host controls use real Linux hardlinks and read leases, including alias writers,
identity substitution, failures and actual GCC/MinGW compilation and EFI
linking. Their policy anchors and Windows producer authority are explicitly
modeled. They do not prove an installer ISO, Windows boot, a working native
application or genuine installed Windows source.

```sh
python3 -B -m unittest discover -s shizukudos/install/tests -p test_native_build_tool_custody.py -v
python3 -B -m unittest discover -s shizukudos/install/tests -p test_native_release_admission.py -v
```
