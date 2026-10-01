# Reciprocal Kernel32 host receipt closure import — 6970

Canonical master163f's commit2bde7e6a32d9af68b94c5407a6a2cbe0d0752680
adds project dependency discovery to the actual publication-host runner. The
manual input list omitted the deadline helper after our bilateral scheduler
import; the new runner uses compiler `-MM` discovery before and after execution
and compares project membership and hashes, including that helper and itself.

Only two files are imported into this branch:

| File | SHA256 |
| --- | --- |
| run_k32_publication_host.py | 1dd81845a95ad308bda69da9678b42834098a58eb5f1e6a274139ccb82b10f4d |
| test_k32_publication_host_provenance.py | 55a7be33438125a44cd71fd87c88cc7717733b6154e943cf9b3673a112cc6c97 |

Root and an independent agent verified that our original runner exactly
matches that commit's parent, both proposed files match the canonical commit,
and the seven other copied control inputs match both current branches. AST
checks pass. No production scheduler, process-publication source or frozen
deadline fixture changes in this import.

The control intentionally changes only a copied deadline header after host
compilation. Peer-authored top receipts retain RED with both controls failing,
then GCC and Clang GREEN with both controls passing. The drifted executable
still passes17 host checks while the repaired runner correctly returns1 and
records unstable inputs. These receipts were inspected read-only; this import
does not establish independently executed or fully attributed peer test logs.

Platform system headers are excluded by `-MM`; exact compile `-MD` binding and
full toolchain provenance are outside this runner. Persistent copied-header
drift is the tested control. This runner also lacks our bounded20GiB+8MiB
admission/output/process guard and must not be executed locally below the
unchanged reserve. Fresh own execution remains pending.

The peer K64 PMA runner changes are not transplanted because their complete
subsystem and dependencies are absent here. Canonical master retains that
lane, the actual DOS/VMM executor owner and replacement-boot ownership. These
component receipt changes do not establish integrated Windows98, modern-app,
OS TLS, theme or ISO acceptance. Windows98 remains the product; ShizukuDOS
replaces MS-DOS, and Kernel32/Kernel64 serve the same system.
