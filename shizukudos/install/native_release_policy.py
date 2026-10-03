# SPDX-License-Identifier: GPL-2.0-only
"""Public, independently reviewed producer anchors; never private fingerprints.

Missing native anchors deliberately refuse issuance. Updates require independent
actual build readback; neither a runtime request nor a receipt can extend these.
"""
from contextlib import contextmanager

INGEST_SHA = '31bdb8bb82e586af6aefc5d496a7c8f8cea36ff3ae35afc9cf628fd39a5e15c4'
DOS_RECEIPT = (17294, '1205ca7575ce30e17a71f2f1c707a0c571cd09c6c60c77f1fd0e924c2fc03104')
DOS_ARTIFACTS = {
    'KERNEL.SYS': (74009, 'cd8ccf3d4f837fd4d675037468ce10023af37874342c407630a3f56af6c07c6e'),
    'COMMAND.COM': (88188, '27c91c0c27d7aac140fd3dbeb4c20592ae6fae0555d4e310cf749e2102bd3e50'),
}
WATCOM_SHA = '4fdc24c04a02e31ffedae1690fc2c6d53fcb01464f92692adf6b17a7e890af3f'
# Exact native producer source-map canonical digest and artifact extents/digests
# must come from the separately reviewed actual producer, not this generator.
NATIVE_SOURCE_MAP_SHA = 'f63fcfa40cbe0fb4b6c0e3290071b1ca20bd35776c411d046320797ab73a372f'
NATIVE_ARTIFACTS = {
    'KERNEL32.BIN': (52796, '87efaee8b0d51493520d5ed51595a5dd7ae0c087984d4dc1c9ed61c7a0f9c882'),
    'KERNEL64.BIN': (857424, '0a0be153b005c51b91975d93d0f21088956f2e8e50a7009d6c2c16bb97509640'),
    'BOOTX64.EFI': (243200, '4ddaa2cd3c208ad02032a0a83c00af0dfd9cecdd1ed08b9d70c84c7d71ab4ab5'),
    'WIN64.IMG': (23413535, 'de87d66af6444fde1de0b51c479e12a8afaf6e36743baa54d81f0afc87fe763d'),
}
# Actual source-built public BIOS, independently checked against the producer's
# complete source archive, generated inputs, original tools and closed unit.
# Native ESP production must use these exact bytes; old packaged BIOS refuses.
NATIVE_SYSTEM_BIOS_SOURCE = {
    'artifact': (262144, '7181de0b555e78ea05ca7fa16702f732d4abf71f44ab572ff8d23510ec85638e'),
    'receipt': (34850, 'b864a9c952d98359601cd3c916c0fb64873f90ccefd55fc2125018f33ce6bcd4'),
    'source_archive': (2877440, 'deeccf47da2716463f99bc59bb5e2e0e84af23f8a8d88a954e1fe72b77b09c04'),
    'source_commit': '578d260b94f62150bf6ab9149784287bd1154f06',
    'source_map_sha256': 'ff41cd97810efc0c509159d7c16e5d431b5f57e9168839569258c4dc96fc83fc',
    'tool_map_sha256': '0b246662b8a6e1cc76841f80d71f96dfb21e8706d5ce4a197ee20be5efe092ba',
}
# Real completed-control checkpoint authority is independently owned and private.
GENUINE_BASELINE = None


def verify_private_source_custody(request, held):
    """Missing independent installed-source producer service; fail closed.

    A saved profile/inventory cannot prove genuine installed Windows bytes.
    Integrate the independently owned producer custody/nonce verifier here;
    never accept a caller-provided approval bit or private source SHA alone.
    Private approved source fingerprints must remain outside public Git.
    """
    del request, held
    raise ValueError('independent actual installed-source custody absent; admission refused')


@contextmanager
def hold_private_source_custody(request, held):
    """Default refusal, with a build lifetime for a reviewed private owner.

    An independently admitted private bootstrap may supply a managed live
    verifier. Its keeper must finish and reap while this same input Union is
    still open. A dict or saved receipt never supplies that managed lifetime.
    """
    yield verify_private_source_custody(request, held)
