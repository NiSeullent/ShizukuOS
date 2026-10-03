# SPDX-License-Identifier: GPL-2.0-only
"""Public, independently reviewed producer anchors; never private fingerprints.

Missing native anchors deliberately refuse issuance. Updates require independent
actual build readback; neither a runtime request nor a receipt can extend these.
"""
from contextlib import contextmanager

INGEST_SHA = '3b778f60771580f4710e7fd019e40cbef44f6dfd5b9f7ddf628453c6c8615642'
DOS_RECEIPT = (17602, '85887531f06bff15b1041476d934f53ec1103e3a4894ba80e6640a1a2058e366')
DOS_ARTIFACTS = {
    'KERNEL.SYS': (74601, '92d73624aa760402ff66108c2da9b8e7bb4ea6954dcb529b7f79c81994764286'),
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
# Exact public compiler roles with independently read-back canonical bytes.
# All source/media/payload inputs retain their one-link boundary.
NATIVE_COMPILER_TOOLS = {
    'gcc': {
        'path': '/usr/bin/gcc',
        'bytes': 1375448,
        'sha256': '14fb376b605118106271d574705c16d6a75cf38ffecefd667db290555670bf53',
        'nlink': 3,
    },
    'private-efi-gcc': {
        'path': '/usr/bin/x86_64-w64-mingw32-gcc',
        'bytes': 1982488,
        'sha256': 'af56f5f5d9cda276727d6e075b697a02e6567855406d3e3d0e2f795c971356f2',
        'nlink': 2,
    },
    'private-efi-as': {
        'path': '/usr/x86_64-w64-mingw32/bin/as',
        'bytes': 1739320,
        'sha256': '860d892a873cef572f116b6cbee19ac277a1f19ad8ff4031cdb718a0caea11bf',
        'nlink': 2,
    },
    'private-efi-ld': {
        'path': '/usr/x86_64-w64-mingw32/bin/ld',
        'bytes': 1768784,
        'sha256': '9611e4ac757eec9fc5a4e595390e577eda45ef3841cad552d8bbbb2383fbb321',
        'nlink': 4,
    },
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
