# SPDX-License-Identifier: GPL-2.0-only
"""Public, independently reviewed producer anchors; never private fingerprints.

Missing native anchors deliberately refuse issuance. Updates require independent
actual build readback; neither a runtime request nor a receipt can extend these.
"""
INGEST_SHA = 'b0f355ad1e7db8a1ee4eab2987984403fd4226fbd1020c1e4ae2b4abf92f9235'
DOS_RECEIPT = (16995, 'dee0c06ae35bae41efd8db0d53dc391a767cf5d4abe289872bb1dc9c78696b0c')
DOS_ARTIFACTS = {
    'KERNEL.SYS': (72751, 'a9be199f1ac10f0b6e73abb0b27e6a272f7e786ee1561e47e178b92553d1687d'),
    'COMMAND.COM': (88188, '27c91c0c27d7aac140fd3dbeb4c20592ae6fae0555d4e310cf749e2102bd3e50'),
}
WATCOM_SHA = '4fdc24c04a02e31ffedae1690fc2c6d53fcb01464f92692adf6b17a7e890af3f'
# Exact native producer source-map canonical digest and artifact extents/digests
# must come from the separately reviewed actual producer, not this generator.
NATIVE_SOURCE_MAP_SHA = None
NATIVE_ARTIFACTS = None
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
