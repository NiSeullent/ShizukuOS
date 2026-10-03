# SPDX-License-Identifier: GPL-2.0-only
"""Public, independently reviewed producer anchors; never private fingerprints.

Missing native anchors deliberately refuse issuance. Updates require independent
actual build readback; neither a runtime request nor a receipt can extend these.
"""
INGEST_SHA = 'ff0296c12ea447b3ac154e0c48988825f85b73c655d74b652c0b1778fc8aedcc'
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
