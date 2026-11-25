#!/usr/bin/env python3
"""Differential test: the parametrized audioport engine must produce
byte-identical output to the original SevenUP CS42L71 pipeline on SevenUP's
own inputs (iPhone 7 15.6 donor -> iPad 7 16.1 target).

Reference side: SevenUP kernel_microphone.prepare + kernel_transplant.apply
(MC1 call signature from kernel_chain.py) + kernel_mc2.apply.
Our side: patchsrc/audioport modules driven by the translated profile that
gen_audio_profiles.py emits for the same kernel pair (must be an identity
translation).

The only SevenUP behavior bypassed: the previous-stage 'MCD' marker rename in
kernel_mc2 (the panic-overlay stage is out of scope), via a tolerant
Edits.string wrapper. The BT1 source marker is NOT bypassed: it is injected
into dead space at the end of the reclaimed AppleANXDPTX __TEXT_EXEC, so the
unmodified SevenUP code path runs end to end.
"""

import json
import shutil
import struct
import sys
import tempfile
import types
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SU = Path('/home/iban/iOS-16-SE/SevenUP-main')
KC_DIR = Path('/home/iban/se-inv-work/kc')
GEN = REPO / 'tools' / 'gen_audio_profiles.py'
PORT = REPO / 'patchsrc' / 'audioport'

sys.path.insert(0, str(PORT))
sys.path.insert(0, str(REPO / 'tools'))
sys.path.insert(0, str(SU / 'src'))

DONOR = KC_DIR / 'iphone9.thin'
TARGET = KC_DIR / 'ipad7b.thin'

BT1 = b'\x1b[32mBT1:%.128s\x1b[0m\n\0'
MC1 = b'\x1b[33mMC1:%.128s\x1b[0m\n\0'
LIBM = {0xfffffff0059f4bf8: {'bytes': '887d16946d80b93f', 'reason': 'Reviewed Libm F64 literal'}}
EXPANDED = {'__DATA_CONST': 0x6000 + 32 + 285 * 8}


def inject_marker(path, out):
    """Write the BT1 stage marker into slack at the end of the reclaimed
    AppleANXDPTX __TEXT_EXEC (a region the transplant overwrites anyway)."""
    from kc import KC
    data = bytearray(Path(path).read_bytes())
    k = KC(path)
    seg = next(s for s in k.ksegments('com.apple.driver.AppleANXDPTX')
               if s['name'] == '__TEXT_EXEC')
    va = seg['addr'] + seg['size'] - 64
    off = k.offset(va)
    # Slack at the very end of the reclaimed code segment; whatever bytes are
    # here are overwritten identically on both sides (the marker write lands
    # inside the reclaimed region and replaces donor slack bytes).
    data[off:off + len(BT1)] = BT1
    Path(out).write_bytes(data)
    return va


def sevenup_side(src, donor, work):
    from iphone7_port import kernel_transplant, kernel_microphone, kernel_mc2, kernel_base, kernel_abi
    from iphone7_port.kc import KC
    d, k = KC(donor), KC(src)
    private, review, slots, patches, extra, skip, finish = kernel_microphone.prepare(
        d, k, SU / 'profiles/microphone-abi.json')
    data, report = kernel_transplant.apply(
        src, donor, work / 'su-mc1', kernel_microphone.OLD, kernel_microphone.NAME,
        BT1, MC1,
        private_bindings=private, private_review=review, slot_overrides=slots,
        donor_word_patches=patches, finalize=finish, extra_donor_slots=extra,
        skip_donor_slots=skip, expanded_segments=EXPANDED,
        non_instruction_words=LIBM)
    # MC2: bypass only the absent 'MCD' marker rename (panic stage not run).
    orig_string = kernel_base.Edits.string
    def tolerant(self, old, new, *, owner=None):
        if self.k.data.count(old + b'\0') == 0:
            return
        return orig_string(self, old, new, owner=owner)
    kernel_base.Edits.string = tolerant
    try:
        project = types.SimpleNamespace(root=SU)
        final, mc2_report = kernel_mc2.apply(work / 'su-mc1/kernelcache.raw', donor,
                                           project, work / 'su-mc2')
    finally:
        kernel_base.Edits.string = orig_string
    return data, final


def our_side(src, donor, work, profiles):
    from kc import KC
    import transplant, microphone, mc2
    abi = json.loads((profiles / 'se-cs42l71-abi.json').read_text())
    switch = json.loads((profiles / 'se-cs42l71-switch-abi.json').read_text())
    d, k = KC(donor), KC(src)
    private, review, slots, patches, extra, skip, finish = microphone.prepare(d, k, abi)
    params = abi['params']
    data, report = transplant.apply(
        src, donor, work / 'our-mc1', microphone.OLD, microphone.NAME,
        marker_source=params['markers']['source'].encode('latin1'),
        marker_target=params['markers']['target'].encode('latin1'),
        private_bindings=private, private_review=review, slot_overrides=slots,
        donor_word_patches=patches, finalize=finish, extra_donor_slots=extra,
        skip_donor_slots=skip,
        expanded_segments={n: int(v, 16) for n, v in params['expanded_segments'].items()},
        non_instruction_words={int(a, 16): v for a, v in params['non_instruction_words'].items()})
    final, mc2_report = mc2.apply(work / 'our-mc1/kernelcache.raw', donor, switch,
                                work / 'our-mc2')
    return data, final


def main():
    work = Path(tempfile.mkdtemp(prefix='audioport-diff-', dir='/tmp'))
    for sub in ('su-mc1', 'su-mc2', 'our-mc1', 'our-mc2'):
        (work / sub).mkdir(parents=True)
    src = work / 'ipad7b-marked.thin'
    inject_marker(TARGET, src)
    profiles = work / 'profiles'
    import subprocess
    subprocess.run([sys.executable, str(GEN),
                    '--ref-donor', str(DONOR), '--ref-target', str(TARGET),
                    '--donor', str(DONOR), '--target', str(TARGET),
                    '--sevenup-profiles', str(SU / 'profiles'),
                    '--out', str(profiles), '--markers', 'sevenup',
                    '--audit', str(work / 'gen-audit.json')], check=True)
    su_mc1, su_final = sevenup_side(src, DONOR, work)
    our_mc1, our_final = our_side(src, DONOR, work, profiles)
    assert su_mc1 == our_mc1, 'MC1 (transplant) output differs'
    print('MC1 transplant output: BYTE-IDENTICAL (%d bytes)' % len(su_mc1))
    assert su_final == our_final, 'MC2 output differs'
    print('MC2 output: BYTE-IDENTICAL (%d bytes)' % len(su_final))
    print('PASS: parametrized audioport engine is equivalent to SevenUP on its inputs')
    return 0


if __name__ == '__main__':
    sys.exit(main())
