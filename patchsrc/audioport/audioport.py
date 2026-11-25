#!/usr/bin/env python3
"""audioport — reclaim AppleANXDPTX for AppleCS42L71Audio on the iPhone SE (N69)
iOS 16 kernel, applying the SevenUP CS42L71 transplant semantics (MC1 + MC2)
parametrized by the translated SE profiles.

Usage:
    python3 patchsrc/audioport/audioport.py <dst_kernel_after_kextport> \
        <se15_kernel> <output> [--profiles DIR]

stdlib-only; runs with macOS /usr/bin/python3 (3.9+). Engine code is vendored
from the SevenUP project (BSD-3-Clause), credit: SevenUP authors.
"""

import hashlib
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from kc import KC
from util import require, load_json
import transplant
import microphone
import amp
import mc2


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def macho_sha256(path):
    import struct
    with open(path, 'rb') as f:
        data = f.read()
    ncmds = struct.unpack_from('<I', data, 16)[0]
    off, end = 32, 0
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, off)
        if cmd == 0x19:
            fileoff, filesize = struct.unpack_from('<QQ', data, off + 40)
            end = max(end, fileoff + filesize)
        off += size
    return hashlib.sha256(data[:end]).hexdigest()


def main(argv):
    if len(argv) < 4:
        sys.stderr.write(__doc__)
        return 2
    dst, donor, output = Path(argv[1]), Path(argv[2]), Path(argv[3])
    profiles = Path(argv[argv.index('--profiles') + 1]) if '--profiles' in argv \
        else HERE.parent.parent / 'profiles'
    abi = load_json(profiles / 'se-cs42l71-abi.json')
    switch = load_json(profiles / 'se-cs42l71-switch-abi.json')
    only = argv[argv.index('--only') + 1] if '--only' in argv else None
    amp_abi = None if only == 'cs42l71' else load_json(profiles / 'se-cs35l19-abi.json')
    expected = abi['source_kernels']
    # img4 (macOS build) drops data trailing the Mach-O that pyimg4 keeps, so
    # also accept a hash of the Mach-O extent only.
    require(sha256(donor) == expected['donor_sha256'] or
            macho_sha256(donor) == expected['donor_macho_sha256'],
            'Donor kernel does not match the profiled SE 15.8.8 kernel')
    if sha256(dst) != expected['target_sha256']:
        # The profiled target is the pre-kextport ipad6f kernel; the pipeline
        # feeds us the kextport output, which legitimately differs.
        sys.stderr.write('note: input is not the profiled target kernel '
                         '(expected after kextport/pmuhax stages)\n')
    if output.exists():
        sys.stderr.write('refusing to overwrite %s\n' % output)
        return 2
    d_kc, k_kc = KC(donor), KC(dst)
    # Target-side verification: every target address the engine relies on must
    # still hold the bytes recorded when the profile was generated (VAs of
    # existing kexts are unchanged by pmuhax/kextport, so raw-byte equality is
    # the right check; any drift here means the input is not the kernel we
    # profiled).
    fps = abi['params'].get('target_fingerprints', {})
    for addr, fp in fps.items():
        got = hashlib.sha256(k_kc.read(int(addr, 16), fp['bytes'])).hexdigest()
        require(got == fp['sha256'],
                'Target fingerprint mismatch at %s (input kernel does not '
                'match the profiled target at this address)' % addr)
    sys.stderr.write('target fingerprints verified: %d\n' % len(fps))
    private, review, slots, patches, extra, skip, finish = microphone.prepare(d_kc, k_kc, abi)
    with tempfile.TemporaryDirectory(prefix='audioport-') as td:
        stage1 = Path(td) / 'mc1'
        stage1.mkdir()
        params = abi['params']
        data, report = transplant.apply(
            dst, donor, stage1,
            OLD=microphone.OLD, NAME=microphone.NAME,
            marker_source=(params['markers']['source'].encode('latin1')
                           if params['markers'].get('source') else None),
            marker_target=(params['markers']['target'].encode('latin1')
                           if params['markers'].get('target') else None),
            private_bindings=private, private_review=review,
            slot_overrides=slots, donor_word_patches=patches,
            finalize=finish, extra_donor_slots=extra, skip_donor_slots=skip,
            expanded_segments={n: int(v, 16) for n, v in params['expanded_segments'].items()},
            non_instruction_words={int(a, 16): v for a, v in
                                   params.get('non_instruction_words', {}).items()})
        stage2 = Path(td) / 'mc2'
        stage2.mkdir()
        if amp_abi is not None:
            ap, areview, aslots, apatches, aextra, askip, afinalize = amp.prepare(d_kc, k_kc, amp_abi)
            stage3 = Path(td) / 'amp'
            stage3.mkdir()
            data, amp_report = transplant.apply(
                stage1 / 'kernelcache.raw', donor, stage3,
                OLD=amp.OLD, NAME=amp.NAME,
                marker_source=None, marker_target=None,
                private_bindings=ap, private_review=areview,
                slot_overrides=aslots, donor_word_patches=apatches,
                finalize=afinalize, extra_donor_slots=aextra, skip_donor_slots=askip,
                expanded_segments={}, non_instruction_words={})
            mc2_in = stage3 / 'kernelcache.raw'
        else:
            amp_report = None
            mc2_in = stage1 / 'kernelcache.raw'
        final, mc2_report = mc2.apply(mc2_in, donor, switch, stage2)
    output.write_bytes(final)
    summary = {'transplant': {k: v for k, v in report.items()
                              if k not in ('allowed_raw_ranges', 'ABI_adaptation',
                                           'private_dependency_review')},
               'amp': None if amp_report is None else
                      {k: v for k, v in amp_report.items()
                       if k not in ('allowed_raw_ranges', 'ABI_adaptation',
                                    'private_dependency_review')},
               'mc2': {'additional_instruction_count': mc2_report['additional_instruction_count'],
                       'edit_count': len(mc2_report['edits'])},
               'output': str(output), 'output_sha256': hashlib.sha256(final).hexdigest()}
    print(json.dumps(summary, indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
