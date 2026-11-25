"""Apply the additional switch-only CS42L71 ABI accesses (MC2 semantics).

Vendored from SevenUP (BSD-3-Clause) src/iphone7_port/kernel_mc2.py.
Changes vs upstream: patch count, marker needle/replacement and extra string
renames come from the switch profile instead of hard-coded values; a rename
with required=false is skipped when its needle is absent.
"""

import re
import struct
from pathlib import Path

from kc import KC
from util import require, plan_patches


class Edits:
    def __init__(self, path):
        self.k = KC(path)
        self.output = bytearray(self.k.data)
        self.records = []

    def put(self, address, old, new, reason, owner=None):
        require(len(old) == len(new), 'An in-place base patch must preserve size.')
        offset = self.k.offset(address)
        require(bytes(self.output[offset:offset + len(old)]) == old, 'Unexpected original bytes at %#x.' % address)
        if owner:
            require(any(s['name'] == '__TEXT_EXEC' and s['addr'] <= address and
                        address + len(old) <= s['addr'] + s['size'] for s in self.k.ksegments(owner)),
                    'Patch is outside the executable allocation for %s.' % owner)
        self.output[offset:offset + len(new)] = new
        self.records.append({'address': hex(address), 'offset': offset, 'size': len(old), 'reason': reason})

    def string(self, old, new, *, owner=None):
        formats = re.compile(rb'%(?:[-+ #0]*)(?:\d+)?(?:\.\d+)?(?:ll|l|z|h)?[diuoxXpsc]')
        require(formats.findall(old) == formats.findall(new), 'A log format changes printf arguments.')
        require(len(new) <= len(old), 'A replacement string exceeds its allocation.')
        if owner:
            sections = [sec for s in self.k.ksegments(owner) for sec in s['sections'] if sec['name'] == '__cstring']
            require(len(sections) == 1, 'Ambiguous driver string section.')
            start = self.k.offset(sections[0]['addr'])
            data = self.k.read(sections[0]['addr'], sections[0]['size'])
        else:
            start, data = 0, self.k.data
        require(data.count(old + b'\0') == 1, 'Log format is not unique: %r' % old)
        offset = start + data.index(old + b'\0')
        segment = next(s for s in self.k.segments if self.k.base + s['offset'] <= offset < self.k.base + s['offset'] + s['size'])
        address = segment['addr'] + offset - self.k.base - segment['offset']
        self.put(address, old + b'\0', new + bytes(len(old) + 1 - len(new)), 'Preserve printf arguments while labeling the console')


def apply(source, donor, plan, work):
    """source: path to post-MC1 kernel; donor: path to donor kernel;
    plan: loaded switch-abi profile dict; work: output directory Path."""
    edits, d = Edits(source), KC(donor)
    params = plan['params']
    name = params['name']
    old = {s['name']: s for s in d.ksegments(name)}
    new = {s['name']: s for s in edits.k.ksegments(name)}
    def local(address):
        return next(new[n]['addr'] + address - s['addr'] for n, s in old.items()
                    if s['addr'] <= address < s['addr'] + s['size'])
    patches, pairs = plan_patches(d, plan)
    require(len(patches) == params['patch_count'] and not pairs, 'MC2 additional ABI plan changed.')
    for row in patches:
        edits.put(local(row['va']), struct.pack('<I', row['old']), struct.pack('<I', row['new']), row['reason'])
    for spec in params['markers']:
        needle = spec['needle'].encode('latin1')
        replacement = spec['replacement'].encode('latin1')
        count = edits.k.data.count(needle)
        if count == 0 and not spec.get('required', True):
            continue
        require(count == spec['count'], 'MC1 class markers changed.')
        start = 0
        for _ in range(count):
            offset = edits.k.data.index(needle, start)
            start = offset + len(needle)
            segment = next(s for s in edits.k.segments if edits.k.base + s['offset'] <= offset < edits.k.base + s['offset'] + s['size'])
            address = segment['addr'] + offset - edits.k.base - segment['offset']
            edits.put(address, needle, replacement, spec.get('reason', 'Retain fixed-size stage markers'))
    for spec in params.get('string_renames', []):
        old = spec['old'].encode('latin1')
        new = spec['new'].encode('latin1')
        if edits.k.data.count(old + b'\0') == 0 and not spec.get('required', True):
            continue
        edits.string(old, new)
    out = bytes(edits.output)
    (work / 'kernelcache.raw').write_bytes(out)
    return out, {'edits': edits.records, 'additional_instruction_count': len(patches)}
