"""Shared helpers vendored from SevenUP (BSD-3-Clause, jmx/SevenUP project).

Source: src/iphone7_port/{core,kernel_chestnut,kernel_base,kernel_maggie,
kernel_d2333,kernel_transplant}.py — logic unchanged; only consolidated here.
"""

import base64
import bisect
import collections
import json
import re
import struct
from xml.sax.saxutils import escape

from kc import KC, plist


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def load_json(path):
    with open(path, 'rb') as f:
        return json.loads(f.read())


def commands(k, va=None):
    off = k.base if va is None else k.offset(va)
    q = off + 32
    for _ in range(struct.unpack_from('<I', k.data, off + 16)[0]):
        cmd, size = struct.unpack_from('<II', k.data, q)
        yield cmd, q, size
        q += size


def image_uuid(k, va):
    return next(k.data[q + 8:q + 24] for cmd, q, size in commands(k, va) if cmd == 27)


def relocations(k):
    d = plist(k.xml)['_PrelinkLinkKASLROffsets']
    words = list(struct.unpack('<' + 'I' * (len(d) // 4), d))
    require(words[0] == len(words) - 1, 'Invalid packed KASLR count')
    require(len(words[1:]) == len(set(words[1:])), 'Duplicate original KASLR slots')
    start = next(s['addr'] for s in k.segments if s['name'] == '__PRELINK_TEXT')
    return start, words[1:]


def xml_value(v):
    if isinstance(v, (bytes, bytearray)):
        return '<data>' + base64.b64encode(v).decode('ascii') + '</data>'
    if isinstance(v, dict):
        return '<dict>' + ''.join('<key>' + escape(k) + '</key>' + xml_value(x) for k, x in v.items()) + '</dict>'
    if isinstance(v, list):
        return '<array>' + ''.join(xml_value(x) for x in v) + '</array>'
    if isinstance(v, bool):
        return '<true/>' if v else '<false/>'
    if isinstance(v, int):
        return '<integer size="64">0x' + format(v, 'x') + '</integer>'
    if isinstance(v, str):
        return '<string>' + escape(v) + '</string>'
    raise TypeError(type(v))


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def adrp_page(word, pc):
    imm = ((word >> 29) & 3) | (((word >> 5) & 0x7ffff) << 2)
    return (pc & ~4095) + (signed(imm, 21) << 12)


def encode_adrp(word, pc, page):
    pages = (page - (pc & ~4095)) >> 12
    require(-(1 << 20) <= pages < (1 << 20), 'ADRP out of range')
    imm = pages & 0x1fffff
    return (word & ~0x60ffffe0) | ((imm & 3) << 29) | ((imm >> 2) << 5)


def branch(pc, target):
    delta = target - pc
    require(delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27), 'ARM64 branch is out of range.')
    return struct.pack('<I', 0x14000000 | ((delta >> 2) & 0x3ffffff))


def adr(pc, target, reg):
    delta = target - pc
    assert -(1 << 20) <= delta < (1 << 20)
    n = delta & 0x1fffff
    return (0x10000000 | ((n & 3) << 29) | ((n >> 2) << 5) | reg)


def bl(pc, target):
    return struct.pack('<I', struct.unpack('<I', branch(pc, target))[0] | 0x80000000)


def entry_range(xml, name):
    prefix = b'<dict><key>_PrelinkInfoDictionary</key><array>'
    require(xml.startswith(prefix), 'Unexpected XML')
    start = len(prefix)
    depth = 0
    begin = None
    for m in re.finditer(rb'<dict\b[^>]*>|</dict>', xml[start:]):
        tag = m[0]
        off = start + m.start()
        if tag.startswith(b'</'):
            depth -= 1
            if depth == 0 and name.encode() in xml[begin:start + m.end()]:
                return begin, start + m.end()
        elif not tag.endswith(b'/>'):
            if depth == 0:
                begin = off
            depth += 1
    raise RuntimeError('Missing prelink entry ' + name)


def fast_symbols(k):
    names, addresses = {}, collections.defaultdict(list)
    for cmd, q, _ in commands(k):
        if cmd != 2:
            continue
        off, count, strings, length = struct.unpack_from('<IIII', k.data, q + 8)
        st = k.data[k.base + strings:k.base + strings + length]
        for i in range(count):
            idx, typ, sect, desc, va = struct.unpack_from('<IBBHQ', k.data, k.base + off + i * 16)
            if not va or typ & 0xe0:
                continue
            name = st[idx:st.find(b'\0', idx)].decode()
            names[name] = va
            addresses[va].append(name)
    return names, addresses


def owner_ranges(k):
    return sorted((s['addr'], s['addr'] + s['size'], n, s['name'])
                  for n, e in k.kexts.items() if e.get('_PrelinkExecutableLoadAddr')
                  for s in k.ksegments(n) if s['size'])


def owner(ranges, va):
    i = bisect.bisect_right(ranges, (va, 1 << 65, '', '')) - 1
    if i >= 0 and ranges[i][0] <= va < ranges[i][1]:
        return ranges[i][2:]
    return ('XNU', None)


def plan_patches(d, plan):
    """kernel_abi.load_plan equivalent; plan is an already-loaded dict."""
    import hashlib
    patches = []
    for row in plan['instruction_fields']:
        address = int(row['address'], 16)
        raw = d.read(address, 4)
        require(hashlib.sha256(raw).hexdigest() == row['expected_sha256'],
                'ABI source word changed at %#x.' % address)
        old = struct.unpack('<I', raw)[0]
        if row['kind'] == 'scalar32':
            new = row['value']
        else:
            require(row['kind'] == 'instruction-immediate', 'Unknown ABI patch kind.')
            mask, shift = int(row['mask'], 16), row['shift']
            require(mask in {0xffff << 5, 4095 << 10, 127 << 15, 511 << 12},
                    'Unreviewed instruction immediate mask.')
            require((row['value'] << shift) & ~mask == 0, 'ABI immediate exceeds its field.')
            new = (old & ~mask) | (row['value'] << shift)
        patches.append({'va': address, 'old': old, 'new': new, 'reason': row['reason']})
    pairs = []
    for row in plan.get('pair_veneers', []):
        pairs.append({**row, 'old': struct.unpack('<I', d.read(row['va'], 4))[0]})
    require(len({p['va'] for p in patches}) == len(patches), 'Duplicate ABI instruction patch.')
    return patches, pairs
