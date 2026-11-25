#!/usr/bin/env python3
"""Shared helpers for Phase B ABI derivation: locate each class's own
vtable association block [own_mc][parent_mc][0][0][slots...] in __DATA_CONST
of its defining kext, read tables, and cross-kernel function equivalence.

Offline analysis tooling (not runtime); imports the vendored reader.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'patchsrc' / 'audioport'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from kc import KC
from util import require, adrp_page, fast_symbols, owner_ranges, owner
from gen_audio_profiles import Side, norm_words


def is_data_ptr(side, v):
    """v is a kernel VA pointing into a __DATA/__DATA_CONST segment of any
    kext or of XNU (metaclass objects live there)."""
    if v >> 36 != 0xfffffff:
        return False
    b, sg = side.owner(v)
    return sg in ('__DATA', '__DATA_CONST') or b == 'XNU'


def own_block(side, bid, mc, parent_mc):
    """Find the class's own association block: needle mc followed by exactly
    parent_mc then [0][0] and a nonzero slot run. Returns (header_addr,
    nslots) where header_addr is the [0][0] pair."""
    out = []
    for s in side.k.ksegments(bid):
        if s['name'] not in ('__DATA_CONST', '__DATA'):
            continue
        buf = side.k.read(s['addr'], s['size'])
        needle = struct.pack('<Q', mc)
        pos = 0
        while True:
            i = buf.find(needle, pos)
            if i < 0:
                break
            pos = i + 1
            if i + 24 > len(buf):
                continue
            nxt = struct.unpack_from('<Q', buf, i + 8)[0]
            z1, z2 = struct.unpack_from('<QQ', buf, i + 16)
            if nxt != parent_mc or z1 != 0 or z2 != 0:
                continue
            q = i + 32
            slots = 0
            while q + 8 <= len(buf) and struct.unpack_from('<Q', buf, q)[0]:
                slots += 1
                q += 8
            if slots:
                out.append((s['addr'] + i + 16, slots))
    require(len(out) == 1, 'own block not unique for %s mc=%s (%d)' % (bid, hex(mc), len(out)))
    return out[0]


def table(side, header, nslots):
    return list(struct.unpack('<%dQ' % nslots, side.k.read(header + 16, nslots * 8)))


def fn_owner(side, a):
    if a >> 36 != 0xfffffff:
        return ('literal', None)
    b, sg = side.owner(a)
    if b == 'XNU':
        return ('xnu', sg)
    return (b, sg)


def xnu_names(side, a):
    return set(side.byaddr.get(a, ()))


def window_sig(side, a, words=24):
    """Normalized-instruction signature of the function at `a` (first `words`
    instructions, stopping at ret)."""
    b, sg = side.owner(a)
    if b == 'XNU' or sg != '__TEXT_EXEC':
        return None
    buf = side.k.read(a, words * 4)
    ws = norm_words(buf)
    out = []
    for i, w in enumerate(ws):
        out.append(w)
        if w == 0xd65f03c0 or (w & 0xfffffc1f) == 0xd65f0000:
            break
    return tuple(out)


def anchors(tab15, tab16, s15, s16):
    """Provably-equal entry pairs between two tables. Returns list of
    (i15, i16, how). XNU symbol name equality is proof; identical literal is
    proof; unique window-signature pairs are strong evidence."""
    pairs = []
    # XNU-named anchors
    for i, a in enumerate(tab15):
        na = xnu_names(s15, a) if a >> 36 == 0xfffffff else set()
        for j, b in enumerate(tab16):
            if a >> 36 != 0xfffffff:
                if a == b:
                    pairs.append((i, j, 'literal'))
                continue
            nb = xnu_names(s16, b) if b >> 36 == 0xfffffff else set()
            if na and nb and na & nb:
                pairs.append((i, j, 'xnu:' + sorted(na & nb)[0]))
    # unique window signatures (functions inside kexts)
    sigs15 = {}
    for i, a in enumerate(tab15):
        w = window_sig(s15, a)
        if w:
            sigs15.setdefault(w, []).append(i)
    for j, b in enumerate(tab16):
        w = window_sig(s16, b)
        if w and w in sigs15 and len(sigs15[w]) == 1:
            pairs.append((sigs15[w][0], j, 'window'))
    return pairs


def align_table(tab15, tab16, s15, s16):
    """Align slot indices between the 15 and 16 tables of the same class.
    Returns (map, report): map i15 -> i16 or 'removed'; report lists evidence
    per region plus ambiguous ranges needing manual review."""
    pairs = anchors(tab15, tab16, s15, s16)
    # keep anchors strictly monotonic, prefer stronger evidence on conflicts
    rank = {'xnu': 3, 'literal': 2, 'window': 1}
    by_i = {}
    for i, j, how in pairs:
        key = how.split(':')[0]
        if i not in by_i or rank[key] > rank[by_i[i][1].split(':')[0]]:
            by_i[i] = (j, how)
    seq = sorted(by_i.items())
    kept = []
    last_j = -1
    for i, (j, how) in seq:
        if j > last_j:
            kept.append((i, j, how))
            last_j = j
    report = {'anchors': len(kept), 'dropped_anchors': len(seq) - len(kept),
              'regions': []}
    mapping = {}
    # fill gaps between consecutive anchors
    prev_i, prev_j = -1, -1
    for i, j, how in kept:
        di, dj = i - prev_i - 1, j - prev_j - 1
        if di or dj:
            report['regions'].append({'i': prev_i + 1, 'j': prev_j + 1,
                                      'len15': di, 'len16': dj,
                                      'proven': di == dj})
            if di == dj:
                for k in range(di):
                    mapping[prev_i + 1 + k] = prev_j + 1 + k
            else:
                for k in range(di):
                    mapping[prev_i + 1 + k] = 'unproven'
        mapping[i] = j
        prev_i, prev_j = i, j
    di, dj = len(tab15) - prev_i - 1, len(tab16) - prev_j - 1
    if di or dj:
        report['regions'].append({'i': prev_i + 1, 'j': prev_j + 1,
                                  'len15': di, 'len16': dj, 'proven': di == dj})
        for k in range(di):
            mapping[prev_i + 1 + k] = (prev_j + 1 + k) if di == dj else 'unproven'
    return mapping, report
