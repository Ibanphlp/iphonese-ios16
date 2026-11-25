#!/usr/bin/env python3
"""Translate SevenUP's CS42L71 profiles (keyed on the iPhone 7 15.6 donor and
iPad 7 16.1 target kernels) into SE profiles keyed on arbitrary donor/target
kernels — for the N69 port: SE 15.8.8 (iphone8b) donor and iPad 5 16.1
(ipad6f) target.

Translation rules (each item asserts; failures are loud):
  * address inside a kext whose content is normalized-identical between the
    two kernels -> same kext / same segment / same offset
  * address inside XNU -> translate by LC_SYMTAB symbol name (must resolve to
    exactly one address on the other side)
  * otherwise -> unique normalized instruction-window match inside the same
    kext (used for the IOHIDFamily layout drift)

Usage:
  python3 tools/gen_audio_profiles.py \
      --ref-donor iphone9.thin --ref-target ipad7b.thin \
      --donor se15.raw --target ipad6f.raw \
      --sevenup-profiles /path/to/SevenUP-main/profiles \
      --out profiles [--markers sevenup|se]
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'patchsrc' / 'audioport'))

from kc import KC
from util import (require, relocations, adrp_page, signed, fast_symbols,
                  owner_ranges, owner)

AUDIT = []


def note(kind, what, old, new):
    AUDIT.append({'kind': kind, 'item': what, 'from': hex(old), 'to': hex(new)})


def norm_words(buf):
    out = []
    for i in range(0, len(buf) - 3, 4):
        w = struct.unpack_from('<I', buf, i)[0]
        n = w
        if (w & 0x9f000000) in (0x90000000, 0x10000000): n &= ~0x60ffffe0
        elif (w & 0x7c000000) == 0x14000000: n &= 0xfc000000
        elif (w & 0xff000010) == 0x54000000 or (w & 0x7e000000) == 0x34000000 or (w & 0x3b000000) == 0x18000000: n &= ~0xffffe0
        elif (w & 0x7e000000) == 0x36000000: n &= ~0x7ffe0
        elif (w & 0x3b000000) == 0x39000000: n &= ~(4095 << 10)
        elif (w & 0xffc00000) == 0x91000000: n &= ~(4095 << 10)
        out.append(n)
    return out


class Side:
    """One kernel with owner map, symbol table and per-kext normalized code."""

    def __init__(self, path):
        self.path = str(path)
        self.k = KC(path)
        self.sha = hashlib.sha256(self.k.data).hexdigest()
        self.ranges = owner_ranges(self.k)
        self.byname, self.byaddr = fast_symbols(self.k)
        self._norm = {}
        self._segs = {}

    def owner(self, a):
        return owner(self.ranges, a)

    def segs(self, bundle):
        if bundle not in self._segs:
            self._segs[bundle] = {s['name']: s for s in self.k.ksegments(bundle)}
        return self._segs[bundle]

    def seg_contains(self, bundle, segname, a):
        s = self.segs(bundle).get(segname)
        return s is not None and s['addr'] <= a < s['addr'] + s['size']

    def code(self, bundle):
        if bundle not in self._norm:
            s = self.segs(bundle)['__TEXT_EXEC']
            self._norm[bundle] = norm_words(self.k.read(s['addr'], s['size']))
        return self._norm[bundle]


def shape(k, bundle):
    return [(s['name'], s['size'], s['vmsize'],
             [(t['name'], t['addr'] - s['addr'], t['size']) for t in s['sections']])
            for s in k.ksegments(bundle)]


_ident_cache = {}


def identical(a_side, b_side, bundle):
    """Normalized-identical kext: same Mach-O shape and same normalized
    __TEXT_EXEC words (code) on both kernels."""
    key = (id(a_side), id(b_side), bundle)
    if key not in _ident_cache:
        ok = False
        if bundle in a_side.k.kexts and bundle in b_side.k.kexts:
            sa, sb = a_side.segs(bundle), b_side.segs(bundle)
            if sa.keys() == sb.keys() and shape(a_side.k, bundle) == shape(b_side.k, bundle):
                if '__TEXT_EXEC' in sa:
                    ok = a_side.code(bundle) == b_side.code(bundle)
                else:
                    ok = True
        _ident_cache[key] = ok
    return _ident_cache[key]


def _norm_qwords(side, s):
    """Normalize a segment's qwords: kernel VAs become symbolic
    (bundle,segment,offset), non-VA scalars stay literal."""
    out = []
    buf = side.k.read(s['addr'], s['size'])
    cur = _CUR[0]
    for i in range(0, len(buf) - 7, 8):
        v = struct.unpack_from('<Q', buf, i)[0]
        if v >> 36 == 0xfffffff:
            b, sg = side.owner(v)
            if b != 'XNU':
                vs = side.segs(b)[sg]
                v = (b, sg, v - vs['addr']) if b != cur else (sg, v - vs['addr'])
            else:
                names = side.byaddr.get(v)
                v = ('xnu', names[0]) if names else ('xnu',)
        out.append(v)
    return out


_CUR = [None]


def window_translate(a, sa, sb, bundle, segname, what):
    """Fallback: unique normalized window match for an address in a kext that
    is NOT normalized-identical between sa and sb. Instruction segments use
    normalized words; other segments use normalized qwords."""
    s, t = sa.segs(bundle)[segname], sb.segs(bundle)[segname]
    if segname == '__TEXT_EXEC':
        xa, xb = sa.code(bundle), sb.code(bundle)
        i = (a - s['addr']) // 4
        require(s['addr'] + i * 4 == a, 'Window-match address not word-aligned: ' + hex(a))
        step = 4
    else:
        _CUR[0] = bundle
        xa, xb = _norm_qwords(sa, s), _norm_qwords(sb, t)
        i = (a - s['addr']) // 8
        require(s['addr'] + i * 8 == a, 'Window-match address not qword-aligned: ' + hex(a))
        step = 8
    for length in (8, 12, 16, 24, 32, 48):
        pat = xa[i:i + length]
        require(len(pat) == length, 'Window-match out of bounds: ' + hex(a))
        hits = [j for j in range(len(xb) - length + 1) if xb[j:j + length] == pat]
        if len(hits) == 1:
            return t['addr'] + hits[0] * step, 'window%d' % length
        if not hits:
            break
    # Content window failed (e.g. zeroed __DATA metaclass storage): locate
    # ADRP+ADD materializations of `a` in the same kext's code, window-match
    # those instructions, and decode the address they compute on the other side.
    exa = sa.segs(bundle).get('__TEXT_EXEC')
    require(exa, 'No __TEXT_EXEC for materialization search: ' + hex(a))
    xa_code, xb_code = sa.code(bundle), sb.code(bundle)
    raw = sa.k.read(exa['addr'], exa['size'])
    cand = set()
    for off in range(0, len(raw) - 7, 4):
        w, v = struct.unpack_from('<II', raw, off)
        if w & 0x9f000000 != 0x90000000:
            continue
        reg = w & 31
        if v & 0xffc003ff != 0x91000000 | (reg << 5) | reg:
            continue
        if adrp_page(w, exa['addr'] + off) + ((v >> 10) & 4095) != a:
            continue
        idx = off // 4
        hit = None
        for length in (8, 16, 32, 64):
            if idx - 4 < 0:
                break
            pat = xa_code[idx - 4:idx - 4 + length]
            if len(pat) != length:
                continue
            hits = [j for j in range(len(xb_code) - length + 1)
                    if xb_code[j:j + length] == pat]
            if len(hits) == 1:
                hit = hits[0] + 4
                break
        if hit is None:
            continue
        npc = sb.segs(bundle)['__TEXT_EXEC']['addr'] + hit * 4
        w2, v2 = struct.unpack_from('<II', sb.k.read(npc, 8))
        if w2 & 0x9f000000 != 0x90000000:
            continue
        reg2 = w2 & 31
        if v2 & 0xffc003ff != 0x91000000 | (reg2 << 5) | reg2:
            continue
        cand.add(adrp_page(w2, npc) + ((v2 >> 10) & 4095))
    require(len(cand) == 1,
            'Materialization search not unique for %s (%d candidates)' % (hex(a), len(cand)))
    return next(iter(cand)), 'materialize'


def xlate(a, sa, sb, what, audit_kind):
    """Translate address `a` from kernel sa to kernel sb."""
    bundle, segname = sa.owner(a)
    if bundle != 'XNU':
        if identical(sa, sb, bundle):
            s, t = sa.segs(bundle)[segname], sb.segs(bundle)[segname]
            require(a - s['addr'] < t['size'], 'Offset outside %s on target: %s' % (bundle, what))
            return t['addr'] + a - s['addr'], 'identical:' + bundle.split('.')[-1]
        new, method = window_translate(a, sa, sb, bundle, segname, what)
        return new, method + ':' + bundle.split('.')[-1]
    names = sa.byaddr.get(a, [])
    require(names, 'XNU address without symbol: ' + hex(a))
    vals = {sb.byname[n] for n in names if n in sb.byname}
    require(len(vals) == 1, 'XNU symbol does not resolve uniquely %s (%s)' % (hex(a), names))
    return next(iter(vals)), 'symbol:' + names[0]


def tx(a, sa, sb, what):
    new, method = xlate(a, sa, sb, what, None)
    note(method, what, a, new)
    return new


def hx(v):
    return hex(v) if isinstance(v, int) else v


def _stubs(side, exec_seg):
    """Map __stubs-style ADRP/LDR/BR trampolines to their GOT target."""
    buf = side.k.read(exec_seg['addr'], exec_seg['size'])
    m = {}
    for off in range(0, len(buf) - 11, 4):
        a, b, c = struct.unpack_from('<III', buf, off)
        if (a & 0x9f00001f) == 0x90000010 and (b & 0xffc003ff) == 0xf9400210 and c == 0xd61f0200:
            got = adrp_page(a, exec_seg['addr'] + off) + ((b >> 10) & 4095) * 8
            m[exec_seg['addr'] + off] = struct.unpack('<Q', side.k.read(got, 8))[0]
    return m


def class_registry(side, wanted, bundles=None):
    """Locate OSMetaClass registrations for `wanted` class names.
    Returns {name: (bundle, metaclass, super_metaclass, instance_size, call_pc)}."""
    found = {}
    cands = [b for b in side.k.kexts
             if (bundles is None or any(x in b for x in bundles))]
    for bid in cands:
        try:
            segs = side.segs(bid)
        except KeyError:
            continue
        ex = segs.get('__TEXT_EXEC')
        if not ex or not ex['size']:
            continue
        stubs = _stubs(side, ex)
        buf = side.k.read(ex['addr'], ex['size'])
        regs = {}
        for i in range(0, len(buf) - 3, 4):
            w = struct.unpack_from('<I', buf, i)[0]
            pc = ex['addr'] + i
            if (w & 0x9f000000) == 0x90000000:
                regs[w & 31] = adrp_page(w, pc)
            elif (w & 0xffc00000) == 0x91000000 and isinstance(regs.get(w >> 5 & 31), int):
                regs[w & 31] = regs[w >> 5 & 31] + ((w >> 10) & 4095)
            elif (w & 0xff800000) == 0x52800000:
                regs[w & 31] = (w >> 5) & 0xffff
            elif (w & 0xffc00000) == 0xf9400000 and isinstance(regs.get(w >> 5 & 31), int):
                try:
                    regs[w & 31] = struct.unpack('<Q', side.k.read(regs[w >> 5 & 31] + ((w >> 10) & 4095) * 8, 8))[0]
                except ValueError:
                    regs.pop(w & 31, None)
            elif (w & 0xffc00000) == 0xaa000000 and (w >> 16 & 31) in regs:
                regs[w & 31] = regs[w >> 16 & 31]
            elif (w & 0xfc000000) == 0x94000000:
                imm = w & 0x3ffffff
                if imm & (1 << 25): imm -= 1 << 26
                t = stubs.get(pc + imm * 4, pc + imm * 4)
                if any(n.startswith('__ZN11OSMetaClassC2EPKcPKS_j')
                       for n in side.byaddr.get(t, [])):
                    nm, sup, sz, mc = regs.get(1), regs.get(2), regs.get(3), regs.get(0)
                    if all(isinstance(x, int) for x in (nm, sup, sz, mc)):
                        name = side.k.read(nm, 64).split(b'\0')[0].decode()
                        if name in wanted:
                            found[name] = (bid, mc, sup, sz, pc)
                regs = {r: v for r, v in regs.items() if r >= 19}
            elif (w & 0x9f000000) != 0x90000000:
                pass
        if wanted <= set(found):
            break
    return found


def find_vtable(side, bundle, metaclass, expected=None):
    """Locate a class vtable given its metaclass address. Layout in
    __DATA_CONST: [metaclass][ancestor metaclass ptrs][0][0][slots...];
    the profile 'vtable' field is the two-zero Itanium header address
    (+16 == first slot)."""
    out = []
    for s in side.k.ksegments(bundle):
        if s['name'] not in ('__DATA_CONST', '__DATA'):
            continue
        buf = side.k.read(s['addr'], s['size'])
        needle = struct.pack('<Q', metaclass)
        pos = 0
        while True:
            i = buf.find(needle, pos)
            if i < 0:
                break
            pos = i + 1
            # the metaclass may open its own association chain, or appear
            # mid-chain when a subclass shares this vtable (seen on ipad7b:
            # V11's table is the shared [AUDIO][V11][MikeyBus] block). Walk
            # forward over the metaclass chain to the 0,0 header + slots.
            at_start = True
            if i >= 8:
                pv = struct.unpack_from('<Q', buf, i - 8)[0]
                pb, psg = side.owner(pv)
                at_start = pb == 'XNU' or psg != '__DATA'
            p = i + 8
            while p + 8 <= len(buf):
                v = struct.unpack_from('<Q', buf, p)[0]
                b, sg = side.owner(v)
                if b == 'XNU' or sg != '__DATA':
                    break
                p += 8
            if p + 16 > len(buf):
                continue
            z1, z2 = struct.unpack_from('<QQ', buf, p)
            if z1 == 0 and z2 == 0:
                slots = 0
                q = p + 16
                while q + 8 <= len(buf) and struct.unpack_from('<Q', buf, q)[0]:
                    slots += 1; q += 8
                if slots:
                    out.append((s['addr'] + p, slots, at_start))
    if len(out) != 1 and expected is not None:
        out = [c for c in out if c[1] == expected]
    if len(out) != 1:
        started = [c for c in out if c[2]]
        if started:
            out = started
    require(len(out) == 1, 'Vtable association not unique (%d) in %s' % (len(out), bundle))
    vt, slots, _ = out[0]
    return vt, slots


def translate_class16(entry, st, nt):
    """classes16 entry: native16-side class record. If its bundle exists on the
    new target and is normalized-identical, translate each address; otherwise
    the class moved bundle (iPad7 CS46L10 -> iPad5 CS42L81): locate it by name."""
    if entry['bundle'] in nt.k.kexts and identical(st, nt, entry['bundle']):
        return translate_class(entry, st, nt)
    reg = class_registry(nt, {entry['name']}, bundles=('Audio', 'Mikey', 'HID', 'CS42'))
    if entry['name'] not in reg:
        reg = class_registry(nt, {entry['name']}, bundles=None)
    require(entry['name'] in reg, 'Native class not found on target: ' + entry['name'])
    bid, mc, sup, sz, pc = reg[entry['name']]
    require(sz == entry['instance_size'],
            'Native instance size differs for ' + entry['name'])
    note('class-by-name', 'classes16.' + entry['name'], 0, mc)
    res = {'name': entry['name'], 'bundle': bid, 'metaclass': hex(mc),
           'super_metaclass': hex(sup), 'instance_size': sz, 'ctor_call': hex(pc)}
    if 'vtable' in entry:
        vt, slots = find_vtable(nt, bid, mc, entry['virtual_slots'])
        require(slots == entry['virtual_slots'],
                'Native vtable length differs for %s (%d vs %d)' % (entry['name'], slots, entry['virtual_slots']))
        res['vtable'] = hex(vt)
        res['virtual_slots'] = slots
    return res


def translate_class(entry, sa, sb):
    out = dict(entry)
    for f in ('metaclass', 'super_metaclass', 'ctor_call', 'vtable'):
        if f in entry:
            out[f] = hex(tx(int(entry[f], 16), sa, sb, '%s.%s' % (entry['name'], f)))
    return out


def fingerprint(nt, addr, span=None):
    """Record a byte fingerprint for a target-side address the engine relies
    on, so the runtime can verify the post-kextport kernel still matches the
    profiled target at that spot. Code -> 16 bytes; pointer slots / object
    starts -> 8 bytes; vtables -> [0][0] header + slot span."""
    bundle, segname = nt.owner(addr)
    try:
        nt.k.offset(addr)
    except ValueError:
        # Unbacked virtual address (bss/zerofill tail) - nothing to check.
        AUDIT.append({'kind': 'fingerprint-skip', 'item': 'unbacked',
                      'from': hex(addr), 'to': hex(addr)})
        return None
    if span is not None:
        n = span
    elif segname in ('__TEXT_EXEC', '__TEXT'):
        n = 16
    else:
        n = 8
    return {'bytes': n, 'sha256': hashlib.sha256(nt.k.read(addr, n)).hexdigest()}


def collect_fingerprints(out, nt):
    fps = {}

    def add(a, span=None, what=''):
        fp = fingerprint(nt, a, span)
        if fp is not None:
            fps[hex(a)] = fp

    for a in out['bindings'].values():
        add(int(a, 16))
    for name, e in out['classes16'].items():
        for f in ('metaclass', 'super_metaclass', 'ctor_call'):
            add(int(e[f], 16))
        if 'vtable' in e:
            add(int(e['vtable'], 16), 16 + e['virtual_slots'] * 8)
    P = out['params']
    add(int(P['decoder_fallback']['target'], 16))
    for a in P['extra_private_bindings'].values():
        add(int(a, 16))
    return fps


def build_profiles(ref_donor, ref_target, donor, target, sevenup_dir, marker_set):
    sd, st = Side(ref_donor), Side(ref_target)     # SevenUP-keyed kernels
    nd, nt = Side(donor), Side(target)           # profiled kernels

    abi = json.loads((sevenup_dir / 'microphone-abi.json').read_text())
    switch = json.loads((sevenup_dir / 'microphone-switch-abi.json').read_text())

    NAME = 'com.apple.driver.AppleCS42L71Audio'
    require(identical(sd, nd, NAME), 'CS42L71 donor kext is not normalized-identical')

    out = {'schema': 1,
           'scope': 'CS42L71 (N69) class metadata and ABI immediate updates; translated from SevenUP microphone-abi.json (BSD-3-Clause)',
           'credit': 'SevenUP project, BSD-3-Clause',
           'source_kernels': {'donor': str(donor), 'donor_sha256': nd.sha,
                              'target': str(target), 'target_sha256': nt.sha,
                              'reference_donor_sha256': sd.sha, 'reference_target_sha256': st.sha},
           'classes15': {}, 'classes16': {}, 'instruction_fields': [],
           'pair_veneers': abi['pair_veneers'],
           'unresolved_dispatches': abi['unresolved_dispatches'],
           'bindings': {}}

    for name, e in abi['classes15'].items():
        out['classes15'][name] = translate_class(e, sd, nd)
    for name, e in abi['classes16'].items():
        out['classes16'][name] = translate_class16(e, st, nt)

    for row in abi['instruction_fields']:
        a = int(row['address'], 16)
        na = tx(a, sd, nd, 'instruction_field')
        got = hashlib.sha256(nd.k.read(na, 4)).hexdigest()
        require(got == row['expected_sha256'],
                'Translated instruction word differs at ' + hex(na))
        out['instruction_fields'].append({**row, 'address': hex(na)})

    for a, b in abi['bindings'].items():
        ia, ib = int(a, 16), int(b, 16)
        na, nb = tx(ia, sd, nd, 'binding.key'), tx(ib, st, nt, 'binding.value')
        out['bindings'][hex(na)] = hex(nb)

    P = {  # hard-coded SevenUP constants -> profile data (translated)
        'audio_vtable': hex(tx(0xfffffff006fce390, sd, nd, 'audio_vtable')),
        'audio_virtual_slots': 252,
        'extra_private_bindings': {
            hex(tx(0xfffffff005bb4890, sd, nd, 'extra_private_binding')):
            hex(tx(0xfffffff005ae9b08, st, nt, 'extra_private_binding.target'))},
        'extra_private_verify': {
            hex(tx(0xfffffff005bb4890, sd, nd, 'extra_private_binding')): 12},
        'legacy_decoder': {'va': hex(tx(0xfffffff005f78f10, sd, nd, 'legacy_decoder')),
                           'size': 1592},
        'decoder_fallback': {'donor': hex(tx(0xfffffff005acf468, sd, nd, 'decoder_fallback')),
                             'target': hex(tx(0xfffffff0059f8468, st, nt, 'decoder_fallback.target'))},
        'materialization_pcs': [hex(tx(a, sd, nd, 'materialization_pc')) for a in [
            0xfffffff006bc23c8, 0xfffffff006bc24a8, 0xfffffff006bcbb08,
            0xfffffff006bcbb28, 0xfffffff006bcbbf8, 0xfffffff006bcbc3c]],
        'mikey_parent_class': 'AppleCSHTDCodecMikey',
        'trace': {'start_fn': hex(tx(0xfffffff006bc1214, sd, nd, 'trace.start')),
                  'handle_fn': hex(tx(0xfffffff006bc1284, sd, nd, 'trace.handleStart')),
                  'start_slot': 86, 'handle_slot_index': 339, 'wrapper_gap': 0x200,
                  'label': 'MC1 CS42L71' if marker_set == 'sevenup' else 'SE-AUDIO CS42L71'},
        'layout': {'data_const_extra': 0x6000, 'moved_header_delta': 16,
                   'moved_vtable_delta': 32, 'parser_off': 0x28000,
                   'trace_off': 0x29000, 'marker_off': 0x30000, 'sig_pool_off': 0x4000},
        'expanded_segments': {'__DATA_CONST': hex(0x6000 + 32 + 285 * 8)},
        'markers': {'source': None, 'target': None,
                    'init_text': '\x1b[33m%s classes ready; ABI adapted\x1b[0m\n\0' %
                                 ('MC1 CS42L71' if marker_set == 'sevenup' else 'SE-AUDIO CS42L71')},
        'non_instruction_words': {},
    }
    if marker_set == 'sevenup':
        P['markers']['source'] = '\x1b[32mBT1:%.128s\x1b[0m\n\0'
        P['markers']['target'] = '\x1b[33mMC1:%.128s\x1b[0m\n\0'
    # Libm literal audit exception (target kernel address).
    lit = tx(0xfffffff0059f4bf8, st, nt, 'non_instruction_word')
    require(nt.k.read(lit, 8).hex() == '887d16946d80b93f', 'Libm literal changed')
    P['non_instruction_words'][hex(lit)] = {'bytes': '887d16946d80b93f',
                                            'reason': 'Reviewed Libm F64 literal'}
    out['params'] = P
    P['target_fingerprints'] = collect_fingerprints(out, nt)

    sout = {'schema': 1, 'credit': 'SevenUP project, BSD-3-Clause',
            'source_kernels': out['source_kernels'],
            'instruction_fields': [], 'pair_veneers': switch['pair_veneers'],
            'params': {'name': NAME, 'patch_count': len(switch['instruction_fields']),
                       'markers': [], 'string_renames': []}}
    for row in switch['instruction_fields']:
        a = int(row['address'], 16)
        na = tx(a, sd, nd, 'switch_field')
        got = hashlib.sha256(nd.k.read(na, 4)).hexdigest()
        require(got == row['expected_sha256'],
                'Translated switch word differs at ' + hex(na))
        sout['instruction_fields'].append({**row, 'address': hex(na)})
    if marker_set == 'sevenup':
        sout['params']['markers'].append(
            {'needle': 'MC1 CS42L71', 'replacement': 'MC2 CS42L71', 'count': 7,
             'required': True, 'reason': 'Retain fixed-size MC2 markers'})
        sout['params']['string_renames'].append(
            {'old': '\x1b[33mMCD:%.128s\x1b[0m\n', 'new': '\x1b[33mM2D:%.128s\x1b[0m\n',
             'required': False})
    else:
        sout['params']['markers'].append(
            {'needle': 'SE-AUDIO CS42L71', 'replacement': 'SE-AUDIO CS42L71', 'count': 7,
             'required': True, 'reason': 'Verify SE-AUDIO CS42L71 markers present'})
    return out, sout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ref-donor', required=True)
    ap.add_argument('--ref-target', required=True)
    ap.add_argument('--donor', required=True)
    ap.add_argument('--target', required=True)
    ap.add_argument('--sevenup-profiles', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--markers', choices=['sevenup', 'se'], default='se')
    ap.add_argument('--audit', default=None)
    args = ap.parse_args()
    abi, switch = build_profiles(args.ref_donor, args.ref_target, args.donor,
                                 args.target, Path(args.sevenup_profiles), args.markers)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    # classes16 order is semantic: it determines the signature-pool layout.
    (out / 'se-cs42l71-abi.json').write_text(json.dumps(abi, indent=1) + '\n')
    (out / 'se-cs42l71-switch-abi.json').write_text(json.dumps(switch, indent=1) + '\n')
    audit = args.audit or str(out / 'gen-audit.json')
    Path(audit).write_text(json.dumps(AUDIT, indent=1, sort_keys=True) + '\n')
    import collections
    methods = collections.Counter(x['kind'].split(':')[0] for x in AUDIT)
    print('wrote', out, '-', len(AUDIT), 'translations:', dict(methods))


if __name__ == '__main__':
    main()
