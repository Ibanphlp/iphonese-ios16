"""CS35L19 amp transplant: rebuild native-parent vtable and typed metadata.

Companion to microphone.py for the second SE audio driver. Single own class
(AppleCS35L19Amp), no Mikey table, no legacy decoder. The derived slot map
differs from SevenUP's slot() for AppleEmbeddedAudio descendants: iOS 16 did
not remove slots 331/332 but moved them to 180/181 (proven by signature
identity; see profiles/se-cs35l19-review.json).
"""

import struct
from kc import KC
from util import (require, relocations, adrp_page, signed, encode_adrp,
                  branch, adr, bl, fast_symbols, plan_patches)

MAIN = 'AppleCS35L19Amp'
NAME = 'com.apple.driver.AppleCS35L19Amp'
OLD = 'com.apple.driver.AppleCS42L81Audio'
PARTS = ('__TEXT', '__TEXT_EXEC', '__DATA', '__DATA_CONST')


def slot(typ, i):
    if i == 331: return 180
    if i == 332: return 181
    return i if i < 180 else i + 3 if i < 331 else i + 1


def prepare(d, k, plan_data):
    params = plan_data['params']
    dc, nc = plan_data['classes15'], plan_data['classes16']
    own = {n: c for n, c in dc.items() if c['bundle'] == NAME}
    require(list(own) == [MAIN], 'unexpected own class set: %s' % list(own))
    bymeta = {int(c['metaclass'], 16): n for n, c in dc.items()}
    ds = {s['name']: s for s in d.ksegments(NAME)}; os = {s['name']: s for s in k.ksegments(OLD)}
    dest = {}
    for n in PARTS:
        pad = (ds[n]['addr'] - os[n]['addr']) % 4096
        dest[n] = os[n]['addr'] + (pad if ds[n]['size'] + pad <= os[n]['size'] else 0)
    dest['__TEXT'] = os['__TEXT']['addr']
    assert all(dest[n] + ds[n]['size'] <= os[n]['addr'] + os[n]['size'] for n in PARTS)
    def local(a):
        for n in PARTS:
            if ds[n]['addr'] <= a < ds[n]['addr'] + ds[n]['size']: return dest[n] + a - ds[n]['addr']
        raise ValueError(hex(a))
    def vt(c): return int(c['vtable'], 16) + 16
    def vals(c, k): return list(struct.unpack('<' + 'Q' * c['virtual_slots'], k.read(vt(c), c['virtual_slots'] * 8)))
    # Trace + marker live in the reclaimed __TEXT_EXEC slack after the donor
    # code (dest is 4096-aligned within it); marker is last, trace before it.
    trace = dest['__TEXT_EXEC'] + ds['__TEXT_EXEC']['size'] + (-ds['__TEXT_EXEC']['size'] % 4096) + 0x800
    marker = trace + 0x200
    assert marker + 256 <= os['__TEXT_EXEC']['addr'] + os['__TEXT_EXEC']['size']
    raw = plan_data
    private = {int(a, 16): int(b, 16) for a, b in raw['bindings'].items()}
    for a, b in params['extra_private_bindings'].items():
        private[int(a, 16)] = int(b, 16)
    nn, _ = fast_symbols(k); on, oa = fast_symbols(d)
    # Rebuild the single own-class vtable from the native16 parent.
    tables = {}; table_reports = {}
    pending = dict(own)
    while pending:
        progressed = False
        for name, c in list(pending.items()):
            parent = bymeta[int(c['super_metaclass'], 16)]
            if parent in pending: continue
            old_table = vals(c, d); old_parent = vals(dc[parent], d)
            if parent in tables: table = list(tables[parent])
            else: table = [{'kind': 'native', 'target': x} for x in vals(nc[parent], k)]
            overrides = []
            for i, x in enumerate(old_table):
                if i < len(old_parent) and x == old_parent[i]: continue
                j = slot(name, i)
                if ds['__TEXT_EXEC']['addr'] <= x < ds['__TEXT_EXEC']['addr'] + ds['__TEXT_EXEC']['size']:
                    value = {'kind': 'donor-local', 'target': x}
                else:
                    if x in private:
                        value = {'kind': 'native', 'target': private[x]}
                    else:
                        targets = {nn[n] for n in oa.get(x, []) if n in nn}
                        assert len(targets) == 1, (name, i, hex(x))
                        value = {'kind': 'native', 'target': targets.pop()}
                if j < len(table): table[j] = value
                else: assert j == len(table); table.append(value)
                overrides.append({'old_slot': i, 'new_slot': j, 'function': hex(x)})
            tables[name] = table
            table_reports[name] = {'parent': parent, 'old_slots': len(old_table), 'new_slots': len(table), 'overrides': overrides}
            del pending[name]; progressed = True
        assert progressed
    ts = params['trace']
    tables[MAIN][slot(MAIN, ts['start_slot'])] = {'kind': 'native', 'target': trace}
    special = {}; extra = []; skip = set()
    base, fix = relocations(d); fixset = {base + x for x in fix}
    for n, table in tables.items():
        a = vt(dc[n])
        for i, v in enumerate(table):
            p = a + i * 8; special[p] = v
            if p not in fixset: assert d.read(p, 8) == bytes(8); extra.append(p - base)
    # Typed allocation signature rebuild with native16 parent prefix.
    def signatures(obj, bundles):
        found = {}
        for bundle in bundles:
            for s in obj.ksegments(bundle):
                for t in s['sections']:
                    if t['name'] != '__kalloc_type': continue
                    for a in range(t['addr'], t['addr'] + t['size'], 64):
                        namep = struct.unpack('<Q', obj.read(a + 16, 8))[0]
                        name = obj.read(namep, 128).split(b'\0')[0].decode().removeprefix('site.')
                        sigp = struct.unpack('<Q', obj.read(a + 32, 8))[0]
                        sig = obj.read(sigp, 2048).split(b'\0')[0]
                        found[name] = (a, sig)
        return found
    parents = {bymeta[int(c['super_metaclass'], 16)] for c in own.values()} - own.keys()
    bundles = {dc[n]['bundle'] for n in parents}
    old_sig = signatures(d, bundles | {NAME}); native_sig = signatures(k, bundles)
    sig_pool_off = ds['__TEXT']['size']
    rebuilt = {}; pending = dict(own); signature_pool = bytearray(); signature_records = []
    while pending:
        progressed = False
        for n, c in list(pending.items()):
            parent = bymeta[int(c['super_metaclass'], 16)]
            if parent in pending: continue
            a, sig = old_sig[n]; parent_old = old_sig[parent][1]
            assert sig.startswith(parent_old), (n, parent)
            parent_new = rebuilt[parent] if parent in rebuilt else native_sig[parent][1]
            sig = parent_new + sig[len(parent_old):]
            expected = (c['instance_size'] + 8 + 7) // 8
            assert len(sig) == expected, (n, len(sig), expected)
            new_address = dest['__TEXT'] + sig_pool_off + len(signature_pool)
            special[a + 32] = {'kind': 'native', 'target': new_address}
            signature_records.append({'class': n, 'descriptor': hex(local(a)), 'signature': hex(new_address), 'words': len(sig)})
            signature_pool.extend(sig + b'\0'); rebuilt[n] = sig; del pending[n]; progressed = True
        assert progressed
    assert sig_pool_off + len(signature_pool) < os['__TEXT']['size']
    patches, pairs = plan_patches(d, plan_data)
    assert not pairs
    init_text = params['markers']['init_text'].encode('latin1')
    def finalize(k, d, out, local, dst, tail, write):
        records = []; newfix = []
        def edit(a, b, why): write(a, b); records.append({'address': hex(a), 'size': len(b), 'reason': why})
        edit(dest['__TEXT'] + sig_pool_off, signature_pool, 'Typed allocation word signatures with native16 parent layouts')
        def trace_wrapper(a, real, name):
            code = struct.pack('<III', 0xa9ba7bfd, 0x910003fd, 0xa90107e0)
            code += struct.pack('<III', 0xa9020fe2, 0xa90317e4, 0xa9041fe6)
            begin = a + 0x100; okay = a + 0x140; fail = a + 0x180
            code += struct.pack('<I', adr(a + len(code), begin, 0)); code += bl(a + len(code), nn['_IOLog'])
            code += struct.pack('<IIII', 0xa94107e0, 0xa9420fe2, 0xa94317e4, 0xa9441fe6)
            code += bl(a + len(code), local(real)); code += struct.pack('<I', 0xf9002be0)
            code += struct.pack('<I', 0x34000060)
            code += struct.pack('<I', adr(a + len(code), okay, 0)); code += branch(a + len(code), a + len(code) + 8)
            code += struct.pack('<I', adr(a + len(code), fail, 0)); code += bl(a + len(code), nn['_IOLog'])
            code += struct.pack('<III', 0xf9402be0, 0xa8c67bfd, 0xd65f03c0)
            assert len(code) < 0x100
            edit(a, code, 'Call real ' + name + ' with all x0-x7 arguments preserved; trace boolean return')
            for addr, label in [(begin, ' begin'), (okay, ' success'), (fail, ' failure')]:
                edit(addr, b'\x1b[36m' + ts['label'].encode() + b' ' + name.encode() + label.encode() + b'\x1b[0m\n\0', 'Cyan hardware path checkpoint')
        trace_wrapper(trace, int(ts['start_fn'], 16), 'start')
        init = next(t for s in ds.values() for t in s['sections'] if t['name'] == '__mod_init_func')
        original = struct.unpack('<Q', d.read(init['addr'] + 8, 8))[0]
        text = init_text
        code = struct.pack('<II', 0xa9bf7bfd, 0x910003fd) + bl(marker + 8, local(original))
        code += struct.pack('<I', adr(marker + 12, marker + 28, 0)) + bl(marker + 16, nn['_IOLog']) + struct.pack('<II', 0xa8c17bfd, 0xd65f03c0) + text
        edit(marker, code, 'Yellow registration marker after all real metaclass initializers')
        edit(local(init['addr'] + 8), struct.pack('<Q', marker), 'Retain initializer through marker wrapper')
        records.append({'marker': hex(marker), 'trace': hex(trace),
                        'table_counts': {n: len(v) for n, v in tables.items()}})
        return marker + len(code), records, newfix
    report = {'status': 'DRAFT; FINAL IMAGE AND NATIVE EXECUTION AUDIT REQUIRED', 'classes': table_reports,
            'field_instruction_and_size_patches': len(patches), 'reclaimed_bundle': OLD,
            'typed_allocation_signatures': signature_records}
    return private, report, special, patches, extra, skip, finalize
