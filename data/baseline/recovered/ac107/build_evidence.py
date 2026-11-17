#!/usr/bin/env python3
"""Build the AC107 evidence manifest: relocation-exact object signatures + the same quantities recomputed from the shipping Image (private input).

usage: build_evidence.py OBJ.o OUT.json
Shipping side uses the SAME mask positions as the object (taken from the object's own relocations, never from the shipping bytes), so the masks cannot hide
an unexplained mismatch. Fails (writes nothing) when any function, data section, call target, string or data target differs."""
import hashlib, json, re, struct, subprocess, sys
from pathlib import Path
H = Path(__file__).resolve().parent
sys.path.insert(0, str(H)); sys.path.insert(0, str(H.parent / 'inc/scripts/baseline'))
import cmpobj as C
import cmpdata as D
import reloc_sig as R

BASES = {'.rodata': 0xf4a578, '.data': 0x19970d8, '.bss': 0x2057420}     # refmap.py: consistent placement over all references
FN = 'ac107_codec0_get ac107_read ac107_codec0_put ac107_dump_regs loader_set_value ac107_start ac107_stop ac107_probe ac107_remove ac107_suspend ac107_resume ac107_codec_read ac107_codec_write ac107_i2c_probe ac107_i2c_remove ac107_i2c_detect ac107_show ac107_store ac107_i2c_suspend ac107_i2c_resume ac107_init'.split()
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
strip = lambda n: re.sub(r'\.(isra|constprop|part|cold)\.\d+', '', n)
img = lambda off, n: C.IMG[off:off + n]
word = lambda va: struct.unpack_from('<I', C.IMG, va - C.B)[0]


def adrp_target(va, w):
    v = ((w >> 5) & 0x7ffff) << 2 | (w >> 29) & 3
    v -= (1 << 21) if v & (1 << 20) else 0
    return (((va >> 12) + v) << 12)


def lo12(w, typ):
    assert typ != 277 or not (w >> 22) & 1, 'ADD with shifted immediate'
    return ((w >> 10) & 0xfff) << ({277: 0, 278: 0, 286: 3}[typ])


EXTERN = {}   # undefined data symbol -> shipping addresses seen across all functions


def ship_function(name, osig):
    va = C.BYN[name]
    nxt = C.KA[C.bisect.bisect_right(C.KA, va)]
    sz = osig['size']
    assert sz == nxt - va, (name, sz, nxt - va)
    words = [word(va + 4 * i) for i in range(sz // 4)]
    mask = [0] * len(words)
    for off, typ, *_r, m in osig['relocations']:
        mask[off // 4] = int(m, 16)
    for off, _t in osig['resolved_branches']:
        mask[off // 4] = 0x03ffffff
    digest = hashlib.sha256(b''.join(struct.pack('<I', w & ~m) for w, m in zip(words, mask))).hexdigest()
    res = {'va': hex(va), 'size': nxt - va, 'unmasked_sha256': digest, 'calls': [], 'data_refs': []}
    fails = [] if digest == osig['unmasked_sha256'] else ['unmasked_sha256']
    for off, callee in osig['calls']:
        w = words[off // 4]
        imm = w & 0x03ffffff
        imm -= (1 << 26) if imm & (1 << 25) else 0
        t = C.name_at(va + off + imm * 4)
        norm = strip(t) != t
        res['calls'].append([off, t])
        if not (t == callee or strip(t) == callee):
            fails.append(f'call@{off:#x}: object {callee} shipping {t}')
        elif norm:
            res.setdefault('suffix_normalized_calls', []).append([off, callee, t])
    relby = {r[0]: r for r in osig['relocations']}
    for e in osig['data_refs']:
        tva = adrp_target(va + e['adrp'], words[e['adrp'] // 4]) + lo12(words[e['lo12'] // 4], relby[e['lo12']][1])
        d = {'adrp': e['adrp'], 'section': e['section'], 'object_offset': e['offset'], 'shipping_va': hex(tva)}
        if 'string' in e:
            s = C.rawstr(C.IMG, tva - C.B)
            d['shipping_string'] = s
            if s != e['string']:
                fails.append(f"string@{e['adrp']:#x}: {e['string']!r} vs {s!r}")
        elif e['section'] in BASES:
            d['expected_va'] = hex(C.B + BASES[e['section']] + e['offset'])
            if tva != C.B + BASES[e['section']] + e['offset']:
                fails.append(f"data@{e['adrp']:#x}: {e['section']}+{e['offset']:#x} -> {tva:#x}, expected {C.B + BASES[e['section']] + e['offset']:#x}")
        else:                       # undefined in the object: kallsyms has no data symbols, so identity is by one consistent address per symbol
            d['shipping_symbol_address'] = hex(tva - e['offset'])
            EXTERN.setdefault(e['section'], set()).add(tva - e['offset'])
        res['data_refs'].append(d)
    if osig['unpaired_adrp']:
        fails.append('unpaired adrp')
    res['verdict'] = 'MATCH' if not fails else 'MISMATCH'
    res['failures'] = fails
    return res


def ship_section(sec, osig):
    base = BASES[sec]
    data = bytearray(img(base, osig['size']))
    fails, slots = [], []
    for s in osig['slots']:
        o = s[0]
        va = C.B + base + o
        tgt = D.RELA.get(va)
        data[o:o + 8] = bytes(8)
        if tgt is None:
            fails.append(f'slot {o:#x}: no RELA entry in the shipping image')
            continue
        kind = s[1]
        if kind == 'function':
            t = C.name_at(tgt)
            ok = t == s[2]
        elif kind == 'string':
            t = C.rawstr(C.IMG, tgt - C.B)
            ok = t == s[2]
        elif kind == 'data':
            t = hex(tgt - C.B - BASES[s[2]]) if s[2] in BASES else None
            ok = t is not None and int(t, 16) == s[3]
        else:
            t = C.name_at(tgt)
            ok = t == s[2]
        slots.append([o, kind, t])
        if not ok:
            fails.append(f'slot {o:#x} {kind}: object {s[2:]} shipping {t}')
    digest = hashlib.sha256(bytes(data)).hexdigest()
    if digest != osig['unmasked_sha256']:
        fails.append('unmasked_sha256')
    return {'base': hex(base), 'unmasked_sha256': digest, 'slots': slots, 'verdict': 'MATCH' if not fails else 'MISMATCH', 'failures': fails}


def main(obj, out):
    o = R.Obj(obj)
    ev = {'functions': {}, 'sections': {}}
    for f in FN:
        s = o.func_signature(f)
        ev['functions'][f] = {'object': s, 'shipping': ship_function(f, s)}
    for sec in ('.rodata', '.data'):
        s = o.data_signature(sec)
        ev['sections'][sec] = {'object': s, 'shipping': ship_section(sec, s)}
    bad = [(k, v['shipping']['failures']) for kind in ('functions', 'sections') for k, v in ev[kind].items() if v['shipping']['verdict'] != 'MATCH']
    for sym_, addrs in EXTERN.items():
        if len(addrs) != 1:
            bad.append((sym_, f'object symbol resolves to {len(addrs)} shipping addresses'))
    types = {}
    for f in ev['functions'].values():
        for r in f['object']['relocations']:
            types.setdefault(r[1], {'mask': r[4], 'count': 0})['count'] += 1
    cc = (H / 'cc.sh').read_text()
    ac = H / 'ktree/include/generated/autoconf.h'
    cfg = {k: v for k, v in re.findall(r'#define (CONFIG_(?:AC107|DEBUG_INFO|I2C|SND_SOC|ARM64|MODULES|CC_STACKPROTECTOR_STRONG|FRAME_POINTER|KASAN|KCOV|GCOV_KERNEL|UBSAN\w*))\s+(\S+)', ac.read_text())}
    ev['meta'] = {
        'evidence_class': 'relocation-masked instruction and data equality under the stated compiler, flags and headers; not identical source text',
        'source': {'repo': 'Bakoubak/android_kernel_lenovo_x306x-10', 'ref': 'upstream', 'commit': '90ff197cbe3da896077ba4ba3b31751d23903b25',
                   'path': 'ac107.c (public tree, sound/soc/codecs/ac107.c)', 'public_blob': '062ed14ffb20e0a9958c323a82b795c6a0dae63a',
                   'public_sha256': sha(H / 'upstream/Bakoubak_android_kernel_lenovo_x306x-10/ac107.c'),
                   'candidate_blob': subprocess.run(['git', 'hash-object', str(H / 'candidate/ac107.c')], capture_output=True, text=True).stdout.strip(),
                   'candidate_sha256': sha(H / 'candidate/ac107.c'),
                   'ac107_h_blob': subprocess.run(['git', 'hash-object', str(H / 'candidate/ac107.h')], capture_output=True, text=True).stdout.strip(),
                   'single_probe_delta': (H / 'candidate/ac107.c.diff').read_text(),
                   'delta_effect': 'public ac107_i2c_probe: 488 bytes, 37 differing words; with the delta 548 bytes and all words equal'},
        'toolchain': {'clang': subprocess.run([str(H / 'tc-darwin/clang/bin/clang-9'), '--version'], capture_output=True, text=True).stdout.splitlines()[0],
                      'target': 'aarch64-linux-gnu', 'cc_sh_sha256': hashlib.sha256(cc.encode()).hexdigest(), 'cc_sh': cc,
                      'autoconf_h_sha256': sha(ac), 'autoconf_selected': cfg, 'header_lineage': 'Lenovo 4.9.117 drop 7f6a59c (not the exact 4.9.190 vendor tree, which is not public)',
                      'object_sha256': sha(obj)},
        'shipping': {'Image_raw_sha256': sha(H.parent / 'shipping-img/Image.raw'), 'kallsyms_sha256': sha(H.parent / 'shipping-img/kallsyms.txt'),
                     'section_bases_file_offset': {k: hex(v) for k, v in BASES.items()}, 'rela_entries': D.RELA_N},
        'masks': {'rule': 'only the operand field of a relocation present in the object, plus imm26 of an unrelocated branch to another function of the same section; unknown relocation types are an error',
                  'relocation_types_used': types, 'operand_mask_table': {str(k): f'{v:08x}' for k, v in R.OPERAND_MASK.items()},
                  'pointer_slots': 'ABS64 slots (8 bytes) in .rodata/.data; shipping keeps zero bytes + R_AARCH64_RELATIVE entry, target compared by function name, string content or section placement'},
        'tools_sha256': {'reloc_sig.py': sha(H.parent / 'inc/scripts/baseline/reloc_sig.py'), 'build_evidence.py': sha(__file__), 'cmpobj.py': sha(H / 'cmpobj.py')},
        'totals': {'functions': len(FN), 'function_bytes': sum(v['object']['size'] for v in ev['functions'].values()),
                   'masked_words': sum(v['object']['masked_words'] for v in ev['functions'].values()),
                   'words': sum(v['object']['unmasked_words'] for v in ev['functions'].values()),
                   'resolved_branches': sum(len(v['object']['resolved_branches']) for v in ev['functions'].values()),
                   'data_refs': sum(len(v['object']['data_refs']) for v in ev['functions'].values()),
                   'pointer_slots': sum(len(v['object']['slots']) for v in ev['sections'].values())},
        'extern_data_symbols': {k: {'shipping_address': hex(next(iter(v))), 'identity': 'one consistent address in every reference; kallsyms carries no data symbols, so the name is not verified'} for k, v in EXTERN.items()},
        'not_covered': ['ac107_exit (.exit.text, discarded in a built-in image)', 'debug sections', 'data bytes of .bss (no content)', 'behaviour: equal code under equal build is not proof of identical source text', 'chip presence / DT node on the board'],
    }
    if bad:
        print('MISMATCH', bad)
        sys.exit(1)
    Path(out).write_text(json.dumps(ev, indent=1))
    print('ok', ev['meta']['totals'], types)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
