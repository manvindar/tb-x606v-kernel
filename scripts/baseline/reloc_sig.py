#!/usr/bin/env python3
"""Relocation-exact signatures of a built kernel object, comparable with the shipping Image without shipping bytes in CI.

usage: reloc_sig.py check OBJ.o EVIDENCE.json OUT.json     (exit 0 all MATCH, 1 any DIFF, 2 unreadable/unsupported)
Masking rule (the only one): an instruction word is masked ONLY at the operand field of a relocation the object itself carries (field bits per type in
OPERAND_MASK, taken from the AArch64 instruction encodings), plus the imm26 of a branch the assembler resolved to another function of the same section
(no relocation, layout-dependent, its target is recorded by name and compared). Every other bit of every word is hashed. A relocation type that is not in
OPERAND_MASK is an error, never a full-word mask. Targets are compared by meaning: calls by function name, string references by content, data references by
(section, offset) of the object, which the evidence maps to the shipping address, data pointer slots by target. Evidence class: relocation-masked
instruction equality under the stated compiler/flags/headers; not identical source text."""
import bisect, hashlib, json, struct, sys
from pathlib import Path

OPERAND_MASK = {  # R_AARCH64_* number -> instruction bits that hold the relocated operand (AArch64 encodings)
    283: 0x03ffffff, 282: 0x03ffffff,                   # CALL26, JUMP26: imm26
    275: 0x60ffffe0, 276: 0x60ffffe0, 274: 0x60ffffe0,  # ADR_PREL_PG_HI21(_NC), ADR_PREL_LO21: immlo[30:29] immhi[23:5]
    277: 0x003ffc00,                                    # ADD_ABS_LO12_NC: imm12[21:10]
    278: 0x003ffc00, 284: 0x003ffc00, 285: 0x003ffc00, 286: 0x003ffc00, 299: 0x003ffc00,   # LDST{8,16,32,64,128}_ABS_LO12_NC: imm12[21:10]
    280: 0x00ffffe0, 273: 0x00ffffe0,                   # CONDBR19, LD_PREL_LO19: imm19[23:5]
    279: 0x0007ffe0,                                    # TSTBR14: imm14[18:5] (the tested bit number [23:19] stays compared)
}
LO12 = (277, 278, 284, 285, 286, 299)
DATA_ABS64 = 257        # pointer slot in a data section, 8 bytes


def elf(path):
    d = Path(path).read_bytes()
    shoff, = struct.unpack_from('<Q', d, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', d, 0x3a)
    sh = [dict(zip(('name', 'type', 'flags', 'addr', 'off', 'size', 'link', 'info', 'align', 'ent'), struct.unpack_from('<IIQQQQIIQQ', d, shoff + i * shentsize)))
          for i in range(shnum)]
    cstr = lambda sec, o: d[sh[sec]['off'] + o:d.index(b'\0', sh[sec]['off'] + o)].decode()
    for s in sh:
        s['sname'] = cstr(shstrndx, s['name'])
    st = next(i for i, s in enumerate(sh) if s['type'] == 2)
    sym = []
    for k in range(sh[st]['size'] // 24):
        n, info, _, shndx, val, size = struct.unpack_from('<IBBHQQ', d, sh[st]['off'] + k * 24)
        sym.append(dict(name=cstr(sh[st]['link'], n), type=info & 15, bind=info >> 4, shndx=shndx, val=val, size=size))
    secs = {i: d[s['off']:s['off'] + s['size']] for i, s in enumerate(sh) if s['type'] == 1}
    rels = {}
    for s in sh:
        if s['type'] == 4:
            r = rels.setdefault(s['info'], {})
            for k in range(s['size'] // 24):
                o, info, add = struct.unpack_from('<QQq', d, s['off'] + k * 24)
                r[o] = (info & 0xffffffff, sym[info >> 32], add)
    return secs, rels, sym, sh


def rawstr(buf, off):
    return bytes(buf[off:buf.index(b'\0', off)]).decode('latin1')


class Obj:
    def __init__(self, path):
        self.secs, self.rels, self.sym, self.sh = elf(path)

    def target(self, rs, add):
        """(section name, offset) for a symbol defined in a section, else (symbol name, addend)."""
        if rs['type'] in (1, 2, 3) and 0 < rs['shndx'] < len(self.sh):
            return self.sh[rs['shndx']]['sname'], (rs['val'] if rs['type'] != 3 else 0) + add
        return rs['name'], add

    def fn(self, name):
        return next((s for s in self.sym if s['name'] == name and s['type'] == 2 and s['shndx'] in self.secs), None)

    def func_signature(self, name):
        s = self.fn(name)
        if s is None:
            raise KeyError(name)
        ti, o0, sz = s['shndx'], s['val'], s['size']
        text, rel = self.secs[ti], self.rels.get(ti, {})
        tsyms = sorted((x['val'], x['name']) for x in self.sym if x['type'] == 2 and x['shndx'] == ti)
        names = [a for a, _ in tsyms]
        nm = lambda a: tsyms[bisect.bisect_right(names, a) - 1][1] if tsyms[bisect.bisect_right(names, a) - 1][0] == a else \
            f'{tsyms[bisect.bisect_right(names, a) - 1][1]}+{a - tsyms[bisect.bisect_right(names, a) - 1][0]:#x}'
        words = [struct.unpack_from('<I', text, o0 + 4 * w)[0] for w in range(sz // 4)]
        masks, relocs, calls, resolved = [0] * len(words), [], [], []
        offs = sorted(o for o in rel if o0 <= o < o0 + sz)
        for o in offs:
            typ, rs, add = rel[o]
            if typ not in OPERAND_MASK:
                raise ValueError(f'{name}: relocation type {typ} at +{o - o0:#x} has no operand mask')
            w = (o - o0) // 4
            masks[w] = OPERAND_MASK[typ]
            tgt = self.target(rs, add)
            if typ == 283:
                callee = rs['name'] if rs['type'] != 3 else nm(add)
                calls.append([o - o0, callee])
            relocs.append([o - o0, typ, tgt[0], tgt[1], f'{OPERAND_MASK[typ]:08x}'])
        for w, ow in enumerate(words):
            if masks[w] or (ow & 0xfc000000) not in (0x94000000, 0x14000000):
                continue
            ot = o0 + 4 * w + (((ow & 0x03ffffff) ^ 0x02000000) - 0x02000000) * 4
            if o0 <= ot < o0 + sz:
                continue                    # inside the function: layout independent, hashed as is
            masks[w] = 0x03ffffff
            resolved.append([4 * w, nm(ot)])
            calls.append([4 * w, nm(ot)])
        unmasked = b''.join(struct.pack('<I', ow & ~m) for ow, m in zip(words, masks))
        refs, strings, unpaired = [], [], 0      # adrp + lo12 pairs: the target in the object's own layout
        for o in offs:
            typ, rs, add = rel[o]
            if typ != 275:
                continue
            lo = next((p for p in offs if p > o and rel[p][1] is rs and rel[p][2] == add and rel[p][0] in LO12), None)
            if lo is None:
                unpaired += 1
                continue
            sec, off = self.target(rs, add)
            e = {'adrp': o - o0, 'lo12': lo - o0, 'section': sec, 'offset': off}
            if sec.startswith('.rodata.str'):
                e['string'] = rawstr(self.secs[rs['shndx']], off)
                strings.append(e['string'])
            refs.append(e)
        return {'size': sz, 'unmasked_words': len(words), 'masked_words': sum(1 for m in masks if m), 'relocations': relocs, 'resolved_branches': resolved,
                'calls': calls, 'data_refs': refs, 'unpaired_adrp': unpaired, 'unmasked_sha256': hashlib.sha256(unmasked).hexdigest()}

    def data_signature(self, secname):
        idx = next(i for i, s in enumerate(self.sh) if s['sname'] == secname)
        data, rel = bytearray(self.secs[idx]), self.rels.get(idx, {})
        slots = []
        for o in sorted(rel):
            typ, rs, add = rel[o]
            if typ != DATA_ABS64:
                raise ValueError(f'{secname}: relocation type {typ} at {o:#x} is not an ABS64 pointer slot')
            data[o:o + 8] = bytes(8)
            sec, off = self.target(rs, add)
            tn = sec
            if rs['type'] in (1, 2, 3) and 0 < rs['shndx'] < len(self.sh):
                if sec.startswith('.rodata.str'):
                    slots.append([o, 'string', rawstr(self.secs[rs['shndx']], off)])
                elif self.sh[rs['shndx']]['flags'] & 4:   # SHF_EXECINSTR: a function, by name
                    f = [x['name'] for x in self.sym if x['type'] == 2 and x['shndx'] == rs['shndx'] and x['val'] == off]
                    slots.append([o, 'function', f[0] if f else f'{tn}+{off:#x}'])
                else:
                    slots.append([o, 'data', f'{tn}', off])
            else:
                slots.append([o, 'extern', rs['name'], add])
        return {'size': len(data), 'slots': slots, 'unmasked_sha256': hashlib.sha256(bytes(data)).hexdigest(), 'masked_bytes': 8 * len(slots)}


def check(obj, ev):
    o = Obj(obj)
    out, bad = {'functions': {}, 'sections': {}}, 0
    for f, want in ev['functions'].items():
        try:
            got = o.func_signature(f)
        except KeyError:
            out['functions'][f] = {'status': 'NOT-BUILT'}
            bad = bad or 2
            continue
        diff = [k for k in want['object'] if want['object'][k] != got[k]]
        out['functions'][f] = {'status': 'MATCH' if not diff else 'DIFF', 'fields_differing': diff}
        bad = bad or (1 if diff else 0)
    for s, want in ev['sections'].items():
        try:
            got = o.data_signature(s)
        except StopIteration:
            out['sections'][s] = {'status': 'NOT-BUILT'}
            bad = bad or 2
            continue
        diff = [k for k in want['object'] if want['object'][k] != got[k]]
        out['sections'][s] = {'status': 'MATCH' if not diff else 'DIFF', 'fields_differing': diff}
        bad = bad or (1 if diff else 0)
    return bad, out


if __name__ == '__main__':
    if sys.argv[1] != 'check':
        sys.exit(__doc__)
    try:
        rc, out = check(sys.argv[2], json.loads(Path(sys.argv[3]).read_text()))
    except (ValueError, OSError) as e:
        print('unreadable/unsupported:', e)
        sys.exit(2)
    Path(sys.argv[4]).write_text(json.dumps({'exit': rc, **out}, indent=1))
    for kind in ('functions', 'sections'):
        for k, v in out[kind].items():
            print(v['status'], k, v.get('fields_differing') or '')
    sys.exit(rc)
