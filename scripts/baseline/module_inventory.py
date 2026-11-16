#!/usr/bin/env python3
"""Inventory ARM64 kernel modules: vermagic, imported symbol CRCs (__versions), exported symbol CRCs.
usage: module_inventory.py MODULE_DIR OUT.json   (every *.ko must parse; empty directory is an error)"""
import hashlib, json, struct, sys
from pathlib import Path


def sections(d):
    if d[:6] != b'\x7fELF\x02\x01':
        raise ValueError('not a little-endian ELF64 module')
    shoff, = struct.unpack_from('<Q', d, 0x28)
    machine, = struct.unpack_from('<H', d, 0x12)
    es, sn, ss = struct.unpack_from('<HHH', d, 0x3a)
    if machine != 183 or es != 64 or not 0 <= ss < sn or shoff + sn * es > len(d):
        raise ValueError('not an ARM64 relocatable module or bad section table')
    raw = [struct.unpack_from('<IIQQQQIIQQ', d, shoff + i * es) for i in range(sn)]
    for s in raw:  # reject sections that point outside the file
        if s[1] != 8 and s[4] + s[5] > len(d):
            raise ValueError('section outside module')
    names = d[raw[ss][4]:raw[ss][4] + raw[ss][5]]
    return [(names[s[0]:names.index(b'\0', s[0])].decode(), s) for s in raw]


def parse(path):
    d = Path(path).read_bytes()
    secs = sections(d)
    by = {n: s for n, s in secs}
    for need in ('__versions', '.modinfo', '.symtab', '.strtab'):
        if need not in by:
            raise ValueError(f'missing {need}')
    body = lambda s: d[s[4]:s[4] + s[5]]
    v = body(by['__versions'])
    if not v or len(v) % 64:
        raise ValueError('empty or malformed __versions')
    imports = {}
    for i in range(0, len(v), 64):
        crc, raw = struct.unpack_from('<Q56s', v, i)
        name = raw.split(b'\0', 1)[0].decode('ascii')
        if not name or name in imports:
            raise ValueError('invalid or duplicate versioned symbol')
        imports[name] = crc & 0xffffffff
    info = [x.decode() for x in body(by['.modinfo']).split(b'\0') if x]
    vermagic = [x[9:] for x in info if x.startswith('vermagic=')]
    if len(vermagic) != 1:
        raise ValueError('missing or duplicate vermagic')
    sym, strs = body(by['.symtab']), body(by['.strtab'])
    exports = {}  # an export is an absolute __crc_<name> symbol (__ksymtab_* symbols are stripped)
    for o in range(0, len(sym) - 23, 24):
        name_off, _info, _other, shndx, value = struct.unpack_from('<IBBHQ', sym, o)
        name = strs[name_off:strs.index(b'\0', name_off)].decode('ascii', 'replace')
        if name.startswith('__crc_') and shndx == 0xfff1:
            exports[name[6:]] = value & 0xffffffff
    exports = dict(sorted(exports.items()))
    return dict(sha256=hashlib.sha256(d).hexdigest(), bytes=len(d), vermagic=vermagic[0],
                imports=dict(sorted(imports.items())), exports=exports)


def inventory(directory):
    mods = sorted(Path(directory).glob('*.ko'))
    if not mods:
        raise ValueError('no modules found')
    return {'modules': {m.name[:-3]: parse(m) for m in mods}}


if __name__ == '__main__':
    out = inventory(sys.argv[1])
    json.dump(out, open(sys.argv[2], 'w'), indent=1, sort_keys=True)
    for n, m in out['modules'].items():
        print(n, len(m['imports']), 'imports', len(m['exports']), 'exports', m['vermagic'])
