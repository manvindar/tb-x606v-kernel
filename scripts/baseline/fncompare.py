#!/usr/bin/env python3
"""Per-function instruction compare of recovered panel drivers against the shipping kernel image. Self-contained (python3 stdlib + llvm-objdump).

  fncompare.py fingerprint SHIPPING_DIR PANEL OUT.json [--streams DIR]   (local only: needs shipping-img/{Image.raw,image.elf,kallsyms.txt})
  fncompare.py compare VMLINUX_OR_ELF FINGERPRINTS.json PANEL [--streams DIR] [--report OUT.json]   (CI: candidate built by the pinned toolchain)
  fncompare.py fingerprint-names SHIPPING_DIR UNIT ANCHOR NAMES.json OUT.json [--streams DIR]
  fncompare.py compare-names VMLINUX_OR_ELF FINGERPRINTS.json UNIT [--streams DIR] [--report OUT.json]
      (name based units such as the NT36523W touch driver: every function name is resolved to the symbol of that name nearest to ANCHOR (e.g. nvt_ts_probe), so
       duplicated static helper names resolve inside the same object)
  PANEL is the driver name, e.g. mipi_hx83102p_inx_video_1200p. Exit 0 only if every function of the panel matches.

How an instance is found (same algorithm both sides, independent of header layout): the LCM_DRIVER object is located through the RELA record whose addend is the
address of the driver-name string; every 8-byte function pointer relocated inside that object is one of the panel's functions, named by symbol (lcm_init, ...);
lcm_set_cabc_mode / lcm_set_recovery_backlight (not reachable through the public LCM_DRIVER) are taken as the same-named symbols nearest to lcm_init.
Normalization: bl/b targets -> callee symbol name (external) or offset from function start (internal); adrp pages and absolute low-12 offsets of adrp-derived
addresses are masked; an adrp+add that resolves to a printable C string becomes STR:<content>; immediates, registers, stack offsets and struct offsets are kept.
Evidence class of a match: 'normalized-instruction-identical' (same code modulo link addresses, incl. string literals). Data tables referenced through
masked addresses are NOT covered by this compare: they are covered by data_equal checks below (bytes of the referenced objects) and by candcheck.py traces."""
import hashlib, json, os, re, struct, subprocess, sys, bisect

OBJDUMP = os.environ.get('LLVM_OBJDUMP', 'llvm-objdump')
ROLES = ['set_util_funcs', 'get_params', 'init', 'suspend', 'resume', 'set_cabc_mode', 'init_power', 'suspend_power', 'resume_power',
         'set_recovery_backlight', 'update', 'compare_id', 'setbacklight_cmdq', 'esd_check', 'ata_check', 'switch_mode']
EXTRA = ('set_cabc_mode', 'set_recovery_backlight')   # not in the public struct layout


class Target:
    """va-addressed view of an ELF (candidate) or of the shipping image."""
    def __init__(self, elf, off, syms, mem, membase, rela):
        self.elf, self.off, self.syms, self.mem, self.membase, self.rela = elf, off, syms, mem, membase, rela   # syms: sorted [(va, size|None, name)]
        self.sv = [s[0] for s in syms]
        self.by_name = {}
        for va, sz, n in syms: self.by_name.setdefault(n, []).append(va)

    def sym_exact(self, va):
        i = bisect.bisect_left(self.sv, va)
        out = [s[2] for s in self.syms[i:i + 4] if s[0] == va]
        return out[0] if out else None

    def func_end(self, va):
        i = bisect.bisect_left(self.sv, va)
        for s in self.syms[i:]:
            if s[0] == va and s[1]: return va + s[1]
        j = bisect.bisect_right(self.sv, va)
        return self.syms[j][0]

    def cstr(self, va):
        o = va - self.membase
        if not (0 <= o < len(self.mem)): return None
        e = self.mem.find(b'\0', o)
        s = self.mem[o:e]
        if 0 < len(s) < 200 and all(32 <= c < 127 or c in (9, 10) for c in s): return s.decode()
        return None


def load_elf(path):
    d = open(path, 'rb').read()
    shoff, = struct.unpack_from('<Q', d, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', d, 0x3a)
    secs = []
    for i in range(shnum):
        nm, typ, flags, addr, off, size, link, info, al, es = struct.unpack_from('<IIQQQQIIQQ', d, shoff + i * shentsize)
        secs.append(dict(nm=nm, typ=typ, flags=flags, addr=addr, off=off, size=size, link=link, es=es))
    shstr = secs[shstrndx]
    name = lambda s: d[shstr['off'] + s['nm']:d.index(b'\0', shstr['off'] + s['nm'])].decode()
    for s in secs: s['name'] = name(s)
    syms = []
    st = next(s for s in secs if s['typ'] == 2)
    strt = secs[st['link']]
    for k in range(st['size'] // 24):
        nm, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', d, st['off'] + 24 * k)
        if (info & 0xf) in (0, 1, 2) and value and shndx and not d[strt['off'] + nm:strt['off'] + nm + 1] == b'$':
            syms.append((value, size, d[strt['off'] + nm:d.index(b'\0', strt['off'] + nm)].decode()))
    syms.sort()
    alloc = [s for s in secs if s['flags'] & 2 and s['typ'] == 1 and s['addr']]
    lo = min(s['addr'] for s in alloc)
    hi = max(s['addr'] + s['size'] for s in alloc)
    buf = bytearray(hi - lo)
    for s in alloc: buf[s['addr'] - lo:s['addr'] - lo + s['size']] = d[s['off']:s['off'] + s['size']]
    rela = {}
    for s in secs:
        if s['name'] in ('.rela.dyn', '.rela') and s['typ'] == 4:
            for k in range(s['size'] // 24):
                ro, info, ad = struct.unpack_from('<QQq', d, s['off'] + 24 * k)
                if info & 0xffffffff == 0x403: rela[ro] = ad & (2 ** 64 - 1)
    return Target(path, 0, syms, bytes(buf), lo, rela)


def load_shipping(shipdir):
    B = 0xffffff8008080000
    img = open(f'{shipdir}/Image.raw', 'rb').read()
    syms = []
    for l in open(f'{shipdir}/kallsyms.txt'):
        f = l.split()
        if len(f) == 3 and len(f[0]) == 16: syms.append((int(f[0], 16), None, f[2]))
    syms.sort()
    # RELATIVE relocation records: contiguous 24-byte {offset, 0x403, addend} run (found through any record, here the first driver-name pointer)
    rela = {}
    pat = struct.pack('<Q', 0x403)
    # locate the table by scanning for the densest run of 0x403 infos
    i = img.find(pat)
    starts = []
    pos = 0
    while True:
        pos = img.find(pat, pos + 1)
        if pos < 0: break
        starts.append(pos)
    # the run is the largest set of positions spaced by 24
    sset = set(starts)
    best = None
    for p in starts:
        if p - 24 not in sset:
            n = 0
            q = p
            while q in sset: n += 1; q += 24
            if best is None or n > best[1]: best = (p, n)
    p0, n = best
    for k in range(n):
        ro, info, ad = struct.unpack_from('<QQq', img, p0 - 8 + 24 * k)
        rela[ro] = ad & (2 ** 64 - 1)
    t = Target(f'{shipdir}/image.elf', B, syms, img, B, rela)
    return t


def disasm(t, start, end):
    r = subprocess.run([OBJDUMP, '-d', '--no-show-raw-insn', f'--start-address={start - t.off:#x}', f'--stop-address={end - t.off:#x}', t.elf],
                       capture_output=True, text=True, check=True).stdout
    out = []
    for line in r.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+(\S+)\s*(.*)', line)
        if m: out.append((int(m.group(1), 16) + t.off, m.group(2), re.sub(r'\s*//.*$', '', re.sub(r' <[^>]*>', '', m.group(3))).strip()))
    return out


def normalize(t, start, end):
    ins = disasm(t, start, end)
    reg = {}     # reg -> 'page' (direct adrp) | ('based', va) (adrp+add)
    adrpv = {}
    out = []
    for a, op, args in ins:
        txt = f'{op} {args}'.strip()
        if op in ('bl', 'b') or op.startswith('b.') or op in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            m = re.search(r'0x([0-9a-f]+)$', args)
            if m:
                tgt = int(m.group(1), 16) + t.off
                if start <= tgt < end: txt = re.sub(r'0x[0-9a-f]+$', f'F{tgt - start:+#x}', txt)
                else: txt = re.sub(r'0x[0-9a-f]+$', 'EXT:' + (t.sym_exact(tgt) or 'UNKNOWN'), txt)
        elif op == 'adrp':
            r, v = re.match(r'(\w+), 0x([0-9a-f]+)', args).groups()
            adrpv[r] = int(v, 16) + t.off
            reg[r] = 'page'
            txt = f'adrp {r}, PAGE'
        elif op == 'adr':
            txt = re.sub(r'#?0x[0-9a-f]+$|#-?0x[0-9a-f]+$', 'ADDR', txt)
        else:
            m = re.match(r'(\w+), (\w+), #0x([0-9a-f]+)$', args)
            if op == 'add' and m and m.group(2) in adrpv and reg.get(m.group(2)) == 'page':
                va = adrpv[m.group(2)] + int(m.group(3), 16)
                s = t.cstr(va)
                txt = f'add {m.group(1)}, {m.group(2)}, ' + (f'STR:{s!r}' if s else 'PAGEOFF')
                adrpv[m.group(1)] = va
                reg[m.group(1)] = 'based'
            else:
                m = re.match(r'(\w+), \[(\w+), #0x([0-9a-f]+)\]', args)
                if op.startswith(('ldr', 'str')) and m and reg.get(m.group(2)) == 'page':
                    txt = txt.replace('#0x' + m.group(3), '#PAGEOFF')
                    if op.startswith('ldr'): reg.pop(m.group(1), None)
                else:
                    d0 = args.split(',')[0].strip()
                    if d0 in reg and not op.startswith(('str', 'cmp', 'tst', 'b')): reg.pop(d0, None)
        out.append(txt)
    return out


def instance(t, drv):
    """-> {role: va}"""
    name_va = None
    needle = drv.encode() + b'\0'
    pos = -1
    while True:
        pos = t.mem.find(needle, pos + 1)
        if pos < 0: break
        if pos == 0 or t.mem[pos - 1] == 0: name_va = pos + t.membase; break
    if name_va is None: raise SystemExit(f'driver name {drv!r} not found')
    structs = [ro for ro, ad in t.rela.items() if ad == name_va]
    if not structs and os.environ.get('FNCOMPARE_BY_NAME'):     # single-object smoke test: every lcm_* symbol is unique
        return {n[4:]: v[0] for n, v in t.by_name.items() if n.startswith('lcm_') and len(v) == 1 and n[4:] in ROLES}
    if len(structs) != 1: raise SystemExit(f'driver name pointer relocations: {structs}')
    s0 = structs[0]
    roles = {}
    for ro, ad in sorted(t.rela.items()):
        if s0 < ro < s0 + 0x200:
            n = t.sym_exact(ad)
            if n and n.startswith('lcm_'): roles[n[4:]] = ad
    # extras: nearest same-named symbol to lcm_init
    for e in EXTRA:
        c = t.by_name.get('lcm_' + e, [])
        if c and 'init' in roles: roles[e] = min(c, key=lambda v: abs(v - roles['init']))
    return roles


def fingerprint_all(t, drv):
    res = {}
    for role, va in instance(t, drv).items():
        end = t.func_end(va)
        norm = normalize(t, va, end)
        res[role] = dict(insns=len(norm), bytes=end - va, sha256=hashlib.sha256('\n'.join(norm).encode()).hexdigest(), _stream=norm)
    return res


def names_instance(t, names, anchor):
    a = t.by_name.get(anchor)
    if not a or len(a) != 1: raise SystemExit(f'anchor {anchor!r} must resolve to exactly one symbol, got {a}')
    out = {}
    for n in names:
        c = t.by_name.get(n, [])
        if c: out[n] = min(c, key=lambda v: abs(v - a[0]))
    return out


def main_names(argv):
    import difflib
    mode = argv[1]
    streams = argv[argv.index('--streams') + 1] if '--streams' in argv else None
    if mode == 'fingerprint-names':
        shipdir, unit, anchor, names_json, out = argv[2:7]
        t = load_shipping(shipdir)
        fp = {}
        for n, va in names_instance(t, json.load(open(names_json)), anchor).items():
            end = t.func_end(va)
            norm = normalize(t, va, end)
            fp[n] = dict(insns=len(norm), bytes=end - va, sha256=hashlib.sha256('\n'.join(norm).encode()).hexdigest())
            if streams:
                os.makedirs(streams, exist_ok=True)
                open(f'{streams}/{unit}.{n}.txt', 'w').write('\n'.join(norm) + '\n')
        db = json.load(open(out)) if os.path.exists(out) else {}
        db[unit] = dict(anchor=anchor, functions=fp)
        json.dump(db, open(out, 'w'), indent=1)
        print(unit, len(fp), 'functions')
        return 0
    elf, fpj, unit = argv[2:5]
    report = argv[argv.index('--report') + 1] if '--report' in argv else None
    db = json.load(open(fpj))[unit]
    t = load_elf(elf)
    got = names_instance(t, list(db['functions']), db['anchor'])
    rep, ok = {}, True
    for n, w in db['functions'].items():
        if n not in got:
            rep[n] = dict(status='missing-in-candidate'); ok = False; continue
        norm = normalize(t, got[n], t.func_end(got[n]))
        same = hashlib.sha256('\n'.join(norm).encode()).hexdigest() == w['sha256']
        ok &= same
        r = dict(status='normalized-instruction-identical' if same else 'differs', shipping_insns=w['insns'], candidate_insns=len(norm))
        if not same and streams and os.path.exists(f'{streams}/{unit}.{n}.txt'):
            a = open(f'{streams}/{unit}.{n}.txt').read().splitlines()
            r['diff'] = list(difflib.unified_diff(a, norm, 'shipping', 'candidate', lineterm='', n=1))[:80]
        rep[n] = r
    res = dict(unit=unit, all_match=ok, matching=sum(1 for v in rep.values() if v['status'].startswith('normalized')), total=len(rep), functions=rep)
    if report: json.dump(res, open(report, 'w'), indent=1)
    print(json.dumps({'all_match': ok, 'matching': res['matching'], 'total': res['total']}))
    return 0 if ok else 1


def main(argv):
    if argv[1] in ('fingerprint-names', 'compare-names'): return main_names(argv)
    mode = argv[1]
    streams = argv[argv.index('--streams') + 1] if '--streams' in argv else None
    if mode == 'fingerprint':
        shipdir, drv, out = argv[2:5]
        fp = fingerprint_all(load_shipping(shipdir), drv)
        if streams:
            os.makedirs(streams, exist_ok=True)
            for r, v in fp.items(): open(f'{streams}/{drv}.{r}.txt', 'w').write('\n'.join(v['_stream']) + '\n')
        for v in fp.values(): v.pop('_stream')
        db = json.load(open(out)) if os.path.exists(out) else {}
        db[drv] = fp
        json.dump(db, open(out, 'w'), indent=1)
        print(drv, {r: v['insns'] for r, v in fp.items()})
        return 0
    if mode == 'compare':
        elf, fpj, drv = argv[2:5]
        report = argv[argv.index('--report') + 1] if '--report' in argv else None
        want = json.load(open(fpj))[drv]
        got = fingerprint_all(load_elf(elf), drv)
        rep, ok = {}, True
        for role, w in want.items():
            g = got.get(role)
            if g is None: rep[role] = dict(status='missing-in-candidate'); ok = False; continue
            same = g['sha256'] == w['sha256']
            ok &= same
            r = dict(status='normalized-instruction-identical' if same else 'differs', shipping_insns=w['insns'], candidate_insns=g['insns'])
            if not same and streams and os.path.exists(f'{streams}/{drv}.{role}.txt'):
                import difflib
                a = open(f'{streams}/{drv}.{role}.txt').read().splitlines()
                r['diff'] = list(difflib.unified_diff(a, g['_stream'], 'shipping', 'candidate', lineterm='', n=1))[:80]
            rep[role] = r
        for role in got:
            if role not in want: rep[role] = dict(status='extra-in-candidate')
        out = dict(panel=drv, all_match=ok, source_identity='proved-for-matching-functions-only' if ok else 'unproved', functions=rep)
        if report: json.dump(out, open(report, 'w'), indent=1)
        print(json.dumps({r: v['status'] for r, v in rep.items()}, indent=1))
        return 0 if ok else 1
    raise SystemExit(__doc__)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
