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


class Unsupported(Exception):
    """An instruction this normalizer cannot decode with certainty. The result for that function is NOT MEASURED, never a mismatch."""


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
    r = subprocess.run([OBJDUMP, '-d', '--no-show-raw-insn', '--print-imm-hex', f'--start-address={start - t.off:#x}', f'--stop-address={end - t.off:#x}', t.elf],
                       capture_output=True, text=True, check=True).stdout
    out = []
    for line in r.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+(\S+)\s*(.*)', line)
        if m: out.append((int(m.group(1), 16) + t.off, m.group(2), re.sub(r'\s*//.*$', '', re.sub(r' <[^>]*>', '', m.group(3))).strip()))
    return out


def word(t, a):
    return struct.unpack_from('<I', t.mem, a - t.membase)[0]


def sext(v, bits):
    return v - (1 << bits) if v >> (bits - 1) else v


def branch_target(op, w, a):
    """Absolute target of b/bl/b.cond/cbz/cbnz/tbz/tbnz from the instruction word (objdump prints '#N' or '0xADDR' depending on its version)."""
    if op in ('b', 'bl'): return a + sext(w & 0x3ffffff, 26) * 4
    if op in ('tbz', 'tbnz'): return a + sext((w >> 5) & 0x3fff, 14) * 4
    return a + sext((w >> 5) & 0x7ffff, 19) * 4     # b.cond, cbz, cbnz


ADRP_MASK, ADRP_BITS = 0x9f000000, 0x90000000
ADR_MASK, ADR_BITS = 0x9f000000, 0x10000000
IMM12 = 0x3ffc00


def check_class(op, w, a):
    """The printed mnemonic must agree with the instruction word, or the text cannot be trusted."""
    ok = {'b': (w >> 26) == 0x05, 'bl': (w >> 26) == 0x25,
          'cbz': (w & 0x7f000000) == 0x34000000,
          'cbnz': (w & 0x7f000000) == 0x35000000,
          'tbz': (w & 0x7f000000) == 0x36000000, 'tbnz': (w & 0x7f000000) == 0x37000000,
          'adrp': (w & ADRP_MASK) == ADRP_BITS, 'adr': (w & ADR_MASK) == ADR_BITS}
    if op.startswith('b.'): ok[op] = (w & 0xff000010) == 0x54000000
    if op in ok and not ok[op]:
        raise Unsupported(f'{a:#x}: printed {op!r} but instruction word {w:#010x} is not that instruction class')


def normalize2(t, start, end):
    """-> (text lines, masked-word lines). The word lines are objdump independent: the raw 32-bit word with pc-relative and adrp-page fields masked."""
    ins = disasm(t, start, end)
    reg = {}     # reg -> 'page' (direct adrp) | ('based', va) (adrp+add)
    adrpv = {}
    out, wout = [], []
    for a, op, args in ins:
        if op in ('<unknown>', '.inst', '.word', '.long', '.byte') or op.startswith('<'):
            raise Unsupported(f'{a:#x}: undecodable instruction {op!r}')
        w = word(t, a)
        txt = f'{op} {args}'.strip()
        wtxt = f'{w:08x}'
        if op in ('bl', 'b') or op.startswith('b.') or op in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            check_class(op, w, a)
            tgt = branch_target(op, w, a)
            lab = f'F{tgt - start:+#x}' if start <= tgt < end else 'EXT:' + (t.sym_exact(tgt) or 'UNKNOWN')
            txt = f'{op} ' + ', '.join(args.split(', ')[:-1] + [lab])
            mask = 0xfc000000 if op in ('b', 'bl') else 0xfff8001f if op in ('tbz', 'tbnz') else 0xff00001f   # keep opcode, registers, bit number, condition
            wtxt = f'{w & mask:08x}|{lab}'
        elif op == 'adrp':
            check_class(op, w, a)
            r = args.split(',')[0].strip()
            if r != f'x{w & 31}' and not (w & 31 == 31 and r == 'xzr'):
                raise Unsupported(f'{a:#x}: adrp destination {r!r} disagrees with word {w:#010x}')
            adrpv[r] = (a & ~0xfff) + (sext(((w >> 5) & 0x7ffff) << 2 | (w >> 29) & 3, 21) << 12)
            reg[r] = 'page'
            txt = f'adrp {r}, PAGE'
            wtxt = f'{w & 0x9f00001f:08x}|PAGE'
        elif op == 'adr':
            check_class(op, w, a)
            txt = f'adr {args.split(",")[0].strip()}, ADDR'
            wtxt = f'{w & 0x9f00001f:08x}|ADDR'
        else:
            m = re.match(r'(\w+), (\w+), #0x([0-9a-f]+)$', args)
            if op == 'add' and m and m.group(2) in adrpv and reg.get(m.group(2)) == 'page':
                va = adrpv[m.group(2)] + int(m.group(3), 16)
                s = t.cstr(va)
                txt = f'add {m.group(1)}, {m.group(2)}, ' + (f'STR:{s!r}' if s else 'PAGEOFF')
                wtxt = f'{w & ~IMM12 & 0xffffffff:08x}|' + (f'STR:{s!r}' if s else 'PAGEOFF')
                adrpv[m.group(1)] = va
                reg[m.group(1)] = 'based'
            else:
                m = re.match(r'(\w+), \[(\w+), #0x([0-9a-f]+)\]', args)
                if op.startswith(('ldr', 'str')) and m and reg.get(m.group(2)) == 'page':
                    txt = txt.replace('#0x' + m.group(3), '#PAGEOFF')
                    wtxt = f'{w & ~IMM12 & 0xffffffff:08x}|PAGEOFF'
                    if op.startswith('ldr'): reg.pop(m.group(1), None)
                else:
                    d0 = args.split(',')[0].strip()
                    if d0 in reg and not op.startswith(('str', 'cmp', 'tst', 'b')): reg.pop(d0, None)
        out.append(txt)
        wout.append(wtxt)
    return out, wout


def normalize(t, start, end):
    return normalize2(t, start, end)[0]


def instance(t, drv):
    """-> {role: va}"""
    # the linker may tail-merge the name into a longer string ("panel_" + name), so every occurrence of name+NUL is a candidate address;
    # the one that a relocation record points at is the driver name pointer (exactly one must)
    needle = drv.encode() + b'\0'
    pos, cands = -1, []
    while True:
        pos = t.mem.find(needle, pos + 1)
        if pos < 0: break
        cands.append(pos + t.membase)
    if not cands: raise SystemExit(f'driver name {drv!r} not found')
    withrel = [va for va in cands if any(ad == va for ad in t.rela.values())]
    if len(withrel) > 1 or (not withrel and not os.environ.get('FNCOMPARE_BY_NAME')):
        raise SystemExit(f'driver name {drv!r}: {len(cands)} occurrences, {len(withrel)} with relocation records')
    name_va = withrel[0] if withrel else cands[0]
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


def role_scopes(roles):
    """Where each role's function lives. The struct-pointed roles are the panel's own functions; EXTRA roles are found by "nearest same-named symbol to lcm_init",
    which can land in a NEIGHBOURING panel's object when this panel defines none (seen on the real CI vmlinux). An extra role is `inside-object-span` only if it lies
    between the lowest and highest struct-pointed function of this panel; otherwise it is `outside-object-span` and a verdict on it says nothing about this panel."""
    base = [v for k, v in roles.items() if k not in EXTRA]
    lo, hi = (min(base), max(base)) if base else (0, -1)
    return {k: ('own' if k not in EXTRA else 'inside-object-span' if lo <= v <= hi else 'outside-object-span') for k, v in roles.items()}


def sha(lines):
    return hashlib.sha256('\n'.join(lines).encode()).hexdigest()


def fingerprint_all(t, drv, strict=True, evidence=None):
    """strict (fingerprinting the shipping image): an unsupported instruction aborts. Not strict (compare): the role is reported NOT MEASURED.
    evidence: directory that receives the objdump text of every role (candidate side only), written before any normalization."""
    res = {}
    roles = instance(t, drv)
    scopes = role_scopes(roles)
    for role, va in roles.items():
        end = t.func_end(va)
        if evidence:
            os.makedirs(evidence, exist_ok=True)
            open(f'{evidence}/{drv}.{role}.s', 'w').write(''.join(f'{a:x}: {op} {args}\n' for a, op, args in disasm(t, va, end)))
        try:
            norm, wn = normalize2(t, va, end)
        except Unsupported as e:
            if strict: raise
            res[role] = dict(not_measured=str(e), bytes=end - va, scope=scopes[role])
            continue
        res[role] = dict(insns=len(norm), bytes=end - va, sha256=sha(norm), wsha256=sha(wn), scope=scopes[role], _stream=norm)
    return res


def judge(w, g):
    """-> status for one function. w: recorded shipping entry, g: candidate entry. Only decoded instruction words may establish a mismatch."""
    if 'not_measured' in g: return 'not-measured'
    text = g['sha256'] == w['sha256']
    if 'wsha256' in w and 'wsha256' in g:
        words = g['wsha256'] == w['wsha256']
        if words: return 'normalized-instruction-identical' if text else 'words-identical-text-differs'
        return 'differs'
    return 'normalized-instruction-identical' if text else 'differs'


MATCH = ('normalized-instruction-identical', 'words-identical-text-differs')


def exit_code(statuses):
    """bit 0: a measured difference or a missing function; bit 1: something NOT MEASURED (unsupported syntax), reported separately."""
    return (1 if any(x in ('differs', 'missing-in-candidate') for x in statuses) else 0) | (2 if 'not-measured' in statuses else 0)


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
            norm, wn = normalize2(t, va, end)
            fp[n] = dict(insns=len(norm), bytes=end - va, sha256=sha(norm), wsha256=sha(wn))
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
    rep = {}
    for n, w in db['functions'].items():
        if n not in got:
            rep[n] = dict(status='missing-in-candidate'); continue
        try:
            norm, wn = normalize2(t, got[n], t.func_end(got[n]))
        except Unsupported as e:
            rep[n] = dict(status='not-measured', reason=str(e)); continue
        st = judge(w, dict(sha256=sha(norm), wsha256=sha(wn)))
        same = st in MATCH
        r = dict(status=st, shipping_insns=w['insns'], candidate_insns=len(norm))
        if not same and streams and os.path.exists(f'{streams}/{unit}.{n}.txt'):
            a = open(f'{streams}/{unit}.{n}.txt').read().splitlines()
            r['diff'] = list(difflib.unified_diff(a, norm, 'shipping', 'candidate', lineterm='', n=1))[:80]
        rep[n] = r
    ok = all(v['status'] in MATCH for v in rep.values())
    code = exit_code([v['status'] for v in rep.values()])
    res = dict(unit=unit, all_match=ok, exit=code, matching=sum(1 for v in rep.values() if v['status'] in MATCH),
               not_measured=sorted(n for n, v in rep.items() if v['status'] == 'not-measured'), total=len(rep), functions=rep)
    if report: json.dump(res, open(report, 'w'), indent=1)
    print(json.dumps({'all_match': ok, 'matching': res['matching'], 'total': res['total'], 'not_measured': len(res['not_measured'])}))
    return code


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
        evidence = argv[argv.index('--disasm-out') + 1] if '--disasm-out' in argv else None
        want = json.load(open(fpj))[drv]
        got = fingerprint_all(load_elf(elf), drv, strict=False, evidence=evidence)
        rep = {}
        for role, w in want.items():
            g = got.get(role)
            if g is None: rep[role] = dict(status='missing-in-candidate'); continue
            st = judge(w, g)
            if st == 'not-measured':
                rep[role] = dict(status=st, reason=g['not_measured'], bytes=g['bytes'], scope=g.get('scope')); continue
            same = st in MATCH
            r = dict(status=st, scope=g.get('scope'), shipping_insns=w['insns'], candidate_insns=g['insns'])
            if st == 'words-identical-text-differs': r['note'] = 'masked instruction words equal; only objdump text differs (printing, not a binary difference)'
            if not same and streams and os.path.exists(f'{streams}/{drv}.{role}.txt'):
                import difflib
                a = open(f'{streams}/{drv}.{role}.txt').read().splitlines()
                r['diff'] = list(difflib.unified_diff(a, g['_stream'], 'shipping', 'candidate', lineterm='', n=1))[:80]
            rep[role] = r
        for role in got:
            if role not in want: rep[role] = dict(status='extra-in-candidate')
        code = exit_code([v['status'] for v in rep.values()])
        ok = all(v['status'] in MATCH for v in rep.values())
        outside = sorted(r for r, v in rep.items() if v.get('scope') == 'outside-object-span')
        own = [v for r, v in rep.items() if r not in outside]
        out = dict(panel=drv, all_match=ok, exit=code, not_measured=sorted(r for r, v in rep.items() if v['status'] == 'not-measured'),
                   own_object=dict(matching=sum(1 for v in own if v['status'] in MATCH), total=len(own)), outside_object_span_roles=outside,
                   source_identity='proved-for-matching-functions-only' if ok else 'unproved', functions=rep)
        if report: json.dump(out, open(report, 'w'), indent=1)
        print(json.dumps({r: v['status'] for r, v in rep.items()}, indent=1))
        return code
    raise SystemExit(__doc__)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
