"""Shared code of the fidelity instrument: instruction normalization (AArch64), shipping-image reader, relocatable-object reader.
stdlib only. See README.md for the normalization spec and what 'equal' proves."""
import bisect, hashlib, re, struct
from pathlib import Path

IMG_BASE = 0xffffff8008080000      # virtual address of file offset 0 of shipping-img/Image.raw (_text); same constant the AC107 pipeline calibrated
NOP = 0xd503201f
SUFFIX = re.compile(r'(\.(isra|constprop|part|cold|llvm)\.\d+|\.cold)+$')
WINDOW = 4096                       # an ADRP's register stays 'page base' until it is rewritten or clobbered by a call (see writes()); this only caps pathological functions
LO12_RELOCS = {277, 278, 284, 285, 286, 287, 299}   # ADD_ABS_LO12_NC, LDST*_ABS_LO12_NC, ...
CALL_RELOCS = {282, 283}            # JUMP26, CALL26


def strip(name):
    return SUFFIX.sub('', name)


def sext(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def cstring(buf, off):
    """NUL-terminated printable string at buf[off:], or None."""
    if off < 0 or off >= len(buf):
        return None
    e = buf.find(b'\0', off, off + 400)
    if e <= off:
        return None
    s = bytes(buf[off:e])
    return s if all(c >= 9 and c != 127 and (c >= 32 or c in (9, 10, 13)) for c in s) else None


def sh12(s):
    return hashlib.sha1(s).hexdigest()[:12]


def classify_word(w):
    """('b', imm26 idx) etc: returns (kind, target_delta_in_words or None, mask) for control-flow words, else None."""
    if (w & 0x7c000000) == 0x14000000:                      # B / BL
        return ('call' if w & 0x80000000 else 'jump', sext(w & 0x03ffffff, 26), 0x03ffffff)
    if (w & 0xff000010) == 0x54000000 or (w & 0x7e000000) == 0x34000000:   # B.cond, CBZ/CBNZ
        return ('cond', sext((w >> 5) & 0x7ffff, 19), 0x00ffffe0)
    if (w & 0x7e000000) == 0x36000000:                      # TBZ/TBNZ
        return ('cond', sext((w >> 5) & 0x3fff, 14), 0x0007ffe0)
    return None


def writes(w):
    """Registers (0..30) the instruction best-effort writes. Used only to end the 'page base' state of an ADRP register."""
    top = (w >> 25) & 0xf
    if top in (8, 9, 5, 13):                                # data-processing immediate / register
        return {w & 31}
    if (w & 0x9f000000) in (0x90000000, 0x10000000):        # ADRP / ADR
        return {w & 31}
    if (w & 0x3b000000) in (0x39000000, 0x38000000) and (w >> 22) & 1:      # single load
        return {w & 31}
    if (w & 0x3b000000) == 0x18000000:                      # literal load
        return {w & 31}
    if (w & 0x3a000000) == 0x28000000 and (w >> 22) & 1:    # LDP/LDPSW
        return {w & 31, (w >> 10) & 31}
    if (w & 0xfffffc1f) in (0xd63f0000,) or (w & 0xfc000000) == 0x94000000:   # BLR / BL: caller-saved registers are clobbered
        return set(range(19)) | {30}
    return set()


def normalize(words, relocs=None):
    """words: instruction words of one function. relocs: {word_index: (type, ...)} for objects (None for the shipping image).
    Returns (norm_words, controls, adds): controls = [(idx, kind, target_idx_or_None_if_relocated)] for every masked branch whose target is outside the
    function or relocated; adds = [(idx, adrp_page_delta, imm12, adrp_idx)] for add-immediates masked after an ADRP (used for string references)."""
    n = len(words)
    out = list(words)
    controls, adds = [], []
    pending = {}                                            # reg -> [adrp idx, page delta]: register still holds an ADRP page base
    snap = {}                                               # forward-branch target index -> pending state at the branch (flow-aware: cold blocks after RET)
    ended = False                                           # previous instruction was an unconditional transfer (RET, BR, B)
    fallbacks = 0
    for i, w in enumerate(words):
        r = relocs.get(i) if relocs else None
        if i in snap:
            if ended:
                pending = {k: list(v) for k, v in snap[i].items()}
            else:
                for k, v in snap[i].items():
                    pending.setdefault(k, list(v))
        elif ended:
            pending = {}
        ended = False
        c = classify_word(w)
        if c:
            kind, d, m = c
            t = i + d
            if 0 <= t < n and r is None:
                if t > i:
                    cur = snap.setdefault(t, {})
                    for k, v in pending.items():
                        cur.setdefault(k, list(v))
            else:
                out[i] = w & ~m
                controls.append((i, kind, None if r is not None else t))
            if kind == 'jump':
                ended = True
            for k in writes(w):
                pending.pop(k, None)
            continue
        if (w & 0xfffffc1f) in (0xd65f0000, 0xd61f0000):    # RET / BR
            ended = True
        if (w & 0x9f000000) == 0x90000000:                  # ADRP
            out[i] = w & ~(0x60000000 | 0x00ffffe0)
            immlo, immhi = (w >> 29) & 3, (w >> 5) & 0x7ffff
            pending[w & 31] = [i, sext((immhi << 2) | immlo, 21)]
            continue
        if (w & 0x9f000000) == 0x10000000:                  # ADR
            out[i] = w & ~(0x60000000 | 0x00ffffe0)
        elif (w & 0x3b000000) == 0x18000000:                # LDR literal
            out[i] = w & ~0x00ffffe0
        else:
            rn = (w >> 5) & 31
            if rn in pending and (w & 0xffc00000) == 0x91000000:        # ADD xd, xn, #imm12 (64-bit, no shift)
                out[i] = w & ~0x003ffc00
                adds.append((i, pending[rn][1], (w >> 10) & 0xfff, pending[rn][0]))
            elif rn in pending and (w & 0x3b000000) == 0x39000000:      # LDR/STR (unsigned offset), any size/V
                out[i] = w & ~0x003ffc00
            elif r is not None:                             # relocated word the patterns did not mask (not expected with these patterns)
                typ = r[0]
                if typ in LO12_RELOCS:
                    out[i] = w & ~0x003ffc00
                elif typ not in CALL_RELOCS and typ != 275:
                    out[i] = w & ~0x001fffe0
                fallbacks += 1
        moved = pending.get((w >> 16) & 31) if (w & 0xffe0ffe0) == 0xaa0003e0 else None     # MOV xd, xm copies the page base
        for k in writes(w):
            pending.pop(k, None)
        if moved:
            pending[w & 31] = list(moved)
    normalize.fallbacks = fallbacks                         # relocated words the patterns did not cover (quality counter, last call)
    return out, controls, adds


def digest(norm, call_names):
    return hashlib.sha1(struct.pack('<%dI' % len(norm), *norm) + b'\0' + '\n'.join(call_names).encode()).hexdigest()[:12]


def trim(words):
    k = len(words)
    while k and words[k - 1] in (NOP, 0):
        k -= 1
    return words[:k]


class Shipping:
    """The shipping image + kallsyms. Function ranges come from kallsyms address deltas."""

    def __init__(self, image, kallsyms):
        self.img = Path(image).read_bytes()
        syms = []
        for l in Path(kallsyms).read_text().splitlines():
            f = l.split()
            if len(f) == 3 and re.fullmatch(r'[0-9a-f]{16}', f[0]):
                syms.append((int(f[0], 16), f[1], f[2]))
        syms.sort(key=lambda s: (s[0], s[2]))
        self.syms = syms
        self.addrs = [s[0] for s in syms]
        names_at = {}
        for a, _, n in syms:
            names_at.setdefault(a, set()).add(strip(n))
        self.canon_at = {a: min(v) for a, v in names_at.items()}
        self.alias = {}
        for a, v in names_at.items():
            if len(v) > 1:
                for n in v:
                    if n != self.canon_at[a]:
                        self.alias[n] = self.canon_at[a]
        self.uaddrs = sorted(names_at)
        self.functions = []                                  # (addr, name, size_bytes)
        for a, t, n in syms:
            if t in 'tTwW' and a >= IMG_BASE:
                k = bisect.bisect_right(self.uaddrs, a)
                nxt = self.uaddrs[k] if k < len(self.uaddrs) else a + 4
                size = min(nxt - a, 65536)
                if size >= 4 and a - IMG_BASE + size <= len(self.img):
                    self.functions.append((a, strip(n), size))

    def words(self, a, size):
        o = a - IMG_BASE
        return list(struct.unpack_from('<%dI' % (size // 4), self.img, o))

    def name_at(self, va):
        k = bisect.bisect_right(self.uaddrs, va) - 1
        a = self.uaddrs[k]
        n = self.canon_at[a]
        return n if a == va else '%s+%#x' % (n, va - a)

    def canon(self, name):
        s = strip(name)
        return self.alias.get(s, s)

    def fingerprint(self, a, size):
        """(full digest, trimmed digest, nwords, sorted string hashes, norm words, call names) of the shipping function at address a."""
        ws = self.words(a, size)
        res = []
        for body in (ws, trim(ws)):
            norm, ctl, adds = normalize(body)
            res.append((norm, [self._target_name(a, i, body[i]) for i, kind, t in ctl], adds))
        strs = set()
        for i, pdelta, lo12, pi in res[0][2]:
            s = cstring(self.img, ((a + pi * 4) & ~0xfff) + (pdelta << 12) + lo12 - IMG_BASE)
            if s:
                strs.add(sh12(s))
        return (digest(res[0][0], res[0][1]), digest(res[1][0], res[1][1]), len(ws), sorted(strs), res[0][0], res[0][1])

    def _target_name(self, a, i, w):
        kind, d, _ = classify_word(w)
        return self.name_at(a + (i + d) * 4)


def alias_in_name(name, alias):
    s = strip(name)
    return alias.get(s, s)


class Obj:
    """A relocatable AArch64 ELF object: function symbols, their words, relocations."""

    def __init__(self, path):
        d = Path(path).read_bytes()
        self.path = str(path)
        if d[:4] != b'\x7fELF' or d[4] != 2:
            raise ValueError('not an ELF64 object')
        shoff, = struct.unpack_from('<Q', d, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from('<HHH', d, 0x3a)
        sh = []
        for i in range(shnum):
            n, t, fl, ad, off, sz, ln, inf, al, es = struct.unpack_from('<IIQQQQIIQQ', d, shoff + i * shentsize)
            sh.append(dict(name=n, type=t, flags=fl, off=off, size=sz, link=ln, info=inf, ent=es))

        def cs(sec, o):
            b = sh[sec]['off'] + o
            return d[b:d.index(b'\0', b)].decode('latin1')
        for s in sh:
            s['sname'] = cs(shstrndx, s['name'])
        self.sh, self.data = sh, d
        st = next((i for i, s in enumerate(sh) if s['type'] == 2), None)
        self.syms = []
        if st is not None:
            for k in range(sh[st]['size'] // 24):
                n, info, oth, shndx, val, size = struct.unpack_from('<IBBHQQ', d, sh[st]['off'] + k * 24)
                self.syms.append(dict(name=cs(sh[st]['link'], n), type=info & 15, bind=info >> 4, shndx=shndx, val=val, size=size))
        self.rels = {}
        for s in sh:
            if s['type'] == 4:
                r = self.rels.setdefault(s['info'], {})
                for k in range(s['size'] // 24):
                    o, info, add = struct.unpack_from('<QQq', d, s['off'] + k * 24)
                    r[o] = (info & 0xffffffff, self.syms[info >> 32], add)
        self.funcs = [s for s in self.syms if s['type'] == 2 and s['size'] >= 4 and 0 < s['shndx'] < len(sh)
                      and sh[s['shndx']]['flags'] & 4 and sh[s['shndx']]['type'] == 1]
        self.by_sec = {}
        for s in self.funcs:
            self.by_sec.setdefault(s['shndx'], []).append((s['val'], s['name']))
        for v in self.by_sec.values():
            v.sort()

    def sec_bytes(self, i):
        s = self.sh[i]
        return self.data[s['off']:s['off'] + s['size']]

    def func_words(self, f):
        b = self.sec_bytes(f['shndx'])
        return list(struct.unpack_from('<%dI' % (f['size'] // 4), b, f['val']))

    def name_in_section(self, shndx, off):
        v = self.by_sec.get(shndx, [])
        k = bisect.bisect_right([x for x, _ in v], off) - 1
        if k < 0:
            return None
        a, n = v[k]
        return n if a == off else '%s+%#x' % (n, off - a)

    def target_names(self, f, ctl, words):
        """Call/branch target names for the controls of function f (relocated: symbol/section+addend; unrelocated: position in the section)."""
        rel = self.rels.get(f['shndx'], {})
        out = []
        for i, kind, t in ctl:
            off = f['val'] + i * 4
            r = rel.get(off)
            if r is not None:
                typ, rs, add = r
                if rs['type'] == 3 and 0 < rs['shndx'] < len(self.sh):          # section symbol: function at the addend
                    out.append(self.name_in_section(rs['shndx'], add) or '?sec%d+%d' % (rs['shndx'], add))
                elif rs['shndx'] and rs['shndx'] < len(self.sh) and rs['type'] == 2 and add == 0:
                    out.append(rs['name'])
                else:
                    out.append(rs['name'] + ('' if add == 0 else '+%#x' % add))
            else:
                out.append(self.name_in_section(f['shndx'], f['val'] + t * 4) or '?')
        return out

    def strings(self, f, adds, words):
        """String hashes referenced by the function via relocated ADD lo12 (object side)."""
        rel = self.rels.get(f['shndx'], {})
        res = set()
        for i, pdelta, lo12, pi in adds:
            r = rel.get(f['val'] + i * 4)
            if not r or r[0] != 277:
                continue
            typ, rs, add = r
            if not (0 < rs['shndx'] < len(self.sh)) or not self.sh[rs['shndx']]['sname'].startswith('.rodata'):
                continue
            base = add if rs['type'] == 3 else rs['val'] + add
            s = cstring(self.sec_bytes(rs['shndx']), base)
            if s:
                res.add(sh12(s))
        return res

    def fingerprint(self, f, alias):
        ws = self.func_words(f)
        rel = {(o - f['val']) // 4: v for o, v in self.rels.get(f['shndx'], {}).items() if f['val'] <= o < f['val'] + f['size']}
        out = []
        for body in (ws, trim(ws)):
            norm, ctl, adds = normalize(body, {k: v for k, v in rel.items() if k < len(body)})
            names = [alias_in_name(x, alias) for x in self.target_names(f, ctl, body)]
            out.append(digest(norm, names))
        norm, ctl, adds = normalize(ws, rel)
        return out[0], out[1], len(ws), sorted(self.strings(f, adds, ws)), norm, ctl


def explain(obj_norm, obj_names, ship_norm, ship_names):
    """Classify the first normalized difference between an object function and the closest shipping instance; also report call-name multiset differences."""
    from collections import Counter
    co, cs = Counter(obj_names), Counter(ship_names)
    extra = {'calls_only_in_object': sorted((co - cs).elements())[:8], 'calls_only_in_shipping': sorted((cs - co).elements())[:8]}
    if obj_norm == ship_norm:
        return dict({'class': 'call-target-only' if obj_names != ship_names else 'identical', 'index': None}, **extra)
    if len(obj_norm) != len(ship_norm):
        return dict({'class': 'instruction-count', 'object_words': len(obj_norm), 'shipping_words': len(ship_norm),
                     'index': next((i for i, (a, b) in enumerate(zip(obj_norm, ship_norm)) if a != b), min(len(obj_norm), len(ship_norm)))}, **extra)
    diffs = [i for i, (a, b) in enumerate(zip(obj_norm, ship_norm)) if a != b]
    if sorted(obj_norm) == sorted(ship_norm):
        return dict({'class': 'reordering', 'index': diffs[0], 'differing_words': len(diffs)}, **extra)
    i = diffs[0]
    x = obj_norm[i] ^ ship_norm[i]
    if x & 0xff000000 and (x & ~0x001f03ff):
        k = 'opcode/control-flow'
    elif x & ~0x001f03ff == 0:
        k = 'register-allocation'
    elif x & 0x001f03ff == 0:
        k = 'immediate-constant'
    else:
        k = 'mixed'
    return dict({'class': k, 'index': i, 'differing_words': len(diffs), 'object_word': '%08x' % obj_norm[i], 'shipping_word': '%08x' % ship_norm[i]}, **extra)
