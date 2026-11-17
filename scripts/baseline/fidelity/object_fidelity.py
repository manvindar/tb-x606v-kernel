#!/usr/bin/env python3
"""Per-function fidelity of built kernel objects against the shipping image fingerprints.
usage: object_fidelity.py DB.json RECEIPT.json OBJ_OR_DIR [OBJ_OR_DIR ...] [--explain IMAGE KALLSYMS] [--root DIR] [--expect EXPECT.json]
Every function symbol of every .o is fingerprinted exactly like the shipping functions (README: normalization) and looked up by name:
  equal            digest (full or trailing-nop-trimmed) is one of the shipping digests of that name
  equal_ambiguous  equal, but the name exists more than once in the shipping image (static name shared by several files): may be another instance
  different        name exists in the shipping image, no digest equal
  absent           name not in the shipping image (inlined away, renamed, or not part of the shipping build)
Per object the file verdict is ALL-EQUAL (functions>0, all equal), PARTIAL, or NONE-EQUAL. With --explain (needs the private image) each 'different'
function is classified against the closest shipping instance (identical / call-target-only / instruction-count / reordering / register-allocation /
immediate-constant / opcode/control-flow / mixed). --expect maps an object path suffix to {require:[funcs], allow_absent:[funcs], allow_different:[funcs]} and adds a PASS/FAIL
expectation to that object (e.g. a recovered unit must be fully equal; __exit functions are not in a built-in image). Objects that fail to parse are listed under 'unreadable'. Exit 0 always when the DB loads: this is evidence."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fidelity_lib as L


def collect(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            for r, _, fs in os.walk(p):
                out += [os.path.join(r, f) for f in fs if f.endswith('.o')]
        else:
            out.append(p)
    return sorted(out)


def min_window(lists):
    """Smallest address window containing one candidate address from every list: (lo, hi, chosen) or None."""
    lists = [sorted(l) for l in lists if l]
    if not lists:
        return None
    pts = sorted((a, i) for i, l in enumerate(lists) for a in l)
    need, have, best, left = len(lists), {}, None, 0
    for right, (a, i) in enumerate(pts):
        have[i] = have.get(i, 0) + 1
        while len(have) == need:
            span = a - pts[left][0]
            if best is None or span < best[0]:
                best = (span, pts[left][0], a)
            j = pts[left][1]
            have[j] -= 1
            if not have[j]:
                del have[j]
            left += 1
    return best


def run(db, objs, root='', shipping=None, expect=None):
    fn, alias = db['fn'], db['alias']
    rows, unreadable = [], []
    by_dir = {}
    for p in objs:
        try:
            o = L.Obj(p)
        except Exception as e:
            unreadable.append({'object': p, 'error': str(e)[:120]})
            continue
        row = {'object': os.path.relpath(p, root) if root else p, 'functions': 0, 'equal': 0, 'equal_ambiguous': 0, 'different': 0, 'absent': 0, 'detail': {}}
        for f in o.funcs:
            full, trm, nw, strs, norm, ctl = o.fingerprint(f, alias)
            row['functions'] += 1
            ent = fn.get(L.strip(f['name']))
            if not ent:
                row['absent'] += 1
                row['detail'][f['name']] = {'verdict': 'absent'}
                continue
            hit = [e for e in ent if full in (e[0], e[1]) or trm in (e[0], e[1] or e[0])]
            if hit:
                amb = len(ent) > 1
                row['equal_ambiguous' if amb else 'equal'] += 1
                sset = set(hit[0][3].split(',')) - {''}
                row['detail'][f['name']] = {'verdict': 'equal_ambiguous' if amb else 'equal', 'words': nw,
                                            'strings_in_shipping': set(strs) <= sset, 'shipping_va': [e[4] for e in hit if len(e) > 4]}
            else:
                row['different'] += 1
                d = {'verdict': 'different', 'words': nw, 'shipping_instances': [e[2] for e in ent]}
                if shipping:
                    words = o.func_words(f)
                    names = [L.alias_in_name(x, alias) for x in o.target_names(f, ctl, words)]
                    best = None
                    for a, n, size in shipping.functions:
                        if n != L.strip(f['name']):
                            continue
                        sf = shipping.fingerprint(a, size)
                        ex = L.explain(norm, names, sf[4], sf[5])
                        score = (ex['class'] == 'instruction-count', abs(len(sf[4]) - len(norm)), ex.get('differing_words', 0))
                        if best is None or score < best[0]:
                            best = (score, ex)
                    d['explain'] = best[1] if best else None
                row['detail'][f['name']] = d
        vas = sorted(int(x, 16) for d in row['detail'].values() for x in d.get('shipping_va', [])[:1] if d.get('verdict') == 'equal')
        row['va_span_of_unambiguous_matches'] = ['%x' % vas[0], '%x' % vas[-1]] if vas else None
        wl = [[int(x, 16) for x in d['shipping_va']] for d in row['detail'].values() if d.get('verdict', '').startswith('equal') and d.get('shipping_va')]
        mw = min_window(wl)
        row['single_region'] = {'functions_in_window': len(wl), 'span_bytes': mw[0], 'lo': '%x' % mw[1], 'hi': '%x' % mw[2]} if mw else None
        row['verdict'] = 'ALL-EQUAL' if row['functions'] and row['equal'] + row['equal_ambiguous'] == row['functions'] else \
            'NONE-EQUAL' if row['functions'] and not (row['equal'] + row['equal_ambiguous']) else 'PARTIAL' if row['functions'] else 'NO-FUNCTIONS'
        for suffix, ex in (expect or {}).items():
            if row['object'].endswith(suffix):
                bad = {k: d['verdict'] for k, d in row['detail'].items()
                       if not d['verdict'].startswith('equal') and not (d['verdict'] == 'absent' and k in ex.get('allow_absent', []))
                       and not (d['verdict'] == 'different' and k in ex.get('allow_different', []))}
                missing = [k for k in ex.get('require', []) if k not in row['detail']]
                row['expectation'] = {'status': 'PASS' if not bad and not missing else 'FAIL', 'unexpected': bad, 'required_but_missing': missing}
        rows.append(row)
        d = by_dir.setdefault(os.path.dirname(row['object']), {'objects': 0, 'functions': 0, 'equal': 0, 'different': 0, 'absent': 0})
        d['objects'] += 1
        d['functions'] += row['functions']
        d['equal'] += row['equal'] + row['equal_ambiguous']
        d['different'] += row['different']
        d['absent'] += row['absent']
    tot = {k: sum(r[k] for r in rows) for k in ('functions', 'equal', 'equal_ambiguous', 'different', 'absent')}
    return {'evidence_class': 'function-normalized-instruction-equality', 'source_identity': 'unproved', 'db': db['meta'], 'totals': tot,
            'directories': by_dir, 'objects': rows, 'unreadable': unreadable}


if __name__ == '__main__':
    a = sys.argv[1:]
    shipping = root = expect = None
    if '--explain' in a:
        i = a.index('--explain')
        shipping = L.Shipping(a[i + 1], a[i + 2])
        del a[i:i + 3]
    if '--expect' in a:
        i = a.index('--expect')
        expect = json.load(open(a[i + 1]))
        del a[i:i + 2]
    if '--root' in a:
        i = a.index('--root')
        root = a[i + 1]
        del a[i:i + 2]
    import gzip
    db = json.load((gzip.open if a[0].endswith('.gz') else open)(a[0], 'rt'))
    r = run(db, collect(a[2:]), root or '', shipping, expect)
    json.dump(r, open(a[1], 'w'), indent=1)
    print(json.dumps(r['totals']), 'objects', len(r['objects']), 'unreadable', len(r['unreadable']))
    for row in r['objects']:
        print('%-12s %-60s fn=%d eq=%d amb=%d diff=%d abs=%d %s' % (row['verdict'], row['object'][-60:], row['functions'], row['equal'], row['equal_ambiguous'], row['different'], row['absent'], row.get('expectation', {}).get('status', '')))
