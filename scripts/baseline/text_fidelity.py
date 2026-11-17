#!/usr/bin/env python3
"""Symbol-layout receipt for the camera sensor drivers: compare the candidate vmlinux's sensor symbol region with the shipping kernel's.

usage: text_fidelity.py SHIPPING_SYMBOLS.json NM_N_OUTPUT.txt RECEIPT.json
SHIPPING_SYMBOLS.json lists, in link order, every symbol of the sensor region with its delta (size + padding) to the next symbol.
NM_N_OUTPUT is `nm -n vmlinux` of the candidate. Both regions are split into per-sensor blocks at the '*_SensorInit' exported symbols, and each block is
compared by symbol-name sequence and per-symbol delta (size plus padding).
Equal names and equal deltas establish a MATCHING SYMBOL LAYOUT only (status 'matching-symbol-layout'). They do not show identical code or exact source:
different instructions, constants and register tables can have identical lengths. Every block therefore carries source_identity='unproved'.
Source or behavior evidence needs a normalized instruction/control-flow comparison plus the referenced register/data tables, accounting for
relocations and compiler differences; this receipt does none of that. A different block is a reported difference, never a failure by itself.
Exit 0 always when the files parse; the receipt is evidence for the reviewer, not a gate."""
import json, re, sys


def blocks(seq):
    out, cur = {}, None
    for name, delta in seq:
        if name.endswith('MIPI_RAW_SensorInit'):
            cur = name
            out[cur] = []
        if cur is not None:
            out[cur].append((name, delta))
    return out


def candidate_region(nm_lines, stop='imgsensor_dfs_ctrl'):
    syms = []
    for l in nm_lines:
        f = l.split()
        if len(f) == 3 and re.fullmatch(r'[0-9a-fA-F]+', f[0]):
            syms.append((int(f[0], 16), f[2], f[1]))
    syms = [s for s in syms if s[2] in 'tTwW']
    names = [s[1] for s in syms]
    if stop not in names:
        raise ValueError(f'{stop} not found in nm output')
    end = names.index(stop)
    starts = [i for i, n in enumerate(names[:end]) if n.endswith('MIPI_RAW_SensorInit')]
    if not starts:
        return []
    # a sensor's static functions precede or follow its Init depending on link order; the shipping region starts at an Init symbol
    return [(syms[i][1], syms[i + 1][0] - syms[i][0]) for i in range(starts[0], end)]


def compare(shipping, cand):
    sb, cb = blocks(shipping), blocks(cand)
    res = {}
    for init, rows in sb.items():
        c = cb.get(init)
        if c is None:
            res[init] = {'status': 'absent-in-candidate'}
        elif c == rows:
            res[init] = {'status': 'matching-symbol-layout', 'symbols': len(rows)}
        elif [n for n, _ in c] == [n for n, _ in rows]:
            res[init] = {'status': 'same-symbols-different-sizes',
                         'differences': [{'symbol': n, 'shipping': d, 'candidate': cd} for (n, d), (_, cd) in zip(rows, c) if d != cd]}
        else:
            res[init] = {'status': 'different-symbols', 'shipping': [n for n, _ in rows], 'candidate': [n for n, _ in c]}
    for v in res.values():
        v['source_identity'] = 'unproved'
    extra = sorted(set(cb) - set(sb))
    return {'evidence_class': 'symbol-layout', 'source_identity': 'unproved', 'blocks': res, 'extra_in_candidate': extra,
            'summary': {s: sum(1 for v in res.values() if v['status'] == s) for s in
                        ('matching-symbol-layout', 'same-symbols-different-sizes', 'different-symbols', 'absent-in-candidate')}}


if __name__ == '__main__':
    ship = json.load(open(sys.argv[1]))
    cand = candidate_region(open(sys.argv[2]).read().splitlines())
    r = compare([(x['name'], x['delta']) for x in ship['region']], cand)
    json.dump(r, open(sys.argv[3], 'w'), indent=1)
    print(r['summary'])
