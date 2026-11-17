#!/usr/bin/env python3
"""Export-CRC accounting of a candidate against the shipping kernel, compared with a pinned accounting.

usage: export_accounting.py MODULE.symvers SHIPPING_EXPORT_CRCS.json PINNED.json REPORT.json
mismatch = a name exported by both with a different CRC; absent = a shipping export the candidate does not export.
The pinned file records the accounting of a measured run; this tool reports whether the sets and CRCs are unchanged, which names are new or resolved, and how
many candidate-only exports exist (not a mismatch: the shipping kernel does not export them). It judges nothing about layout or behaviour: a CRC is a prototype/layout
hash of the headers, not a runtime identity. Exit 0 = identical to the pin, 1 = changed (the report lists every difference)."""
import json, sys


def load_symvers(path):
    out = {}
    for l in open(path, errors='ignore'):
        f = l.rstrip('\n').split('\t')
        if len(f) >= 2:
            out[f[1]] = int(f[0], 16)
    return out


def account(sym, ship):
    mismatch = {n: [sym[n], ship[n]] for n in sorted(ship) if n in sym and sym[n] != ship[n]}
    absent = sorted(n for n in ship if n not in sym)
    return mismatch, absent


def compare(sym, ship, pin):
    mm, ab = account(sym, ship)
    pm = {n: [v['candidate'], v['shipping']] for n, v in pin['mismatch'].items()}
    pa = set(pin['absent'])
    rep = {'mismatch': len(mm), 'absent': len(ab), 'pinned_mismatch': len(pm), 'pinned_absent': len(pa),
           'new_mismatch': sorted(set(mm) - set(pm)), 'resolved_mismatch': sorted(set(pm) - set(mm)),
           'crc_changed_within_mismatch': sorted(n for n in mm if n in pm and mm[n] != pm[n]),
           'new_absent': sorted(set(ab) - pa), 'resolved_absent': sorted(pa - set(ab)),
           'candidate_only_exports': len(set(sym) - set(ship)),
           'mismatch_by_class': {c: sum(1 for n in mm if pin['mismatch'].get(n, {}).get('class', 'NEW') == c) for c in sorted({v['class'] for v in pin['mismatch'].values()} | {'NEW'})}}
    rep['unchanged'] = not (rep['new_mismatch'] or rep['resolved_mismatch'] or rep['crc_changed_within_mismatch'] or rep['new_absent'] or rep['resolved_absent'])
    return rep


if __name__ == '__main__':
    symvers, shipping, pinned, out = sys.argv[1:5]
    rep = compare(load_symvers(symvers), json.load(open(shipping))['shipping_export_crcs'], json.load(open(pinned)))
    json.dump(rep, open(out, 'w'), indent=1)
    print(json.dumps({k: v for k, v in rep.items() if not isinstance(v, list)}), {k: len(v) for k, v in rep.items() if isinstance(v, list) and v})
    sys.exit(0 if rep['unchanged'] else 1)
