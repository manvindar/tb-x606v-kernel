#!/usr/bin/env python3
"""Receipt of how far a built .config drifted from the pinned stock config (symbols the tree dropped, changed or added).
usage: config_drift.py STOCK.config BUILT.config OUT.json"""
import hashlib, json, re, sys
from pathlib import Path


def load(path):
    d = {}
    for line in Path(path).read_text().splitlines():
        m = re.match(r'(CONFIG_\w+)=(.*)$', line) or re.match(r'# (CONFIG_\w+) is not set$', line)
        if m:
            d[m[1]] = m[2] if '=' in line else 'n'
    return d


def drift(stock, built):
    a, b = load(stock), load(built)
    return dict(stock_sha256=hashlib.sha256(Path(stock).read_bytes()).hexdigest(),
                built_sha256=hashlib.sha256(Path(built).read_bytes()).hexdigest(),
                stock_symbols=len(a), built_symbols=len(b),
                changed={k: [a[k], b[k]] for k in sorted(a) if k in b and a[k] != b[k]},
                dropped={k: a[k] for k in sorted(a) if k not in b and a[k] != 'n'},
                added={k: b[k] for k in sorted(b) if k not in a and b[k] != 'n'})


if __name__ == '__main__':
    r = drift(sys.argv[1], sys.argv[2])
    Path(sys.argv[3]).write_text(json.dumps(r, indent=1))
    print({k: (len(v) if isinstance(v, dict) else v) for k, v in r.items()})
