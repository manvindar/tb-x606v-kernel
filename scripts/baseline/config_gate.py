#!/usr/bin/env python3
"""Gate on the .config the tree actually produces, against the pinned stock config.

usage: config_gate.py STOCK.config BUILT.config PINS.json OVERLAY.json RECEIPT.json [KERNEL_TREE]
Every stock symbol must survive olddefconfig unchanged. A dropped symbol is accepted only as an explicitly blocked or no-code gap listed in PINS,
and then the status is BLOCKED (exit 3), never OK. A symbol the tree adds is accepted only if the overlay lists it as a neutral constant at that value.
Exit 0 OK, 1 FAIL (unexplained drop, change or addition), 3 BLOCKED (only listed gaps remain)."""
import json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config_drift import drift


def gate(stock, built, pins, overlay, tree=None):
    d = drift(stock, built)
    still = [b for b in pins['blocked'] if tree is None or not (Path(tree) / b['expect_path']).exists()]
    listed = {b['config']: ('blocked', b['id']) for b in still if b['config'].startswith('CONFIG_') and b['config'] != 'CONFIG_CUSTOM_KERNEL_IMGSENSOR'
              and b['config'] != 'CONFIG_CUSTOM_KERNEL_LCM'}
    listed.update({g['config']: ('no-code-in-shipping', g['evidence']) for g in pins['no_code_in_shipping']})
    neutral = {f"CONFIG_{n['symbol']}": n['value'] for n in overlay['neutral_constants']}
    r = {'changed': d['changed'], 'unexplained_dropped': {}, 'listed_dropped': {}, 'unexplained_added': {}, 'neutral_added': {}}
    for k, v in d['dropped'].items():
        (r['listed_dropped'] if k in listed else r['unexplained_dropped'])[k] = listed.get(k, v)
    for k, v in d['added'].items():
        (r['neutral_added'] if neutral.get(k) == v else r['unexplained_added'])[k] = v
    r['status'] = 'FAIL' if (r['changed'] or r['unexplained_dropped'] or r['unexplained_added']) else \
        'BLOCKED' if (r['listed_dropped'] or still) else 'OK'
    r['open_blocked'] = [b['id'] for b in still]
    r['summary'] = {k: len(v) for k, v in r.items() if isinstance(v, (dict, list))}
    return r


if __name__ == '__main__':
    stock, built, pins, overlay, out = sys.argv[1:6]
    r = gate(stock, built, json.loads(Path(pins).read_text()), json.loads(Path(overlay).read_text()), sys.argv[6] if len(sys.argv) > 6 else None)
    Path(out).write_text(json.dumps(r, indent=1))
    print(r['status'], r['summary'])
    sys.exit({'OK': 0, 'FAIL': 1, 'BLOCKED': 3}[r['status']])
