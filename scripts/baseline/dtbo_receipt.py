#!/usr/bin/env python3
"""Receipt of the device-tree diagnostic build (philmb achilles6_row_call: dts + DrvGen from the .dws + the base tree, merged by ufdt_apply_overlay).

usage: dtbo_receipt.py SRC_TREE BUILD_OUT PINS.json DTBS_EXIT RECEIPT.json
Records, never judges: the git blob id of every input against its pin (a mismatch means the build did not use the pinned inputs), the git tree id of the DrvGen directory,
size and sha256 of each pinned output and of every generated cust*.dtsi, and whether the base tree equals the retained carrier's appended base DTB.
Exit 0 = inputs match their pins and every pinned output exists (so the files can be compared offline); 1 otherwise. Whether the overlay matches the unit is decided offline
against the unit's live tree, never here."""
import hashlib, json, subprocess, sys
from pathlib import Path


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def git_blob(p):
    return subprocess.run(['git', 'hash-object', str(p)], capture_output=True, text=True).stdout.strip()


def git_tree(src, rel):
    return subprocess.run(['git', '-C', str(src), 'rev-parse', f'HEAD:{rel}'], capture_output=True, text=True).stdout.strip()


def receipt(src, out, pins, dtbs_exit):
    src, out = Path(src), Path(out)
    inputs = {rel: {'pinned': blob, 'blob': git_blob(src / rel) if (src / rel).is_file() else None} for rel, blob in pins['inputs_blob'].items()}
    for v in inputs.values(): v['ok'] = v['blob'] == v['pinned']
    dt = {'pinned': pins['drvgen_tree']['git_tree'], 'tree': git_tree(src, pins['drvgen_tree']['path'])}
    dt['ok'] = dt['tree'] == dt['pinned']
    outs = {}
    for rel in pins['outputs']:
        p = out / rel
        outs[rel] = {'exists': p.is_file(), 'bytes': p.stat().st_size if p.is_file() else None, 'sha256': sha256(p) if p.is_file() else None}
    gen = {str(p.relative_to(out)): {'bytes': p.stat().st_size, 'sha256': sha256(p)} for p in sorted(out.rglob('cust*.dtsi'))}
    base = outs.get(next((r for r in pins['outputs'] if r.endswith('/mt6765.dtb')), ''), {})
    rec = {'dtbs_exit': int(dtbs_exit), 'inputs': inputs, 'drvgen_tree': dt, 'outputs': outs, 'generated_cust_dtsi': gen,
           'base_dtb_equals_carrier_base': base.get('sha256') == pins['carrier_base_dtb_sha256'] if base.get('sha256') else None,
           'carrier_base_dtb_sha256': pins['carrier_base_dtb_sha256'], 'not_claimed': pins['not_claimed']}
    rec['ok'] = all(v['ok'] for v in inputs.values()) and dt['ok'] and all(o['exists'] for o in outs.values())
    return rec


if __name__ == '__main__':
    src, out, pins, ex, dst = sys.argv[1:6]
    r = receipt(src, out, json.loads(Path(pins).read_text()), ex)
    Path(dst).write_text(json.dumps(r, indent=1))
    print(json.dumps({k: r[k] for k in ('dtbs_exit', 'ok', 'base_dtb_equals_carrier_base')}), {k: v['ok'] for k, v in r['inputs'].items()})
    sys.exit(0 if r['ok'] else 1)
