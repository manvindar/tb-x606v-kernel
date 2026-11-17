#!/usr/bin/env python3
"""Move the display core of the target tree to the generation of the shipping panels, file by file, pinned by git blob id.

usage: display_core.py AMAR_CHECKOUT KERNEL_TREE PINS.json RECEIPT.json
PINS lists files (path, old blob in the target tree, new blob in the source checkout). Nothing is written unless every check passes first:
the source HEAD is the pinned commit, every source blob matches its pin, every target file hashes to its pinned old blob. After writing, every
target file is hashed again. Files in `kept` and `not_installed` are only checked (they must still hash to their pinned old blob). Reports, never repairs.
Exit 0 only when everything matched."""
import hashlib, json, subprocess, sys
from pathlib import Path


def blob(b):
    return hashlib.sha1(b'blob %d\0' % len(b) + b).hexdigest()


def plan(src, tree, pins):
    src, tree = Path(src), Path(tree)
    head = subprocess.run(['git', '-C', str(src), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
    rec = {'source': pins['source'], 'source_head': head, 'source_ok': head == pins['source']['sha'], 'files': [], 'kept': [], 'not_installed': []}
    writes = []
    for f in pins['files']:
        s, t = src / f['path'], tree / f['path']
        sb = blob(s.read_bytes()) if s.is_file() else None
        tb = blob(t.read_bytes()) if t.is_file() else None
        ok = sb == f['new'] and tb == f['old']
        rec['files'].append({'path': f['path'], 'source_blob': sb, 'pinned_new': f['new'], 'tree_blob': tb, 'pinned_old': f['old'], 'ok': ok})
        if ok:
            writes.append((t, s))
    for k, key in (('kept', 'old'), ('not_installed', 'blob')):
        for f in pins[k]:
            t = tree / f['path']
            tb = blob(t.read_bytes()) if t.is_file() else None
            rec[k].append({'path': f['path'], 'tree_blob': tb, 'pinned': f[key], 'ok': tb == f[key]})
    rec['ok'] = rec['source_ok'] and all(x['ok'] for k in ('files', 'kept', 'not_installed') for x in rec[k])
    return rec, writes


def run(src, tree, pins):
    rec, writes = plan(src, tree, pins)
    if rec['ok']:
        for t, s in writes:
            t.write_bytes(s.read_bytes())
        for f, r in zip(pins['files'], rec['files']):
            r['after_blob'] = blob((Path(tree) / f['path']).read_bytes())
            r['ok'] = r['ok'] and r['after_blob'] == f['new']
        rec['ok'] = all(r['ok'] for r in rec['files'])
    return rec


if __name__ == '__main__':
    src, tree, pins_path, out = sys.argv[1:5]
    r = run(src, tree, json.loads(Path(pins_path).read_text()))
    Path(out).write_text(json.dumps(r, indent=1))
    bad = [(k, x['path']) for k in ('files', 'kept', 'not_installed') for x in r[k] if not x['ok']]
    print('ok' if r['ok'] else f"FAIL source_ok={r['source_ok']} {bad[:10]}")
    sys.exit(0 if r['ok'] else 1)
