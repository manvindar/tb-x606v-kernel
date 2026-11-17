#!/usr/bin/env python3
"""Replace the camera units of a candidate kernel tree with the pinned Lenovo-drop units, verified per file.

usage: camera_transplant.py LENOVO_CHECKOUT KERNEL_TREE PINS.json RECEIPT.json
Every file of every unit is checked against its pinned git blob id before and after the copy; extra or missing files fail."""
import hashlib, json, shutil, sys
from pathlib import Path


def blob_id(p):
    b = Path(p).read_bytes()
    return hashlib.sha1(b'blob %d\0' % len(b) + b).hexdigest()


def verify(root, unit, manifest):
    base = Path(root) / unit
    want = {k: v['blob'] for k, v in manifest.items()}
    have = {str(p.relative_to(root)): blob_id(p) for p in base.rglob('*') if p.is_file()}
    return {'files': len(have), 'missing': sorted(set(want) - set(have)), 'extra': sorted(set(have) - set(want)),
            'mismatch': sorted(k for k in want if k in have and have[k] != want[k])}


def clean(check):
    return check is not None and not any(check[k] for k in ('missing', 'extra', 'mismatch'))


def transplant(lenovo, tree, pins, base='.'):
    receipt = {'source': pins['source'], 'known_gaps': pins['known_gaps'], 'units': []}
    for u in pins['units']:
        manifest = json.loads((Path(base) / u['manifest']).read_text())
        assert len(manifest) == u['files'], f"manifest for {u['path']} has {len(manifest)} files, pin says {u['files']}"
        before = verify(lenovo, u['path'], manifest)
        dst = Path(tree) / u['path']
        replaced = sum(1 for p in dst.rglob('*') if p.is_file()) if dst.exists() else 0
        after = None
        if clean(before):
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(Path(lenovo) / u['path'], dst)
            after = verify(tree, u['path'], manifest)
        receipt['units'].append({'path': u['path'], 'git_tree': u['git_tree'], 'source_check': before, 'tree_check': after,
                                 'replaced_files': replaced, 'installed_files': after['files'] if after else 0, 'ok': clean(after)})
    receipt['ok'] = all(u['ok'] for u in receipt['units'])
    return receipt


if __name__ == '__main__':
    lenovo, tree, pins_path, out = sys.argv[1:5]
    pins = json.loads(Path(pins_path).read_text())
    r = transplant(lenovo, tree, pins, base=Path(pins_path).resolve().parents[2])
    Path(out).write_text(json.dumps(r, indent=1))
    print(json.dumps({'ok': r['ok'], 'units': [(u['path'], u['installed_files'], u['ok']) for u in r['units']]}))
    sys.exit(0 if r['ok'] else 1)
