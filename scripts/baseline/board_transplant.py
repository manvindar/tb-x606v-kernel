#!/usr/bin/env python3
"""Install the pinned Lenovo-drop peripheral units into the candidate tree and wire them into Kconfig/Makefiles, verified per file.

usage: board_transplant.py LENOVO_CHECKOUT KERNEL_TREE PINS.json RECEIPT.json [NAME=CHECKOUT ...]
A unit or file may name another donor ("donor": NAME, checkout given as NAME=CHECKOUT, pinned in PINS "donors": {NAME: {repo, sha}}; its HEAD must be that sha).
A recovered file may carry "replaces": BLOB to overwrite an existing file, only if the destination currently has exactly that blob.
PINS.json lists (a) directory units (whole dirs, per-file blob manifest), (b) single files, (b2) recovered files kept in this repo (pinned by blob id), (c) a hooks file: insert-only / delete-line edits of
target files, each guarded by the pre-edit and post-edit git blob id. Nothing is written unless every check passes first:
the destination of a unit or file must not exist, every source blob must match its pin, every hook anchor must occur exactly once and the
edited file must hash to the pinned post-edit blob. Reports, never repairs."""
import hashlib, json, shutil, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import camera_transplant as ct


def blob(b):
    return hashlib.sha1(b'blob %d\0' % len(b) + b).hexdigest()


def apply_ops(text, ops):
    lines = text.split('\n')
    for o in ops:
        if o['op'] == 'insert_after':
            a = o['anchor_lines']
            k = len(a)
            hits = [j for j in range(len(lines) - k + 1) if lines[j:j + k] == a]
            if len(hits) != 1:
                raise ValueError(f'anchor {a!r} occurs {len(hits)} times')
            lines[hits[0] + k:hits[0] + k] = o['insert'].rstrip('\n').split('\n')
        elif o['op'] == 'delete_line':
            hits = [j for j, x in enumerate(lines) if x == o['line']]
            if len(hits) != 1:
                raise ValueError(f"line {o['line']!r} occurs {len(hits)} times")
            del lines[hits[0]]
        else:
            raise ValueError(f"unknown op {o['op']}")
    return '\n'.join(lines)


def donor_dir(default, donors, item):
    if not item.get('donor'):
        return default
    if item['donor'] not in donors:
        raise ValueError(f"donor {item['donor']!r} has no checkout")
    return donors[item['donor']]


def donor_heads(pins, donors):
    """Receipt of every extra donor: its HEAD must be the pinned sha."""
    import subprocess
    out = {}
    for n, d in pins.get('donors', {}).items():
        head = subprocess.run(['git', '-C', str(donors.get(n, '/nonexistent')), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
        out[n] = {'repo': d['repo'], 'pinned': d['sha'], 'head': head, 'ok': head == d['sha']}
    return out


def plan(lenovo, tree, pins, hooks, base, donors=None):
    """Check everything, return (receipt, writes) where writes is a list of ('dir'|'file'|'text', dst, src_or_bytes)."""
    default, tree = Path(lenovo), Path(tree)
    donors = {k: Path(v) for k, v in (donors or {}).items()}
    rec = {'target': pins['target'], 'source': pins['source'], 'units': [], 'files': [], 'recovered': [], 'hooks': [], 'blocked': pins['blocked']}
    rec['donors'] = donor_heads(pins, donors)
    writes = []
    for u in pins['units']:
        lenovo = donor_dir(default, donors, u)
        manifest = json.loads((Path(base) / u['manifest']).read_text())
        chk = ct.verify(lenovo, u['path'], manifest) if (lenovo / u['path']).is_dir() else None
        exists = (tree / u['path']).exists()
        ok = chk is not None and ct.clean(chk) and len(manifest) == u['files'] and not exists
        rec['units'].append({'path': u['path'], 'serves': u['serves'], 'files': len(manifest), 'source_check': chk, 'destination_exists': exists, 'ok': ok})
        if ok:
            writes.append(('dir', tree / u['path'], lenovo / u['path']))
    for f in pins['files']:
        src, dst = donor_dir(default, donors, f) / f['path'], tree / f['path']
        got = blob(src.read_bytes()) if src.is_file() else None
        ok = got == f['blob'] and not dst.exists()
        rec['files'].append({'path': f['path'], 'serves': f['serves'], 'blob': got, 'pinned': f['blob'], 'destination_exists': dst.exists(), 'ok': ok})
        if ok:
            writes.append(('file', dst, src))
    for f in pins.get('recovered_files', []):   # files shipped in this repo (recovered from the shipping image), pinned by blob id
        src, dst = Path(base) / f['bundle'], tree / f['path']
        got = blob(src.read_bytes()) if src.is_file() else None
        if f.get('replaces'):     # overwrite only the exact pinned original
            dest_ok = dst.is_file() and blob(dst.read_bytes()) == f['replaces']
        else:
            dest_ok = not dst.exists()
        ok = got == f['blob'] and dest_ok
        rec['recovered'].append({'path': f['path'], 'unit': f['unit'], 'blob': got, 'pinned': f['blob'], 'replaces': f.get('replaces'), 'destination_exists': dst.exists(), 'ok': ok})
        if ok:
            writes.append(('file', dst, src))
    for h in hooks:
        p = tree / h['file']
        entry = {'file': h['file'], 'ops': len(h['ops']), 'ok': False}
        rec['hooks'].append(entry)
        if not p.is_file():
            entry['error'] = 'target file missing'
            continue
        pre = p.read_bytes()
        entry['pre_blob'] = blob(pre)
        if entry['pre_blob'] != h['pre_blob']:
            entry['error'] = f"pre-edit blob {entry['pre_blob']} != pin {h['pre_blob']}"
            continue
        try:
            post = apply_ops(pre.decode(), h['ops']).encode()
        except ValueError as e:
            entry['error'] = str(e)
            continue
        entry['post_blob'] = blob(post)
        if entry['post_blob'] != h['post_blob']:
            entry['error'] = f"post-edit blob {entry['post_blob']} != pin {h['post_blob']}"
            continue
        entry['ok'] = True
        writes.append(('text', p, post))
    rec['ok'] = all(x['ok'] for k in ('units', 'files', 'recovered', 'hooks') for x in rec[k]) and all(d['ok'] for d in rec['donors'].values())
    return rec, writes


def run(lenovo, tree, pins, hooks, base='.', donors=None):
    rec, writes = plan(lenovo, tree, pins, hooks, base, donors)
    if rec['ok']:
        for kind, dst, src in writes:
            if kind == 'dir':
                shutil.copytree(src, dst)
            elif kind == 'file':
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dst)
            else:
                dst.write_bytes(src)
        for u in pins['units']:   # installed trees must hash to the manifest again
            after = ct.verify(tree, u['path'], json.loads((Path(base) / u['manifest']).read_text()))
            rec['units'][[x['path'] for x in rec['units']].index(u['path'])]['tree_check'] = after
            rec['ok'] = rec['ok'] and ct.clean(after)
    return rec


if __name__ == '__main__':
    lenovo, tree, pins_path, out = sys.argv[1:5]
    donors = dict(a.split('=', 1) for a in sys.argv[5:])
    pins = json.loads(Path(pins_path).read_text())
    base = Path(pins_path).resolve().parents[2]
    hooks = json.loads((base / pins['hooks']).read_text())
    r = run(lenovo, tree, pins, hooks, base, donors)
    Path(out).write_text(json.dumps(r, indent=1))
    bad = [(k, x.get('path') or x.get('file'), x.get('error')) for k in ('units', 'files', 'recovered', 'hooks') for x in r[k] if not x['ok']]
    print('ok' if r['ok'] else f'FAIL {bad}')
    sys.exit(0 if r['ok'] else 1)
