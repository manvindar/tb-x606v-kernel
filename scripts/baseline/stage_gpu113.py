#!/usr/bin/env python3
"""Stage the pinned PowerVR DDK 1.13 kernel driver (m1.13ED5776728) next to the shipping 1.11 driver of the target tree, for a SCOPED object compile only.

usage: stage_gpu113.py DONOR_CHECKOUT KERNEL_TREE PINS.json RECEIPT.json
Nothing is written unless every check passes: the donor HEAD is the pinned commit, the donor driver subtree has the pinned git tree id and no symlink, the target
selector Makefile (drivers/misc/mediatek/gpu/gpu_rgx/Makefile) has its pinned blob id, the destination does not exist, and every edited file hashes to its pinned
pre-edit and post-edit blob id. The selector Makefile is NOT edited: the 1.13 driver is not part of the Image; it is only reachable as its own directory target,
so a global image or link success proves nothing about it. Reports, never repairs. Exit 0 only if everything matched."""
import hashlib, json, shutil, subprocess, sys
from pathlib import Path


def blob(b):
    return hashlib.sha1(b'blob %d\0' % len(b) + b).hexdigest()


def git(repo, *a):
    return subprocess.run(['git', '-C', str(repo), *a], capture_output=True, text=True).stdout.strip()


def edit(text, e):
    if e['op'] == 'prepend':
        return e['text'] + text
    n = text.count(e['old'])
    if n != e['count']:
        raise ValueError(f"{e['old']!r} occurs {n} times, pinned {e['count']}")
    return text.replace(e['old'], e['new'])


def run(donor, tree, pins, apply=True):
    donor, tree = Path(donor), Path(tree)
    d = pins['donor']
    src = donor / d['subtree']
    dst = tree / pins['dest']
    rec = {'donor': d, 'checks': {}, 'files': []}
    c = rec['checks']
    c['donor_head'] = git(donor, 'rev-parse', 'HEAD') == d['sha']
    c['donor_worktree_clean'] = not git(donor, 'status', '--porcelain', '--untracked-files=all', '--', d['subtree'])
    c['donor_tree'] = git(donor, 'rev-parse', 'HEAD:' + d['subtree']) == d['tree']
    files = sorted(p for p in src.rglob('*') if p.is_file()) if src.is_dir() else []
    c['donor_file_count'] = len(files) == d['files']
    c['no_symlink'] = src.is_dir() and not any(p.is_symlink() for p in src.rglob('*'))
    sel = tree / pins['selector']['path']
    c['selector_blob'] = sel.is_file() and blob(sel.read_bytes()) == pins['selector']['blob']
    c['destination_absent'] = not dst.exists()
    edits = {}
    for f in pins['edits']:
        p = src / f['path']
        ok = p.is_file() and blob(p.read_bytes()) == f['pre']
        post = None
        if ok:
            try:
                t = p.read_text()
                for e in f['ops']:
                    t = edit(t, e)
                post = t.encode()
            except ValueError as ex:
                rec['files'].append({'path': f['path'], 'error': str(ex)})
                ok = False
        ok = ok and post is not None and blob(post) == f['post']
        rec['files'].append({'path': f['path'], 'pre_ok': p.is_file() and blob(p.read_bytes()) == f['pre'], 'post_ok': ok})
        if ok:
            edits[f['path']] = post
    c['edits'] = len(edits) == len(pins['edits'])
    rec['ok'] = all(c.values())
    if rec['ok'] and apply:
        shutil.copytree(src, dst)
        for rel, post in edits.items():
            (dst / rel).write_bytes(post)
        rec['staged_files'] = sum(1 for p in dst.rglob('*') if p.is_file())
        rec['ok'] = rec['staged_files'] == d['files']
    return rec


if __name__ == '__main__':
    donor, tree, pins_path, out = sys.argv[1:5]
    r = run(donor, tree, json.loads(Path(pins_path).read_text()))
    Path(out).write_text(json.dumps(r, indent=1))
    print('ok' if r['ok'] else 'FAIL ' + json.dumps({k: v for k, v in r['checks'].items() if v is not True}))
    sys.exit(0 if r['ok'] else 1)
