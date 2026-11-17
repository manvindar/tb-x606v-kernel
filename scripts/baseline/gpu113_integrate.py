#!/usr/bin/env python3
"""Integrate the pinned PowerVR DDK 1.13 driver into the Image build: stage it (stage_gpu113.py, with the pinned edits) and switch the selector Makefile
(drivers/misc/mediatek/gpu/gpu_rgx/Makefile) from the 1.11 directory to the 1.13 directory for the stock GPU word `doma`.

usage: gpu113_integrate.py DONOR_CHECKOUT KERNEL_TREE PINS.json HOOKS.json RECEIPT.json
All-or-nothing: the donor/stage checks of stage_gpu113.py pass, the selector hook applies (pinned pre- and post-edit blob) and the selector then evaluates, with GNU make,
to the 1.13 directory for `doma` and to the 1.11 directory for `doma-ddk-1.11`, while `lorne` and `clark` keep their pre-edit result. If anything fails the tree is left
exactly as it was (a staged directory is removed again) and the receipt says integrated=false, so the build still runs and reports every other gate.
Exit 0 = integrated, 1 = not integrated. Reports, never repairs."""
import json, shutil, subprocess, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import board_transplant as bt
import stage_gpu113 as sg

D113, D111 = 'm1.13ED5776728/', 'm1.11ED5425693/'
WORDS = ('doma', 'doma-ddk-1.11', 'lorne', 'clark')


def selector_value_objs(selector, value):
    """obj-y of the selector Makefile for CONFIG_MTK_GPU_VERSION = value (GNU make evaluates the real file); None if make printed no unique result."""
    mk = f'CONFIG_MTK_GPU_VERSION := "{value}"\ninclude {selector}\n$(info OBJ=$(obj-y))\nall: ;\n'
    with tempfile.NamedTemporaryFile('w', suffix='.mk', delete=False) as f:
        f.write(mk)
    try:
        out = subprocess.run(['make', '-s', '-f', f.name], capture_output=True, text=True).stdout
    finally:
        Path(f.name).unlink()
    hits = [l[4:].split() for l in out.splitlines() if l.startswith('OBJ=')]
    return hits[0] if len(hits) == 1 else None


def selector_objs(selector, word):
    return selector_value_objs(selector, f'rgx {word} m1.x')


def run(donor, tree, pins, hooks):
    tree = Path(tree)
    rec = {'stage': None, 'hooks': [], 'selector': {}, 'integrated': False}
    sel = tree / pins['selector']['path']
    before = {w: selector_objs(sel, w) for w in WORDS}
    rec['selector']['before'] = before
    dst = tree / pins['dest']
    existed = dst.exists()
    st = sg.run(donor, tree, pins)
    rec['stage'] = st
    if not st['ok']:
        rec['error'] = 'stage failed'
        if not existed:
            shutil.rmtree(dst, ignore_errors=True)   # a copy that failed its final file count must not stay
        return rec
    pre_selector = sel.read_bytes()
    ok = True
    for h in hooks:
        p = tree / h['file']
        e = {'file': h['file'], 'ok': False}
        rec['hooks'].append(e)
        if not p.is_file():
            e['error'] = 'target file missing'; ok = False; continue
        pre = p.read_bytes()
        e['pre_blob'] = bt.blob(pre)
        if e['pre_blob'] != h['pre_blob']:
            e['error'] = f"pre-edit blob {e['pre_blob']} != pin {h['pre_blob']}"; ok = False; continue
        try:
            post = bt.apply_ops(pre.decode(), h['ops']).encode()
        except ValueError as ex:
            e['error'] = str(ex); ok = False; continue
        e['post_blob'] = bt.blob(post)
        if e['post_blob'] != h['post_blob']:
            e['error'] = f"post-edit blob {e['post_blob']} != pin {h['post_blob']}"; ok = False; continue
        p.write_bytes(post)
        e['ok'] = True
    after = {w: selector_objs(sel, w) for w in WORDS}
    rec['selector']['after'] = after
    want = {'doma': [D113], 'doma-ddk-1.11': [D111], 'lorne': before['lorne'], 'clark': before['clark']}
    rec['selector']['expected_after'] = want
    sel_ok = ok and after == want and before['doma'] == [D111]
    rec['selector']['ok'] = sel_ok
    if not sel_ok:   # restore: the tree must be exactly as it was
        sel.write_bytes(pre_selector)
        shutil.rmtree(dst, ignore_errors=True)
        rec['error'] = 'selector hook or selector evaluation failed; tree restored'
        return rec
    rec['integrated'] = True
    return rec


if __name__ == '__main__':
    donor, tree, pins_path, hooks_path, out = sys.argv[1:6]
    r = run(donor, tree, json.loads(Path(pins_path).read_text()), json.loads(Path(hooks_path).read_text()))
    Path(out).write_text(json.dumps(r, indent=1))
    print('integrated' if r['integrated'] else 'NOT integrated: ' + r.get('error', '?'))
    sys.exit(0 if r['integrated'] else 1)
