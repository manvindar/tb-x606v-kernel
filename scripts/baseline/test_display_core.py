#!/usr/bin/env python3
"""Tests for display_core.py (synthetic checkouts) and consistency of the committed v7 pins (bundles hash to their pins, no pin is duplicated or overlaps)."""
import json, subprocess, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import board_transplant as bt
import display_core as dc

BASE = Path(__file__).resolve().parents[2]


def setup(d, tamper_src=False, tamper_tree=False, wrong_head=False):
    d = Path(d)
    (d / 'src/a').mkdir(parents=True); (d / 'tree/a').mkdir(parents=True)
    subprocess.run(['git', 'init', '-q', str(d / 'src')], check=True)
    files = {'a/x.c': (b'old x\n', b'new x\n'), 'a/y.h': (b'old y\n', b'new y\n')}
    pins = {'source': {'sha': ''}, 'files': [], 'kept': [], 'not_installed': []}
    for p, (o, n) in files.items():
        (d / 'src' / p).write_bytes(n + (b'x' if tamper_src else b''))
        (d / 'tree' / p).write_bytes(o + (b'x' if tamper_tree and p == 'a/y.h' else b''))
        pins['files'].append({'path': p, 'old': bt.blob(o), 'new': bt.blob(n)})
    (d / 'tree/a/keep.c').write_bytes(b'keep\n')
    pins['kept'].append({'path': 'a/keep.c', 'old': bt.blob(b'keep\n')})
    (d / 'tree/a/only.c').write_bytes(b'only\n')
    pins['not_installed'].append({'path': 'a/only.c', 'blob': bt.blob(b'only\n')})
    subprocess.run(['git', '-C', str(d / 'src'), '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'x'], check=True)
    head = subprocess.run(['git', '-C', str(d / 'src'), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
    pins['source']['sha'] = '0' * 40 if wrong_head else head
    return d, pins


class T(unittest.TestCase):
    def test_installs_and_rehashes(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins = setup(t)
            r = dc.run(d / 'src', d / 'tree', pins)
            self.assertTrue(r['ok'])
            self.assertEqual((d / 'tree/a/x.c').read_bytes(), b'new x\n')
            self.assertEqual((d / 'tree/a/keep.c').read_bytes(), b'keep\n')   # kept and not_installed are never written

    def test_tampered_source_writes_nothing(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins = setup(t, tamper_src=True)
            self.assertFalse(dc.run(d / 'src', d / 'tree', pins)['ok'])
            self.assertEqual((d / 'tree/a/x.c').read_bytes(), b'old x\n')

    def test_changed_target_file_writes_nothing(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins = setup(t, tamper_tree=True)
            self.assertFalse(dc.run(d / 'src', d / 'tree', pins)['ok'])
            self.assertEqual((d / 'tree/a/x.c').read_bytes(), b'old x\n')   # all or nothing

    def test_wrong_source_commit_writes_nothing(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins = setup(t, wrong_head=True)
            r = dc.run(d / 'src', d / 'tree', pins)
            self.assertFalse(r['ok']); self.assertFalse(r['source_ok'])
            self.assertEqual((d / 'tree/a/x.c').read_bytes(), b'old x\n')

    def test_kept_file_changed_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins = setup(t)
            (d / 'tree/a/keep.c').write_bytes(b'edited\n')
            self.assertFalse(dc.run(d / 'src', d / 'tree', pins)['ok'])

    def test_committed_pins_are_consistent(self):
        pins = json.loads((BASE / 'data/baseline/display-core.json').read_text())
        paths = [f['path'] for k in ('files', 'kept', 'not_installed') for f in pins[k]]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(pins['counts'], {'installed': len(pins['files']), 'kept': len(pins['kept']), 'philmb_only': len(pins['not_installed'])})
        for f in pins['files']:
            self.assertNotEqual(f['old'], f['new'])
            self.assertEqual(len(f['old']), 40); self.assertEqual(len(f['new']), 40)
        self.assertIn('drivers/misc/mediatek/lcm/inc/lcm_drv.h', [f['path'] for f in pins['files']])

    def test_committed_recovered_bundles_hash_to_their_pins(self):
        pins = json.loads((BASE / 'data/baseline/stock-board-transplant.json').read_text())
        self.assertGreaterEqual(len(pins['recovered_files']), 9)
        for f in pins['recovered_files']:
            self.assertEqual(bt.blob((BASE / f['bundle']).read_bytes()), f['blob'], f['path'])
        dest = [f['path'] for f in pins['recovered_files']]
        self.assertEqual(len(dest), len(set(dest)))
        ids = {b['id'] for b in pins['blocked']}
        pending = {b['id'] for b in pins['recovered_pending_ci']}
        self.assertFalse(ids & pending)   # a unit is either blocked or recovered-pending-CI, never both


if __name__ == '__main__':
    unittest.main()
