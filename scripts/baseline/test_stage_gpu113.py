#!/usr/bin/env python3
"""Tests for stage_gpu113.py on synthetic donor/target trees, and consistency of the committed pins."""
import json, subprocess, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stage_gpu113 as sg

BASE = Path(__file__).resolve().parents[2]
SUB = 'drv/m1'


def setup(d, tamper_edit=False, existing_dest=False, bad_selector=False, symlink=False):
    d = Path(d)
    src = d / 'donor' / SUB
    (src / 'include').mkdir(parents=True)
    (src / 'Makefile').write_text('ccflags-y += -Idrivers/gpu/mediatek/ged/include\n')
    (src / 'include/cfg.h').write_text('#define H "../drivers/staging/android/aosp_ion/ion.h"\n')
    (src / 'x.c').write_text('int x;\n')
    if symlink:
        (src / 'ln').symlink_to('x.c')
    subprocess.run(['git', 'init', '-q', str(d / 'donor')], check=True)
    subprocess.run(['git', '-C', str(d / 'donor'), 'add', '-A'], check=True)
    subprocess.run(['git', '-C', str(d / 'donor'), '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', 'x'], check=True)
    git = lambda *a: subprocess.run(['git', '-C', str(d / 'donor'), *a], capture_output=True, text=True).stdout.strip()
    (d / 'tree/gpu').mkdir(parents=True)
    (d / 'tree/gpu/Makefile').write_text('sel\n' if not bad_selector else 'other\n')
    if existing_dest:
        (d / 'tree/gpu/m1').mkdir()
    mk_ops = [{'op': 'prepend', 'text': 'P := 1\n'}, {'op': 'replace', 'old': 'drivers/gpu/mediatek/ged/include', 'new': 'drivers/misc/mediatek/gpu/ged/include', 'count': 1}]
    h_ops = [{'op': 'replace', 'old': 'aosp_ion', 'new': 'ion', 'count': 1}]
    def post(p, ops):
        t = p.read_text()
        for e in ops:
            t = sg.edit(t, e)
        return t.encode()
    edits = []
    for rel, ops in (('Makefile', mk_ops), ('include/cfg.h', h_ops)):
        edits.append({'path': rel, 'pre': sg.blob((src / rel).read_bytes()), 'ops': ops, 'post': 'bad' if tamper_edit else sg.blob(post(src / rel, ops))})
    pins = {'donor': {'sha': git('rev-parse', 'HEAD'), 'subtree': SUB, 'tree': git('rev-parse', 'HEAD:' + SUB), 'files': 3 if not symlink else 4},
            'selector': {'path': 'gpu/Makefile', 'blob': sg.blob(b'sel\n')}, 'dest': 'gpu/m1', 'edits': edits}
    return d, pins


class T(unittest.TestCase):
    def test_stages_and_edits(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins = setup(t)
            r = sg.run(d / 'donor', d / 'tree', pins)
            self.assertTrue(r['ok'], r)
            self.assertTrue((d / 'tree/gpu/m1/Makefile').read_text().startswith('P := 1\n'))
            self.assertIn('/ion.h', (d / 'tree/gpu/m1/include/cfg.h').read_text())
            self.assertEqual((d / 'tree/gpu/Makefile').read_text(), 'sel\n')   # selector never edited

    def test_wrong_edit_pin_writes_nothing(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins = setup(t, tamper_edit=True)
            self.assertFalse(sg.run(d / 'donor', d / 'tree', pins)['ok'])
            self.assertFalse((d / 'tree/gpu/m1').exists())

    def test_existing_destination_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins = setup(t, existing_dest=True)
            r = sg.run(d / 'donor', d / 'tree', pins)
            self.assertFalse(r['ok']); self.assertFalse(r['checks']['destination_absent'])

    def test_changed_selector_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins = setup(t, bad_selector=True)
            r = sg.run(d / 'donor', d / 'tree', pins)
            self.assertFalse(r['ok']); self.assertFalse(r['checks']['selector_blob']); self.assertFalse((d / 'tree/gpu/m1').exists())

    def test_wrong_donor_commit_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins = setup(t)
            pins['donor']['sha'] = '0' * 40
            self.assertFalse(sg.run(d / 'donor', d / 'tree', pins)['checks']['donor_head'])

    def test_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins = setup(t, symlink=True)
            r = sg.run(d / 'donor', d / 'tree', pins)
            self.assertFalse(r['ok']); self.assertFalse(r['checks']['no_symlink'])

    def test_changed_unedited_file_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins = setup(t)
            (d / 'donor' / SUB / 'x.c').write_text('int changed;\n')
            r = sg.run(d / 'donor', d / 'tree', pins)
            self.assertFalse(r['ok'])
            self.assertFalse(r['checks']['donor_worktree_clean'])
            self.assertFalse((d / 'tree/gpu/m1').exists())

    def test_committed_pins(self):
        p = json.loads((BASE / 'data/baseline/gpu113-stage.json').read_text())
        self.assertEqual(p['donor']['version'], 'm1.13ED5776728')
        self.assertEqual(len(p['donor']['sha']), 40); self.assertEqual(len(p['donor']['tree']), 40)
        self.assertEqual(p['donor']['files'], 774)
        self.assertEqual([e['path'] for e in p['edits']], ['Makefile', 'include/config_kernel_eng_mt6765.h', 'include/config_kernel_user_mt6765.h'])
        self.assertTrue(p['dest'].endswith(p['donor']['version']))
        self.assertNotEqual(p['dest'], p['selector']['path'].rsplit('/', 1)[0])   # the 1.11 driver directory is not touched


if __name__ == '__main__':
    unittest.main()
