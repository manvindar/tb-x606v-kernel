#!/usr/bin/env python3
"""gpu113_integrate.py (stage + selector switch, all-or-nothing), gpu113_assert.py (what the Image actually contains) and export_accounting.py on synthetic trees,
plus consistency of the committed pins."""
import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import board_transplant as bt
import export_accounting as ea
import gpu113_assert as ga
import gpu113_integrate as gi
import stage_gpu113 as sg

BASE = Path(__file__).resolve().parents[2]
SEL = 'drivers/misc/mediatek/gpu/gpu_rgx'
SUB = 'drv/m1.13ED5776728'
SELECTOR = '''MTK_GPU_VERSION = $(subst ",,$(CONFIG_MTK_GPU_VERSION))
$(info *MTK_GPU_VERSION 2 = $(word 2,$(MTK_GPU_VERSION)))

ifeq ($(word 2,$(MTK_GPU_VERSION)),doma)
	obj-y += m1.11ED5425693/
else ifeq ($(word 2,$(MTK_GPU_VERSION)),lorne)
	obj-y += m1.11ED5425693/
else ifeq ($(word 2,$(MTK_GPU_VERSION)),clark)
	obj-y += m1.11ED5425693/
endif
'''
HOOK_OPS = [{'op': 'insert_after', 'anchor_lines': ['ifeq ($(word 2,$(MTK_GPU_VERSION)),doma)'],
             'insert': '\tobj-y += m1.13ED5776728/\nelse ifeq ($(word 2,$(MTK_GPU_VERSION)),doma-ddk-1.11)\n'}]


def setup(d, bad_hook=False):
    d = Path(d)
    src = d / 'donor' / SUB
    src.mkdir(parents=True)
    (src / 'Makefile').write_text('ccflags-y += -Idrivers/gpu/mediatek/ged/include\n')
    (src / 'x.c').write_text('int x;\n')
    subprocess.run(['git', 'init', '-q', str(d / 'donor')], check=True)
    subprocess.run(['git', '-C', str(d / 'donor'), 'add', '-A'], check=True)
    subprocess.run(['git', '-C', str(d / 'donor'), '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', 'x'], check=True)
    git = lambda *a: subprocess.run(['git', '-C', str(d / 'donor'), *a], capture_output=True, text=True).stdout.strip()
    (d / 'tree' / SEL).mkdir(parents=True)
    (d / 'tree' / SEL / 'Makefile').write_text(SELECTOR)
    ops = [{'op': 'replace', 'old': 'drivers/gpu/mediatek/ged/include', 'new': 'drivers/misc/mediatek/gpu/ged/include', 'count': 1}]
    post = sg.edit((src / 'Makefile').read_text(), ops[0]).encode()
    pins = {'donor': {'sha': git('rev-parse', 'HEAD'), 'subtree': SUB, 'tree': git('rev-parse', 'HEAD:' + SUB), 'files': 2},
            'selector': {'path': SEL + '/Makefile', 'blob': bt.blob(SELECTOR.encode())}, 'dest': SEL + '/m1.13ED5776728',
            'edits': [{'path': 'Makefile', 'pre': sg.blob((src / 'Makefile').read_bytes()), 'ops': ops, 'post': sg.blob(post)}]}
    post_sel = bt.apply_ops(SELECTOR, HOOK_OPS).encode()
    hooks = [{'file': SEL + '/Makefile', 'pre_blob': bt.blob(SELECTOR.encode()), 'post_blob': 'bad' if bad_hook else bt.blob(post_sel), 'ops': HOOK_OPS}]
    return d, pins, hooks


class Integrate(unittest.TestCase):
    def test_integrates(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins, hooks = setup(t)
            r = gi.run(d / 'donor', d / 'tree', pins, hooks)
            self.assertTrue(r['integrated'], r)
            self.assertEqual(r['selector']['after']['doma'], ['m1.13ED5776728/'])
            self.assertEqual(r['selector']['after']['doma-ddk-1.11'], ['m1.11ED5425693/'])
            self.assertEqual(r['selector']['after']['lorne'], r['selector']['before']['lorne'])    # other GPU words are untouched
            self.assertEqual(r['selector']['after']['clark'], ['m1.11ED5425693/'])
            self.assertTrue((d / 'tree' / SEL / 'm1.13ED5776728/x.c').is_file())

    def test_bad_selector_pin_restores_the_tree(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins, hooks = setup(t, bad_hook=True)
            r = gi.run(d / 'donor', d / 'tree', pins, hooks)
            self.assertFalse(r['integrated'])
            self.assertEqual((d / 'tree' / SEL / 'Makefile').read_text(), SELECTOR)
            self.assertFalse((d / 'tree' / SEL / 'm1.13ED5776728').exists())    # the staged copy is removed again

    def test_stage_failure_changes_nothing(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins, hooks = setup(t)
            pins['donor']['sha'] = '0' * 40
            r = gi.run(d / 'donor', d / 'tree', pins, hooks)
            self.assertFalse(r['integrated'])
            self.assertEqual((d / 'tree' / SEL / 'Makefile').read_text(), SELECTOR)
            self.assertFalse((d / 'tree' / SEL / 'm1.13ED5776728').exists())

    def test_hook_that_does_not_switch_doma_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            d, pins, hooks = setup(t)
            ops = [{'op': 'insert_after', 'anchor_lines': ['else ifeq ($(word 2,$(MTK_GPU_VERSION)),lorne)'], 'insert': '\tobj-y += m1.13ED5776728/\nelse ifeq ($(word 2,$(MTK_GPU_VERSION)),lorne-old)\n'}]
            hooks = [{'file': SEL + '/Makefile', 'pre_blob': bt.blob(SELECTOR.encode()), 'post_blob': bt.blob(bt.apply_ops(SELECTOR, ops).encode()), 'ops': ops}]
            r = gi.run(d / 'donor', d / 'tree', pins, hooks)
            self.assertFalse(r['integrated'])      # doma must evaluate to 1.13, lorne must stay as before
            self.assertEqual((d / 'tree' / SEL / 'Makefile').read_text(), SELECTOR)


class Assert(unittest.TestCase):
    SYM = {'ddk113': {'dir': 'm1.13ED5776728/', 'version_string': 'V13', 'objects': 2, 'only': ['new_a', 'new_b'], 'exports': ['exp_a', 'exp_new']},
           'ddk111': {'dir': 'm1.11ED5425693/', 'version_string': 'V11', 'only': ['old_a'], 'exports': ['exp_a']}}

    def make(self, d, which, break_what=None):
        d = Path(d)
        (d / 'tree' / SEL).mkdir(parents=True)
        sel = bt.apply_ops(SELECTOR, HOOK_OPS) if which == 'ddk113' else SELECTOR
        (d / 'tree' / SEL / 'Makefile').write_text(sel)
        (d / 'cfg').write_text('CONFIG_MTK_GPU_VERSION="rgx doma m1.9ED4940716"\n')
        dirname = self.SYM[which]['dir']
        o = d / 'out' / SEL / dirname
        o.mkdir(parents=True)
        (o / 'built-in.o').write_bytes(b'')
        if which == 'ddk113':
            for n in ('a.o', 'b.o'): (o / n).write_bytes(b'')
            (d / 'tree' / SEL / dirname).mkdir(parents=True)     # the staged source directory (latent-define check reads it)
        names = self.SYM[which]['only']
        exp = self.SYM[which]['exports']
        (d / 'nm').write_text(''.join(f'ffff000000001000 T {n}\n' for n in names))
        (d / 'sv').write_text(''.join(f'0x1\t{n}\tvmlinux\tEXPORT_SYMBOL\n' for n in exp))
        (d / 'vm').write_bytes(b'..' + self.SYM[which]['version_string'].encode() + b'..')
        (d / 'errs').write_text('')
        (d / 'sym.json').write_text(json.dumps(self.SYM))
        if break_what == 'other_symbol': (d / 'nm').write_text((d / 'nm').read_text() + 'ffff000000002000 T old_a\n')
        if break_what == 'version': (d / 'vm').write_bytes(b'V11')
        if break_what == 'error': (d / 'errs').write_text('drivers/misc/mediatek/gpu/gpu_rgx/m1.13ED5776728/x.c:1: error: boom\n')
        if break_what == 'undefined_is_not_defined': (d / 'nm').write_text(''.join(f'                 U {n}\n' for n in names))
        return d

    def args(self, d, expect, **drop):
        class A: pass
        a = A()
        a.expect, a.tree, a.config, a.nm, a.vmlinux, a.symvers = expect, str(d / 'tree'), str(d / 'cfg'), str(d / 'nm'), str(d / 'vm'), str(d / 'sv')
        a.symbols, a.compile_errors, a.build_log, a.out = str(d / 'sym.json'), str(d / 'errs'), None, str(d / 'out')
        for k, v in drop.items(): setattr(a, k, v)
        return a

    def status(self, checks): return {c['check']: c['status'] for c in checks}

    def test_ddk113_all_pass(self):
        with tempfile.TemporaryDirectory() as t:
            d = self.make(t, 'ddk113')
            self.assertEqual(ga.verdict(ga.run(self.args(d, 'ddk113'))), 0)

    def test_control_all_pass(self):
        with tempfile.TemporaryDirectory() as t:
            d = self.make(t, 'ddk111')
            self.assertEqual(ga.verdict(ga.run(self.args(d, 'none'))), 0)

    def test_an_image_that_did_not_get_the_driver_fails_each_check(self):
        with tempfile.TemporaryDirectory() as t:
            d = self.make(t, 'ddk111')
            r = ga.run(self.args(d, 'ddk113'))
            s = self.status(r)
            self.assertEqual(ga.verdict(r), 1)
            for k in ('selector', 'built_objects', 'symbols', 'exports', 'version_string'): self.assertEqual(s[k], 'FAIL', k)

    def test_1_11_symbol_left_in_the_link_fails(self):
        with tempfile.TemporaryDirectory() as t:
            d = self.make(t, 'ddk113', 'other_symbol')
            self.assertEqual(self.status(ga.run(self.args(d, 'ddk113')))['symbols'], 'FAIL')

    def test_file_local_symbol_with_the_same_name_is_not_a_definition(self):
        with tempfile.TemporaryDirectory() as t:
            d = self.make(t, 'ddk113')
            (d / 'nm').write_text((d / 'nm').read_text() + 'ffff000000003000 t old_a\n')    # lower case: static in some other file
            self.assertEqual(self.status(ga.run(self.args(d, 'ddk113')))['symbols'], 'PASS')

    def test_undefined_reference_is_not_a_definition(self):
        with tempfile.TemporaryDirectory() as t:
            d = self.make(t, 'ddk113', 'undefined_is_not_defined')
            self.assertEqual(self.status(ga.run(self.args(d, 'ddk113')))['symbols'], 'FAIL')

    def test_old_version_string_fails(self):
        with tempfile.TemporaryDirectory() as t:
            d = self.make(t, 'ddk113', 'version')
            self.assertEqual(self.status(ga.run(self.args(d, 'ddk113')))['version_string'], 'FAIL')

    def test_compile_error_in_the_driver_fails(self):
        with tempfile.TemporaryDirectory() as t:
            d = self.make(t, 'ddk113', 'error')
            self.assertEqual(self.status(ga.run(self.args(d, 'ddk113')))['gpu_compile_errors'], 'FAIL')

    def test_no_link_is_not_measured_not_failed(self):
        with tempfile.TemporaryDirectory() as t:
            d = self.make(t, 'ddk113')
            r = ga.run(self.args(d, 'ddk113', nm=None, vmlinux=None, symvers=None))
            s = self.status(r)
            self.assertEqual((s['symbols'], s['exports'], s['version_string']), ('NOT_MEASURED',) * 3)
            self.assertEqual(ga.verdict(r), 2)

    def test_latent_define_is_caught(self):
        with tempfile.TemporaryDirectory() as t:
            d = self.make(t, 'ddk113')
            (d / 'tree' / SEL / 'm1.13ED5776728/cfg.h').write_text('#define MTK_CAL_POWER_INDEX 1\n')
            self.assertEqual(self.status(ga.run(self.args(d, 'ddk113')))['latent_cal_power_index_off'], 'FAIL')


class Accounting(unittest.TestCase):
    PIN = {'mismatch': {'a': {'candidate': 1, 'shipping': 2, 'class': 'k'}}, 'absent': ['z']}
    SHIP = {'a': 2, 'b': 3, 'z': 9}

    def test_unchanged(self):
        r = ea.compare({'a': 1, 'b': 3}, self.SHIP, self.PIN)
        self.assertTrue(r['unchanged']); self.assertEqual(r['candidate_only_exports'], 0)

    def test_candidate_only_exports_are_counted_not_judged(self):
        r = ea.compare({'a': 1, 'b': 3, 'extra': 5}, self.SHIP, self.PIN)
        self.assertTrue(r['unchanged']); self.assertEqual(r['candidate_only_exports'], 1)

    def test_new_mismatch_and_new_absent_are_reported(self):
        r = ea.compare({'a': 1, 'b': 4}, self.SHIP, self.PIN)
        self.assertFalse(r['unchanged']); self.assertEqual(r['new_mismatch'], ['b'])
        r = ea.compare({'a': 1}, self.SHIP, self.PIN)
        self.assertEqual(r['new_absent'], ['b'])

    def test_resolved_and_changed_crc_are_reported(self):
        r = ea.compare({'a': 2, 'b': 3, 'z': 9}, self.SHIP, self.PIN)
        self.assertEqual((r['resolved_mismatch'], r['resolved_absent']), (['a'], ['z']))
        r = ea.compare({'a': 7, 'b': 3}, self.SHIP, self.PIN)
        self.assertEqual(r['crc_changed_within_mismatch'], ['a'])


class Committed(unittest.TestCase):
    def j(self, p): return json.loads((BASE / p).read_text())

    def test_pins_and_hooks_agree(self):
        pins, hooks = self.j('data/baseline/gpu113-integration-pins.json'), self.j('data/amar/gpu113-selector-hooks.json')
        stage = self.j('data/baseline/gpu113-stage.json')
        self.assertEqual(pins['donor'], stage['donor'])
        self.assertEqual(pins['selector'], stage['selector'])
        self.assertEqual(pins['edits'][:3], stage['edits'])     # the published edits are kept unchanged; one is added
        self.assertEqual([e['path'] for e in pins['edits']][3:], ['services/system/rogue/rgx_mtk/mt6765/mtk_mfgsys.c'])
        self.assertEqual(len(pins['edits'][3]['ops']), 6)
        self.assertEqual(hooks[0]['pre_blob'], pins['selector']['blob'])
        self.assertEqual(hooks[0]['file'], pins['selector']['path'])

    def test_symbol_and_accounting_pins(self):
        s = self.j('data/baseline/gpu113-symbols.json')
        self.assertEqual((len(s['ddk113']['only']), len(s['ddk111']['only']), len(s['ddk113']['exports']), len(s['ddk111']['exports']), s['ddk113']['objects']), (159, 204, 11, 12, 134))
        self.assertFalse(set(s['ddk113']['only']) & set(s['ddk111']['only']))
        a = self.j('data/baseline/export-accounting-44045545603.json')
        self.assertEqual((len(a['mismatch']), len(a['absent'])), (82, 6))
        self.assertEqual(sorted({v['class'] for v in a['mismatch'].values()}), ['drift_without_calibrated_after', 'excluded_uncalibrated_charger', 'predicted_power_supply_regression'])


if __name__ == '__main__':
    unittest.main()
