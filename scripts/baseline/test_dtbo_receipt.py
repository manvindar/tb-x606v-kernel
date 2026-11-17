#!/usr/bin/env python3
"""dtbo_receipt.py: pinned inputs, outputs present, base-vs-carrier comparison, and the committed pin file."""
import hashlib, json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dtbo_receipt as R

BASE = Path(__file__).resolve().parents[2]


def build(d, tamper=False, drop=None, base_bytes=b'BASE'):
    d = Path(d)
    src, out = d / 'src', d / 'out'
    files = {'a.dts': b'dts', 'tools/dct/DrvGen.py': b'py'}
    for rel, b in files.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_bytes(b)
    subprocess.run(['git', 'init', '-q', str(src)], check=True)
    subprocess.run(['git', '-C', str(src), 'add', '-A'], check=True)
    subprocess.run(['git', '-C', str(src), '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', 'x'], check=True)
    pins = {'inputs_blob': {rel: R.git_blob(src / rel) for rel in files}, 'drvgen_tree': {'path': 'tools/dct', 'git_tree': R.git_tree(src, 'tools/dct')},
            'outputs': ['m/mt6765.dtb', 'm/o.dtb', 'm/o.dtb.merge'], 'carrier_base_dtb_sha256': hashlib.sha256(b'BASE').hexdigest(), 'not_claimed': ['x']}
    for rel in pins['outputs']:
        if rel != drop:
            (out / rel).parent.mkdir(parents=True, exist_ok=True)
            (out / rel).write_bytes(base_bytes if rel.endswith('mt6765.dtb') else b'o')
    (out / 'm/cust.dtsi').write_text('x')
    if tamper: (src / 'a.dts').write_bytes(b'changed')
    return src, out, pins


class T(unittest.TestCase):
    def test_ok_and_base_equals_carrier(self):
        with tempfile.TemporaryDirectory() as t:
            r = R.receipt(*build(t), 0)
            self.assertTrue(r['ok']); self.assertTrue(r['base_dtb_equals_carrier_base']); self.assertEqual(list(r['generated_cust_dtsi']), ['m/cust.dtsi'])

    def test_different_base_is_reported_not_failed(self):
        with tempfile.TemporaryDirectory() as t:
            r = R.receipt(*build(t, base_bytes=b'OTHER'), 0)
            self.assertTrue(r['ok']); self.assertFalse(r['base_dtb_equals_carrier_base'])

    def test_input_that_differs_from_its_pin_fails(self):
        with tempfile.TemporaryDirectory() as t:
            r = R.receipt(*build(t, tamper=True), 0)
            self.assertFalse(r['ok']); self.assertFalse(r['inputs']['a.dts']['ok'])

    def test_missing_output_fails_but_the_rest_is_recorded(self):
        with tempfile.TemporaryDirectory() as t:
            r = R.receipt(*build(t, drop='m/o.dtb.merge'), 2)
            self.assertFalse(r['ok']); self.assertEqual(r['dtbs_exit'], 2); self.assertTrue(r['outputs']['m/o.dtb']['exists'])

    def test_committed_pins(self):
        p = json.loads((BASE / 'data/amar/dtbo-diagnostic.json').read_text())
        self.assertEqual(p['source']['sha'], '0a95b5010777186eed379b2ed11e3d1a4f85921e')
        self.assertEqual(p['source']['sha'], json.loads((BASE / 'data/baseline/sources.json').read_text())['refs'][0]['sha'])
        self.assertEqual(p['config']['sha256'], json.loads((BASE / 'data/baseline/sources.json').read_text())['config']['sha256'])
        self.assertEqual(len(p['inputs_blob']), 4)
        self.assertTrue(all(len(v) == 40 for v in p['inputs_blob'].values()))
        self.assertEqual(sorted(o.rsplit('/', 1)[1] for o in p['outputs']), ['achilles6_row_call.dtb', 'achilles6_row_call.dtb.merge', 'mt6765.dtb'])


if __name__ == '__main__':
    unittest.main()
