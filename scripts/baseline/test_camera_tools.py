#!/usr/bin/env python3
"""Tests for sensor_contract_guard.py and camera_transplant.py (synthetic trees, no kernel source needed)."""
import hashlib, json, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import camera_transplant as ct
import sensor_contract_guard as g
import text_fidelity as tf

HEADER = '''#define SENSOR_FEATURE_START 3000
enum ACDK_SENSOR_FEATURE_ENUM {
    SENSOR_FEATURE_BEGIN = SENSOR_FEATURE_START,
    SENSOR_FEATURE_GET_RESOLUTION,
    SENSOR_FEATURE_CHECK_SENSOR_ID,
    SENSOR_FEATURE_SET_VIDEO_MODE,
    SENSOR_FEATURE_MAX
};'''
LIST = '#if defined(FOO_MIPI_RAW)\n\t{FOO_SENSOR_ID,\n\tSENSOR_DRVNAME_FOO_MIPI_RAW,\n\tFOO_MIPI_RAW_SensorInit},\n#endif\n'
CFG = 'CONFIG_CUSTOM_KERNEL_IMGSENSOR="foo_mipi_raw"\n'


def driver(cases, extra=''):
    body = ''.join(f'\tcase {c}:\n\t\tbreak;\n' for c in cases)
    return ('UINT32 FOO_MIPI_RAW_SensorInit(struct SENSOR_FUNCTION_STRUCT **pfFunc)\n{ return 0; }\n'
            'static kal_uint32 feature_control(MSDK_SENSOR_FEATURE_ENUM feature_id, UINT8 *p, UINT32 *l)\n{\n'
            '\tswitch (feature_id) {\n' + body + '\tdefault:\n\t\tbreak;\n\t}\n' + extra + '\treturn 0;\n}\n')


def make_root(d, src, with_list=True):
    root = Path(d) / 'imgsensor'
    (root / 'inc').mkdir(parents=True)
    (root / 'inc' / 'kd_imgsensor_define.h').write_text(HEADER)
    v1 = root / 'src' / 'common' / 'v1'
    (v1 / 'foo_mipi_raw').mkdir(parents=True)
    (v1 / 'imgsensor_sensor_list.c').write_text(LIST if with_list else '')
    if src is not None:
        (v1 / 'foo_mipi_raw' / 'Makefile').write_text('obj-y += foo.o\n')
        (v1 / 'foo_mipi_raw' / 'foo.c').write_text(src)
    return root


class Guard(unittest.TestCase):
    def run_guard(self, src, **kw):
        with tempfile.TemporaryDirectory() as d:
            return g.run(make_root(d, src, **kw), CFG)

    def kinds(self, r):
        return [p['kind'] for s in r['sensors'] for p in s['problems']]

    def test_clean(self):
        r = self.run_guard(driver(['SENSOR_FEATURE_CHECK_SENSOR_ID', 'SENSOR_FEATURE_SET_VIDEO_MODE', '3001']))
        self.assertTrue(r['ok'], r)

    def test_undefined_label_is_reported_not_repaired(self):  # the gc5035 GET_SENSOR_ID mismatch
        r = self.run_guard(driver(['SENSOR_FEATURE_CHECK_SENSOR_ID', 'SENSOR_FEATURE_GET_SENSOR_ID']))
        self.assertEqual(self.kinds(r), ['undefined-case-label'])
        self.assertEqual(r['sensors'][0]['problems'][0]['label'], 'SENSOR_FEATURE_GET_SENSOR_ID')

    def test_alias_creates_duplicate_value(self):  # the rejected 'alias GET to CHECK' repair must be caught
        r = self.run_guard(driver(['SENSOR_FEATURE_CHECK_SENSOR_ID', '3002']))
        self.assertEqual(self.kinds(r), ['duplicate-case-value'])

    def test_nested_switch_labels_are_ignored(self):
        nested = '\tswitch (scenario) {\n\tcase MSDK_SCENARIO_ID_VIDEO_PREVIEW:\n\t\tbreak;\n\t}\n'
        body = driver(['SENSOR_FEATURE_CHECK_SENSOR_ID'])
        body = body.replace('\tcase SENSOR_FEATURE_CHECK_SENSOR_ID:\n\t\tbreak;\n',
                            '\tcase SENSOR_FEATURE_CHECK_SENSOR_ID:\n' + nested + '\t\tbreak;\n')
        self.assertTrue(self.run_guard(body)['ok'])

    def test_missing_driver_and_list_entry(self):
        r = self.run_guard(None, with_list=False)
        self.assertEqual(sorted(self.kinds(r)), ['missing-driver-source', 'missing-sensor-list-entry'])

    def test_init_function_must_be_defined(self):
        r = self.run_guard(driver(['SENSOR_FEATURE_CHECK_SENSOR_ID']).replace('FOO_MIPI_RAW_SensorInit', 'BAR_SensorInit'))
        self.assertEqual(self.kinds(r), ['init-function-not-defined'])

    def test_config_required(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                g.run(make_root(d, driver([])), '# CONFIG_CUSTOM_KERNEL_IMGSENSOR is not set\n')


def blob(b):
    return hashlib.sha1(b'blob %d\0' % len(b) + b).hexdigest()


class Transplant(unittest.TestCase):
    def setup(self, d, tamper=False):
        d = Path(d)
        (d / 'lenovo/unit/sub').mkdir(parents=True)
        files = {'unit/a.c': b'int a;\n', 'unit/sub/b.h': b'#define B 1\n'}
        for k, v in files.items():
            (d / 'lenovo' / k).write_bytes(v + (b'x' if tamper and k == 'unit/a.c' else b''))
        (d / 'tree/unit').mkdir(parents=True)
        (d / 'tree/unit/stale.c').write_text('old')
        (d / 'data/baseline').mkdir(parents=True)
        (d / 'data/baseline/m.json').write_text(json.dumps({k: {'blob': blob(v), 'bytes': len(v)} for k, v in files.items()}))
        pins = {'source': {'sha': 'x'}, 'known_gaps': [], 'units': [{'path': 'unit', 'git_tree': 't', 'manifest': 'data/baseline/m.json', 'files': 2}]}
        return pins

    def test_replaces_unit_exactly(self):
        with tempfile.TemporaryDirectory() as d:
            pins = self.setup(d)
            r = ct.transplant(Path(d) / 'lenovo', Path(d) / 'tree', pins, base=d)
            self.assertTrue(r['ok'], r)
            self.assertFalse((Path(d) / 'tree/unit/stale.c').exists())
            self.assertEqual(r['units'][0]['replaced_files'], 1)
            self.assertEqual(r['units'][0]['installed_files'], 2)

    def test_tampered_source_is_refused_and_tree_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            pins = self.setup(d, tamper=True)
            r = ct.transplant(Path(d) / 'lenovo', Path(d) / 'tree', pins, base=d)
            self.assertFalse(r['ok'])
            self.assertEqual(r['units'][0]['source_check']['mismatch'], ['unit/a.c'])
            self.assertTrue((Path(d) / 'tree/unit/stale.c').exists())

    def test_extra_file_in_source_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            pins = self.setup(d)
            (Path(d) / 'lenovo/unit/extra.c').write_text('x')
            self.assertFalse(ct.transplant(Path(d) / 'lenovo', Path(d) / 'tree', pins, base=d)['ok'])


class Fidelity(unittest.TestCase):
    REF = json.loads((Path(__file__).resolve().parents[2] / 'data/baseline/shipping-sensor-symbols.json').read_text())
    SHIP = [(x['name'], x['delta']) for x in REF['region']]

    def nm(self, rows, base=0xffffff8008600000):
        out, a = [], base
        for n, d in rows:
            out.append('%016x t %s' % (a, n) if n != 'x' else '')
            a += d
        out.append('%016x T imgsensor_dfs_ctrl' % a)
        return out

    def test_same_layout_is_layout_match_only(self):  # equal names and sizes never claim identical code
        r = tf.compare(self.SHIP, tf.candidate_region(self.nm(self.SHIP)))
        self.assertEqual(r['summary']['matching-symbol-layout'], 10)
        self.assertEqual(sum(r['summary'].values()), 10)
        self.assertEqual(r['source_identity'], 'unproved')
        self.assertEqual(r['evidence_class'], 'symbol-layout')
        self.assertTrue(all(v['source_identity'] == 'unproved' for v in r['blocks'].values()))
        self.assertNotIn('identical', r['summary'])

    def test_one_size_difference_is_located(self):
        rows = [(n, d + 8 if (n == 'feature_control' and i == 4) else d) for i, (n, d) in enumerate(self.SHIP)]
        r = tf.compare(self.SHIP, tf.candidate_region(self.nm(rows)))
        self.assertEqual(r['summary']['same-symbols-different-sizes'], 1)
        bad = [v for v in r['blocks'].values() if v['status'] != 'matching-symbol-layout'][0]
        self.assertEqual(bad['differences'][0]['symbol'], 'feature_control')

    def test_missing_sensor_blocks_are_absent(self):
        keep = [i for i, (n, _) in enumerate(self.SHIP) if n.endswith('MIPI_RAW_SensorInit')]
        cut = keep[1]   # drop the first sensor block entirely (as when its source is missing)
        r = tf.compare(self.SHIP, tf.candidate_region(self.nm(self.SHIP[cut:])))
        self.assertEqual(r['summary']['absent-in-candidate'], 1)
        self.assertEqual(r['summary']['matching-symbol-layout'], 9)


if __name__ == '__main__':
    unittest.main()
