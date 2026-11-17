#!/usr/bin/env python3
"""Tests for board_transplant.py and config_gate.py (synthetic trees, no kernel source needed)."""
import json, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import board_transplant as bt
import config_gate as cg
import reloc_sig as rs

KC = 'source "a/Kconfig"\nsource "old/Kconfig"\nsource "b/Kconfig"\n'
MK = 'obj-y += a/\nobj-y += b/\n'


def write(root, rel, text):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def setup(d, tamper_blob=False):
    d = Path(d)
    write(d, 'len/drv/x.c', 'int x;\n')
    write(d, 'len/drv/Makefile', 'obj-y += x.o\n')
    write(d, 'len/inc/x.h', '#define X 1\n')
    write(d, 'tree/Kconfig', KC)
    write(d, 'tree/Makefile', MK)
    man = {k: {'blob': bt.blob((d / 'len' / k).read_bytes()), 'bytes': 1} for k in ('drv/x.c', 'drv/Makefile')}
    write(d, 'data/baseline/m.json', json.dumps(man))
    ops_k = [{'op': 'insert_after', 'anchor_lines': ['source "a/Kconfig"'], 'insert': 'source "drv/Kconfig"\n'},
             {'op': 'delete_line', 'line': 'source "old/Kconfig"'}]
    ops_m = [{'op': 'insert_after', 'anchor_lines': ['obj-y += a/'], 'insert': 'obj-y += drv/\n'}]
    hooks = []
    for f, ops in (('Kconfig', ops_k), ('Makefile', ops_m)):
        pre = (d / 'tree' / f).read_bytes()
        post = bt.apply_ops(pre.decode(), ops).encode()
        hooks.append({'file': f, 'pre_blob': bt.blob(pre), 'post_blob': 'bad' if tamper_blob else bt.blob(post), 'ops': ops})
    pins = {'target': {}, 'source': {}, 'blocked': [],
            'units': [{'path': 'drv', 'git_tree': 't', 'manifest': 'data/baseline/m.json', 'files': 2, 'serves': 'X'}],
            'files': [{'path': 'inc/x.h', 'blob': bt.blob((d / 'len/inc/x.h').read_bytes()), 'bytes': 1, 'serves': 'X'}]}
    return pins, hooks


class Board(unittest.TestCase):
    def run_it(self, d, pins, hooks):
        return bt.run(Path(d) / 'len', Path(d) / 'tree', pins, hooks, base=d)

    def test_installs_and_edits(self):
        with tempfile.TemporaryDirectory() as d:
            pins, hooks = setup(d)
            r = self.run_it(d, pins, hooks)
            self.assertTrue(r['ok'], r)
            self.assertEqual((Path(d) / 'tree/Kconfig').read_text(), 'source "a/Kconfig"\nsource "drv/Kconfig"\nsource "b/Kconfig"\n')
            self.assertEqual((Path(d) / 'tree/Makefile').read_text(), 'obj-y += a/\nobj-y += drv/\nobj-y += b/\n')
            self.assertTrue((Path(d) / 'tree/inc/x.h').is_file() and (Path(d) / 'tree/drv/x.c').is_file())

    def test_wrong_post_blob_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            pins, hooks = setup(d, tamper_blob=True)
            r = self.run_it(d, pins, hooks)
            self.assertFalse(r['ok'])
            self.assertEqual((Path(d) / 'tree/Kconfig').read_text(), KC)
            self.assertFalse((Path(d) / 'tree/drv').exists() or (Path(d) / 'tree/inc').exists())

    def test_changed_target_file_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            pins, hooks = setup(d)
            write(d, 'tree/Makefile', MK + '# drift\n')
            r = self.run_it(d, pins, hooks)
            self.assertFalse(r['ok'])
            self.assertIn('pre-edit blob', [h for h in r['hooks'] if h['file'] == 'Makefile'][0]['error'])
            self.assertFalse((Path(d) / 'tree/drv').exists())

    def test_existing_destination_is_refused_not_replaced(self):
        with tempfile.TemporaryDirectory() as d:
            pins, hooks = setup(d)
            write(d, 'tree/drv/other.c', 'x')
            r = self.run_it(d, pins, hooks)
            self.assertFalse(r['ok'])
            self.assertTrue(r['units'][0]['destination_exists'])
            self.assertEqual((Path(d) / 'tree/Kconfig').read_text(), KC)

    def test_tampered_source_blob_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            pins, hooks = setup(d)
            write(d, 'len/inc/x.h', '#define X 2\n')
            self.assertFalse(self.run_it(d, pins, hooks)['ok'])

    def test_ambiguous_anchor_is_refused(self):
        with self.assertRaises(ValueError):
            bt.apply_ops('a\na\n', [{'op': 'insert_after', 'anchor_lines': ['a'], 'insert': 'b\n'}])


class Recovered(unittest.TestCase):
    def test_recovered_file_installs_pinned_and_refuses_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            write(d, 'data/baseline/rec/a.c', 'int a;\n')
            write(d, 'tree/x/Makefile', '')
            pins = {'target': {}, 'source': {}, 'units': [], 'files': [], 'blocked': [], 'recovered_files': [
                {'path': 'x/a.c', 'bundle': 'data/baseline/rec/a.c', 'blob': bt.blob(b'int a;\n'), 'unit': 'u'}]}
            r = bt.run(d / 'len', d / 'tree', pins, [], d)
            self.assertTrue(r['ok'])
            self.assertEqual((d / 'tree/x/a.c').read_text(), 'int a;\n')
            self.assertFalse(bt.run(d / 'len', d / 'tree', pins, [], d)['ok'])   # destination now exists: refused, not replaced
            (d / 'tree/x/a.c').unlink()
            write(d, 'data/baseline/rec/a.c', 'int b;\n')   # bundle changed after pinning
            r = bt.run(d / 'len', d / 'tree', pins, [], d)
            self.assertFalse(r['ok'])
            self.assertFalse((d / 'tree/x/a.c').exists())

    NDK = Path.home() / 'Library/Android/sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/darwin-x86_64/bin/clang'

    @unittest.skipUnless(NDK.exists(), 'NDK clang not available')
    def test_reloc_sig_masks_only_relocated_operands(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'a.c').write_text('int g; extern int h(int);\nint f(int x) { return h(x + 3) + g + 1000; }\n')
            subprocess.run([str(self.NDK), '--target=aarch64-linux-android29', '-O1', '-fno-pic', '-c', f'{d}/a.c', '-o', f'{d}/a.o'], check=True)
            o = rs.Obj(f'{d}/a.o')
            sig = o.func_signature('f')
            masks = {r[0] // 4: int(r[4], 16) for r in sig['relocations']}
            self.assertTrue(masks and all(r[1] in rs.OPERAND_MASK for r in sig['relocations']))
            raw = bytearray(Path(f'{d}/a.o').read_bytes())
            sec = o.sh[o.fn('f')['shndx']]
            base = sec['off'] + o.fn('f')['val']

            def flipped(word, bit):
                m = bytearray(raw)
                m[base + 4 * word + bit // 8] ^= 1 << (bit % 8)
                (Path(d) / 'm.o').write_bytes(m)
                return rs.Obj(f'{d}/m.o').func_signature('f')['unmasked_sha256']
            for w in range(sig['size'] // 4):
                for bit in range(32):
                    same = flipped(w, bit) == sig['unmasked_sha256']
                    self.assertEqual(same, bool(masks.get(w, 0) >> bit & 1), (w, bit))   # a bit is ignored iff it is a relocation operand bit
            self.assertEqual(rs.check(f'{d}/a.o', {'functions': {'f': {'object': sig}}, 'sections': {}})[0], 0)

    def test_unknown_relocation_type_is_an_error_not_a_full_mask(self):
        self.assertNotIn(999, rs.OPERAND_MASK)
        self.assertEqual(rs.OPERAND_MASK[279], 0x0007ffe0)   # TSTBR14: the tested-bit number is not masked
        self.assertEqual(rs.OPERAND_MASK[283], 0x03ffffff)


STOCK = 'CONFIG_A=y\nCONFIG_B=y\n# CONFIG_C is not set\nCONFIG_D=y\n'
PINS = {'blocked': [{'id': 'touch:D', 'config': 'CONFIG_D', 'expect_path': 'drv/D/Makefile'}], 'no_code_in_shipping': []}
OV = {'neutral_constants': [{'symbol': 'K', 'value': '0'}]}


class Gate(unittest.TestCase):
    def go(self, built, tree=None):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 's').write_text(STOCK)
            (Path(d) / 'b').write_text(built)
            return cg.gate(Path(d) / 's', Path(d) / 'b', PINS, OV, tree)

    def test_listed_gap_is_blocked_never_ok(self):
        r = self.go('CONFIG_A=y\nCONFIG_B=y\n# CONFIG_C is not set\n')
        self.assertEqual(r['status'], 'BLOCKED')
        self.assertEqual(r['open_blocked'], ['touch:D'])

    def test_unlisted_drop_fails(self):
        self.assertEqual(self.go('CONFIG_A=y\n# CONFIG_C is not set\nCONFIG_D=y\n')['status'], 'FAIL')

    def test_added_symbol_fails_unless_neutral_constant(self):
        self.assertEqual(self.go(STOCK + 'CONFIG_E=y\n')['status'], 'FAIL')
        self.assertEqual(self.go(STOCK + 'CONFIG_K=1\n')['status'], 'FAIL')
        self.assertEqual(self.go(STOCK + 'CONFIG_K=0\n', tree='/nonexistent')['status'], 'BLOCKED')

    def test_changed_value_fails(self):
        self.assertEqual(self.go('CONFIG_A=m\nCONFIG_B=y\n# CONFIG_C is not set\nCONFIG_D=y\n')['status'], 'FAIL')

    def test_ok_only_when_nothing_is_blocked(self):
        with tempfile.TemporaryDirectory() as t:
            write(t, 'drv/D/Makefile', '')
            self.assertEqual(self.go(STOCK, tree=t)['status'], 'OK')


if __name__ == '__main__':
    unittest.main()
