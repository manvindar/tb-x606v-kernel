#!/usr/bin/env python3
"""fncompare must not depend on how llvm-objdump prints pc-relative operands (run 44036431871: LLVM 9 printed 'adrp x8, #0x1000' and broke the compare).
fixtures/llvm9-operands.json is a REAL capture of the pinned toolchain's llvm-objdump (LLVM 9.0.9svn, same major as CI's clang r353983c) on a synthetic function
(make_llvm9_fixture.py regenerates it). Unsupported syntax must be reported NOT MEASURED, never as a mismatch."""
import json, os, struct, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fncompare as F

FIX = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures/llvm9-operands.json')))
BASE, FUNC, EXT = FIX['base'], FIX['func_bytes'], 0x2000
EXPECT = ['stp x29, x30, [sp, #-0x10]!', 'bl EXT:ext_fn', 'adrp x8, PAGE', "add x8, x8, STR:'hi'", 'adrp x9, PAGE', 'ldr x0, [x9, #PAGEOFF]',
          'cbz x0, F+0x24', 'tbnz w1, #0x5, F+0x28', 'b.eq F+0x2c', 'adr x2, ADDR', 'b EXT:ext_fn', 'ret']


def target(words=None):
    mem = bytearray(0x3000)
    for i, w in enumerate(words or FIX['words']): mem[4 * i:4 * i + 4] = struct.pack('<I', w)
    mem[0x1010:0x1013] = b'hi\0'
    return F.Target('x.elf', 0, [(BASE, FUNC, 'func'), (BASE + EXT, 0x10, 'ext_fn')], bytes(mem), BASE, {})


class Normalize(unittest.TestCase):
    def run_lines(self, lines, words=None):
        old = F.disasm
        F.disasm = lambda t, s, e: [tuple(x) for x in lines]
        try:
            return F.normalize2(target(words), BASE, BASE + FUNC)
        finally:
            F.disasm = old

    def test_real_llvm9_operand_syntax(self):
        text, words = self.run_lines(FIX['lines'])
        self.assertEqual(text, EXPECT)
        self.assertEqual(len(words), 12)

    def test_absolute_operand_syntax_gives_the_same_result(self):      # a newer objdump prints 0xADDR instead of #offset
        lines = [list(x) for x in FIX['lines']]
        new = {1: 'bl 0x%x' % (BASE + EXT), 2: 'adrp x8, 0x%x' % (BASE + 0x1000), 4: 'adrp x9, 0x%x' % (BASE + 0x2000), 6: 'cbz x0, 0x%x' % (BASE + 0x24),
               7: 'tbnz w1, #0x5, 0x%x' % (BASE + 0x28), 8: 'b.eq 0x%x' % (BASE + 0x2c), 9: 'adr x2, 0x%x' % (BASE + 0x24), 10: 'b 0x%x' % (BASE + EXT)}
        for i, t in new.items(): lines[i][1], lines[i][2] = t.split(' ', 1)
        self.assertEqual(self.run_lines(lines), self.run_lines(FIX['lines']))

    def test_unsupported_forms_are_not_measured(self):
        lines = [list(x) for x in FIX['lines']]
        bad = [list(x) for x in lines]; bad[2][1] = 'bl'                # printed mnemonic disagrees with the instruction word
        with self.assertRaises(F.Unsupported): self.run_lines(bad)
        bad = [list(x) for x in lines]; bad[3][1] = '.inst'             # undecodable
        with self.assertRaises(F.Unsupported): self.run_lines(bad)
        bad = [list(x) for x in lines]; bad[2][2] = 'x9, #0x1000'       # adrp destination register disagrees with the word
        with self.assertRaises(F.Unsupported): self.run_lines(bad)


class Judge(unittest.TestCase):
    W = dict(sha256='a', wsha256='w', insns=1, bytes=4)

    def test_only_decoded_words_establish_a_difference(self):
        self.assertEqual(F.judge(self.W, dict(sha256='a', wsha256='w')), 'normalized-instruction-identical')
        self.assertEqual(F.judge(self.W, dict(sha256='b', wsha256='w')), 'words-identical-text-differs')   # printing difference only
        self.assertEqual(F.judge(self.W, dict(sha256='a', wsha256='x')), 'differs')
        self.assertEqual(F.judge(self.W, dict(not_measured='why')), 'not-measured')
        self.assertEqual(F.judge(dict(sha256='a'), dict(sha256='b', wsha256='w')), 'differs')              # old fingerprints: text only

    def test_exit_code_keeps_not_measured_separate(self):
        m = F.MATCH[0]
        self.assertEqual(F.exit_code([m, m]), 0)
        self.assertEqual(F.exit_code([m, 'not-measured']), 2)
        self.assertEqual(F.exit_code([m, 'differs']), 1)
        self.assertEqual(F.exit_code(['differs', 'not-measured']), 3)
        self.assertEqual(F.exit_code([m, 'missing-in-candidate']), 1)


if __name__ == '__main__':
    unittest.main()
