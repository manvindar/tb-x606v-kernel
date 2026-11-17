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


class Instance(unittest.TestCase):
    """instance() finds the LCM_DRIVER by its driver-name string + the relocation record that points at it. The linker may tail-merge the name into a longer string
    ('panel_' + name, seen on the real CI vmlinux for ft8201 and hx83102e), so a name that is not at the start of a string must still be found."""
    NAME = 'mipi_x_video_1200p'
    BASE = 0x1000

    def build(self, strings, reloc_to):
        """strings: list of str placed back to back (NUL separated); reloc_to: index of the string the struct's name pointer targets (None = no record)."""
        mem = bytearray(0x400)
        va, at = {}, 0x100
        for i, st in enumerate(strings):
            mem[at:at + len(st) + 1] = st.encode() + b'\0'
            va[i] = at + self.BASE + (len(st) - len(self.NAME) if st.endswith(self.NAME) else 0)   # address of the NAME inside it
            at += len(st) + 1
        syms = [(self.BASE + 0x300, 8, 'lcm_init'), (self.BASE + 0x308, 8, 'lcm_suspend')]
        s0 = self.BASE + 0x20
        rela = {s0 + 8: self.BASE + 0x300, s0 + 16: self.BASE + 0x308}
        if reloc_to is not None: rela[s0] = va[reloc_to]
        return F.Target('x.elf', 0, syms, bytes(mem), self.BASE, rela)

    def test_name_at_string_start(self):
        r = F.instance(self.build([self.NAME], 0), self.NAME)
        self.assertEqual(sorted(r), ['init', 'suspend'])

    def test_tail_merged_name_is_found(self):
        r = F.instance(self.build(['panel_' + self.NAME], 0), self.NAME)
        self.assertEqual(sorted(r), ['init', 'suspend'])

    def test_the_relocated_occurrence_wins_over_an_unrelocated_one(self):
        t = self.build(['other_' + self.NAME, 'panel_' + self.NAME], 1)    # the struct points at the second; the first is unrelated data
        self.assertEqual(sorted(F.instance(t, self.NAME)), ['init', 'suspend'])

    def test_two_relocated_occurrences_are_ambiguous(self):
        t = self.build(['a_' + self.NAME, 'b_' + self.NAME], 0)
        t.rela[0x1000 + 0x40] = 0x1000 + 0x100 + len('a_' + self.NAME) + 1 + len('b_')   # a second record, at the second occurrence
        with self.assertRaises(SystemExit): F.instance(t, self.NAME)

    def test_name_with_no_relocation_record_is_an_error(self):
        with self.assertRaises(SystemExit): F.instance(self.build(['panel_' + self.NAME], None), self.NAME)

    def test_absent_name(self):
        with self.assertRaises(SystemExit): F.instance(self.build(['panel_other'], 0), self.NAME)


class Scope(unittest.TestCase):
    ROLES = {'init': 0x100, 'suspend': 0x180, 'compare_id': 0x200}

    def test_extra_roles_inside_and_outside_the_panel_object(self):
        r = dict(self.ROLES, set_cabc_mode=0x150, set_recovery_backlight=0x400)
        s = F.role_scopes(r)
        self.assertEqual(s['init'], 'own')
        self.assertEqual(s['set_cabc_mode'], 'inside-object-span')
        self.assertEqual(s['set_recovery_backlight'], 'outside-object-span')      # a neighbouring panel's function

    def test_extra_role_below_the_object_is_outside(self):
        self.assertEqual(F.role_scopes(dict(self.ROLES, set_cabc_mode=0x50))['set_cabc_mode'], 'outside-object-span')


if __name__ == '__main__':
    unittest.main()
