#!/usr/bin/env python3
"""lcm_registration must catch, before CI, the two failures of run 44043020010 (empty lcm_driver_list, AW2016 charger_class.h) and the
nearby ways panel wiring breaks: missing extern, duplicate entry, wrong/missing definition, unbuilt object, entry for no configured panel."""
import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lcm_registration as L

CFG = 'CONFIG_MTK_LCM=y\nCONFIG_CUSTOM_KERNEL_LCM="panel_a panel_b"\n'
LIST_C = '''struct LCM_DRIVER *lcm_driver_list[] = {
#if defined(PANEL_A)
	&a_lcm_drv,
#endif

#if defined(PANEL_B)
	&b_lcm_drv,
#endif

#if defined(PANEL_OFF)
	&off_lcm_drv,
#endif
};
'''
LIST_H = 'extern struct LCM_DRIVER a_lcm_drv;\nextern struct LCM_DRIVER b_lcm_drv;\nextern struct LCM_DRIVER off_lcm_drv;\n'


def build(root, list_c=LIST_C, list_h=LIST_H, b_def='struct LCM_DRIVER b_lcm_drv = {', mk_b='obj-$(CONFIG_MTK_LCM) += panel_b.o\n', aw=True):
    def w(p, t):
        p = os.path.join(root, p); os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'w') as f: f.write(t)
    w(L.LIST_C, list_c); w(L.LIST_H, list_h)
    w(L.LCM + '/panel_a/panel_a.c', 'struct LCM_DRIVER a_lcm_drv = {\n};\n'); w(L.LCM + '/panel_a/Makefile', 'obj-$(CONFIG_MTK_LCM) += panel_a.o\n')
    w(L.LCM + '/panel_b/panel_b.c', b_def + '\n};\n'); w(L.LCM + '/panel_b/Makefile', mk_b)
    if aw:
        w('drivers/leds/leds-aw2016.c', '#include <charger_class.h>\n')
        w('drivers/leds/Makefile', 'CFLAGS_leds-aw2016.o += -I$(srctree)/inc/mt-plat\n')
        w('inc/mt-plat/charger_class.h', '')


class Guard(unittest.TestCase):
    def run_check(self, **kw):
        with tempfile.TemporaryDirectory() as d:
            build(d, **kw)
            p, rep = L.check(d, CFG)
            p2, _ = L.check_aw2016(d)
            return p + p2, rep

    def test_complete_wiring_passes_and_keeps_unconfigured_entry_conditional(self):
        p, rep = self.run_check()
        self.assertEqual(p, [])
        self.assertEqual(rep['active_entries'], ['a_lcm_drv', 'b_lcm_drv'])
        self.assertEqual(rep['conditional_entries_in_list'], 3)

    def test_run_44043020010_empty_list(self):
        p, _ = self.run_check(list_c='struct LCM_DRIVER *lcm_driver_list[] = {\n#if defined(PANEL_OTHER)\n\t&x_lcm_drv,\n#endif\n};\n')
        self.assertTrue(any('empty' in x for x in p))
        self.assertTrue(any('panel_a' in x for x in p) and any('panel_b' in x for x in p))

    def test_one_missing_registration(self):
        p, _ = self.run_check(list_c=LIST_C.replace('#if defined(PANEL_B)\n\t&b_lcm_drv,\n#endif\n', ''))
        self.assertEqual([x.split(':')[0] for x in p], ['panel_b'])

    def test_missing_extern(self):
        p, _ = self.run_check(list_h=LIST_H.replace('extern struct LCM_DRIVER b_lcm_drv;\n', ''))
        self.assertTrue(any('no extern declaration of b_lcm_drv' in x for x in p))

    def test_duplicate_entry(self):
        p, _ = self.run_check(list_c=LIST_C.replace('\t&b_lcm_drv,\n', '\t&b_lcm_drv,\n\t&b_lcm_drv,\n'))
        self.assertTrue(any('duplicate list entry b_lcm_drv' in x for x in p))

    def test_entry_without_definition_in_the_panel_dir(self):
        p, _ = self.run_check(b_def='struct LCM_DRIVER renamed_lcm_drv = {')
        self.assertTrue(any(x.startswith('panel_b: 0 enabled') for x in p))

    def test_object_not_built(self):
        p, _ = self.run_check(mk_b='obj-$(CONFIG_MTK_LCM) += other.o\n')
        self.assertTrue(any('does not build panel_b.o' in x for x in p))

    def test_unbalanced_conditional_is_an_error_not_a_pass(self):
        p, _ = self.run_check(list_c=LIST_C.replace('#endif\n\n#if defined(PANEL_B)', '\n#if defined(PANEL_B)'))
        self.assertTrue(p)

    def test_aw2016_include_hook(self):
        with tempfile.TemporaryDirectory() as d:
            build(d)
            self.assertEqual(L.check_aw2016(d), ([], 'inc/mt-plat'))
            with open(os.path.join(d, 'drivers/leds/Makefile'), 'w') as f: f.write('obj-y += leds-aw2016.o\n')
            self.assertTrue(L.check_aw2016(d)[0])


if __name__ == '__main__':
    unittest.main()
