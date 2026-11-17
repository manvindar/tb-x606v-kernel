#!/usr/bin/env python3
"""The two Makefile hooks added after run 44032568227: the philmb originals (verbatim, base 0a95b50) must hash to the pinned pre-edit
blob, the pinned ops must produce the pinned post-edit blob, and the result must drop exactly the named objects."""
import json, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import board_transplant as bt

HOOKS = json.loads((Path(__file__).resolve().parents[2] / 'data/baseline/stock-board-hooks.json').read_text())
FAT = '#\n# Makefile for the Linux fat filesystem support.\n#\n\nobj-$(CONFIG_FAT_FS) += fat.o\nobj-$(CONFIG_VFAT_FS) += vfat.o\nobj-$(CONFIG_MSDOS_FS) += msdos.o\n\nfat-y := cache.o dir.o fatent.o file.o inode.o misc.o nfs.o xattr.o\nvfat-y := namei_vfat.o\nmsdos-y := namei_msdos.o\n'
LCM = '#\n# Copyright (C) 2015 MediaTek Inc.\n#\n# This program is free software: you can redistribute it and/or modify\n# it under the terms of the GNU General Public License version 2 as\n# published by the Free Software Foundation.\n#\n# This program is distributed in the hope that it will be useful,\n# but WITHOUT ANY WARRANTY; without even the implied warranty of\n# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the\n# GNU General Public License for more details.\n#\n\n#\n# Makefile for misc devices that really don\'t fit anywhere else.\n#\n\nobj-$(CONFIG_MTK_LCM) += mt65xx_lcm_list.o        \\\n                         lcm_common.o             \\\n                         lcm_gpio.o               \\\n                         lcm_i2c.o                \\\n                         lcm_pmic.o               \\\n                         lcm_util.o               \\\n                         sm5109.o                 \\\n                         ocp2131.o                \\\n                         sgm37604a_driver.o\n\nLCM_LISTS := $(subst ",,$(CONFIG_CUSTOM_KERNEL_LCM))\nobj-$(CONFIG_MTK_LCM) += $(foreach LCM,$(LCM_LISTS),$(LCM)/)\n\nsubdir-ccflags-$(CONFIG_MTK_LCM) += -I$(srctree)/drivers/misc/mediatek/lcm/inc\nsubdir-ccflags-$(CONFIG_MTK_FB) += -I$(srctree)/drivers/misc/mediatek/video/$(MTK_PLATFORM)/dispsys \\\n                                       -I$(srctree)/drivers/misc/mediatek/video/$(MTK_PLATFORM)/dispsys/mt6735 \\\n                                       -I$(srctree)/drivers/misc/mediatek/video/$(MTK_PLATFORM)/videox \\\n                                       -I$(srctree)/drivers/misc/mediatek/video/include\n\nLCM_DEFINES := $(shell echo $(CONFIG_CUSTOM_KERNEL_LCM) | tr a-z A-Z)\nDEFINES += $(foreach LCM,$(LCM_DEFINES),$(LCM))\nDEFINES += MTK_LCM_PHYSICAL_ROTATION=\\"$(MTK_LCM_PHYSICAL_ROTATION)\\"\nccflags-$(CONFIG_MTK_LCM) += $(addprefix -D, $(DEFINES))\nccflags-$(CONFIG_MTK_LCM_DEVICE_TREE_SUPPORT) += -DMTK_LCM_DEVICE_TREE_SUPPORT\n\n'


def hook(f):
    return [h for h in HOOKS if h['file'] == f][0]


class MakefileHooks(unittest.TestCase):
    def apply(self, f, text):
        h = hook(f)
        self.assertEqual(bt.blob(text.encode()), h['pre_blob'])
        out = bt.apply_ops(text, h['ops'])
        self.assertEqual(bt.blob(out.encode()), h['post_blob'])
        return out

    def test_fat_xattr_object_is_conditional(self):
        out = self.apply('fs/fat/Makefile', FAT)
        self.assertIn('fat-$(CONFIG_FAT_VIRTUAL_XATTR) += xattr.o', out)
        self.assertNotIn('nfs.o xattr.o', out)

    def test_lcm_drops_only_the_three_duplicates(self):
        out = self.apply('drivers/misc/mediatek/lcm/Makefile', LCM)
        for gone in ('sm5109.o', 'ocp2131.o', 'sgm37604a_driver.o'):
            self.assertIn(gone, LCM)
            self.assertNotIn(gone, out)
        for kept in ('mt65xx_lcm_list.o', 'lcm_common.o', 'lcm_gpio.o', 'lcm_i2c.o', 'lcm_pmic.o', 'lcm_util.o'):
            self.assertIn(kept, out)
        self.assertNotIn('lcm_util.o \\', out)   # no dangling continuation after the last object

    def test_changed_makefile_is_refused(self):
        with self.assertRaises(AssertionError):
            self.apply('fs/fat/Makefile', FAT + '# x\n')


if __name__ == '__main__':
    unittest.main()
