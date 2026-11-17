#!/usr/bin/env python3
"""The Makefile hooks added after run 44032568227 and the ncm.h stub hook added after run 44034228971: the philmb originals (verbatim, base 0a95b50) must hash to the pinned pre-edit
blob, the pinned ops must produce the pinned post-edit blob, and the result must drop exactly the named objects."""
import json, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import board_transplant as bt

HOOKS = json.loads((Path(__file__).resolve().parents[2] / 'data/baseline/stock-board-hooks.json').read_text())
FAT = '#\n# Makefile for the Linux fat filesystem support.\n#\n\nobj-$(CONFIG_FAT_FS) += fat.o\nobj-$(CONFIG_VFAT_FS) += vfat.o\nobj-$(CONFIG_MSDOS_FS) += msdos.o\n\nfat-y := cache.o dir.o fatent.o file.o inode.o misc.o nfs.o xattr.o\nvfat-y := namei_vfat.o\nmsdos-y := namei_msdos.o\n'
LCM = '#\n# Copyright (C) 2015 MediaTek Inc.\n#\n# This program is free software: you can redistribute it and/or modify\n# it under the terms of the GNU General Public License version 2 as\n# published by the Free Software Foundation.\n#\n# This program is distributed in the hope that it will be useful,\n# but WITHOUT ANY WARRANTY; without even the implied warranty of\n# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the\n# GNU General Public License for more details.\n#\n\n#\n# Makefile for misc devices that really don\'t fit anywhere else.\n#\n\nobj-$(CONFIG_MTK_LCM) += mt65xx_lcm_list.o        \\\n                         lcm_common.o             \\\n                         lcm_gpio.o               \\\n                         lcm_i2c.o                \\\n                         lcm_pmic.o               \\\n                         lcm_util.o               \\\n                         sm5109.o                 \\\n                         ocp2131.o                \\\n                         sgm37604a_driver.o\n\nLCM_LISTS := $(subst ",,$(CONFIG_CUSTOM_KERNEL_LCM))\nobj-$(CONFIG_MTK_LCM) += $(foreach LCM,$(LCM_LISTS),$(LCM)/)\n\nsubdir-ccflags-$(CONFIG_MTK_LCM) += -I$(srctree)/drivers/misc/mediatek/lcm/inc\nsubdir-ccflags-$(CONFIG_MTK_FB) += -I$(srctree)/drivers/misc/mediatek/video/$(MTK_PLATFORM)/dispsys \\\n                                       -I$(srctree)/drivers/misc/mediatek/video/$(MTK_PLATFORM)/dispsys/mt6735 \\\n                                       -I$(srctree)/drivers/misc/mediatek/video/$(MTK_PLATFORM)/videox \\\n                                       -I$(srctree)/drivers/misc/mediatek/video/include\n\nLCM_DEFINES := $(shell echo $(CONFIG_CUSTOM_KERNEL_LCM) | tr a-z A-Z)\nDEFINES += $(foreach LCM,$(LCM_DEFINES),$(LCM))\nDEFINES += MTK_LCM_PHYSICAL_ROTATION=\\"$(MTK_LCM_PHYSICAL_ROTATION)\\"\nccflags-$(CONFIG_MTK_LCM) += $(addprefix -D, $(DEFINES))\nccflags-$(CONFIG_MTK_LCM_DEVICE_TREE_SUPPORT) += -DMTK_LCM_DEVICE_TREE_SUPPORT\n\n'

NCM = '/*\n * Copyright (c) 2016 Samsung Electronics Co., Ltd.\n *\n * Network Context Metadata Module[NCM]:Implementation.\n *\n * This program is free software; you can redistribute it and/or modify\n * it under the terms of the GNU General Public License version 2 as\n * published by the Free Software Foundation.\n *\n * This program is distributed in the hope that it will be useful,\n * but WITHOUT ANY WARRANTY; without even the implied warranty of\n * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n * GNU General Public License for more details.\n *\n * You should have received a copy of the GNU General Public License\n * along with this program.  If not, see <http://www.gnu.org/licenses/>.\n */\n\n// KNOX NPA - START\n\n#ifndef NCM_COMMON_H__\n#define NCM_COMMON_H__\n\n#define NCM_VERSION 11\n\n#define INIT_UID_NAP 0\n#define INIT_PID_NAP 1\n#define DNS_PORT_NAP 53\n#define IPV4_FAMILY_NAP 2\n#define IPV6_FAMILY_NAP 10\n#define INET6_ADDRSTRLEN_NAP 48\n\n#define NCM_FLOW_TYPE_DEFAULT -1\n#define NCM_FLOW_TYPE_ALL 0\n#define NCM_FLOW_TYPE_OPEN 1\n#define NCM_FLOW_TYPE_CLOSE 2\n#define NCM_FLOW_TYPE_INTERMEDIATE 3\n\n#include <linux/kernel.h>\n#include <linux/inet.h>\n#include <linux/sched.h>\n#include <linux/string.h>\n#include <net/netfilter/nf_conntrack.h>\n\n#define isIpv4AddressEqualsNull(srcaddr, dstaddr) ((((strcmp(srcaddr, "0.0.0.0")) || (strcmp(dstaddr, "0.0.0.0"))) == 0) ? 1 : 0)\n#define isIpv6AddressEqualsNull(srcaddr, dstaddr) ((((strcmp(srcaddr, "0000:0000:0000:0000:0000:0000:0000:0000")) || (strcmp(dstaddr, "0000:0000:0000:0000:0000:0000:0000:0000"))) == 0) ? 1 : 0)\n\n/* Struct Socket definition */\nstruct knox_socket_metadata {\n/* The source port of the socket */\n\t__u16   srcport;\n/* The destination port of the socket */\n\t__u16   dstport;\n/* The Transport layer protocol of the socket*/\n\t__u16   trans_proto;\n/* The number of application layer bytes sent by the socket */\n\t__u64   knox_sent;\n/* The number of application layer bytes recieved by the socket */\n\t__u64   knox_recv;\n/* The uid which created the socket */\n\tuid_t   knox_uid;\n/* The pid under which the socket was created */\n\tpid_t   knox_pid;\n/* The parent user id under which the socket was created */\n\tuid_t   knox_puid;\n/* The epoch time at which the socket was opened */\n\t__u64   open_time;\n/* The epoch time at which the socket was closed */\n\t__u64   close_time;\n/* The source address of the socket */\n\tchar srcaddr[INET6_ADDRSTRLEN_NAP];\n/* The destination address of the socket */\n\tchar dstaddr[INET6_ADDRSTRLEN_NAP];\n/* The name of the process which created the socket */\n\tchar process_name[PROCESS_NAME_LEN_NAP];\n/* The name of the parent process which created the socket */\n\tchar parent_process_name[PROCESS_NAME_LEN_NAP];\n/*  The Domain name associated with the ip address of the socket. The size needs to be in sync with the userspace implementation */\n\tchar domain_name[DOMAIN_NAME_LEN_NAP];\n/* The uid which originated the dns request */\n\tuid_t   knox_uid_dns;\n/* The parent process id under which the socket was created */\n\tpid_t   knox_ppid;\n/* The interface used by the flow to transmit packet */\n\tchar interface_name[IFNAMSIZ];\n/* The flow type is used identify the current state of the network flow*/\n\tint   flow_type;\n/* The struct defined is responsible for inserting the socket meta-data into kfifo */\n\tstruct work_struct work_kfifo;\n};\n\n/* Struct Socket definition */\nstruct knox_user_socket_metadata {\n/* The source port of the socket */\n\t__u16   srcport;\n/* The destination port of the socket */\n\t__u16   dstport;\n/* The Transport layer protocol of the socket*/\n\t__u16   trans_proto;\n/* The number of application layer bytes sent by the socket */\n\t__u64   knox_sent;\n/* The number of application layer bytes recieved by the socket */\n\t__u64   knox_recv;\n/* The uid which created the socket */\n\tuid_t   knox_uid;\n/* The pid under which the socket was created */\n\tpid_t   knox_pid;\n/* The parent user id under which the socket was created */\n\tuid_t   knox_puid;\n/* The epoch time at which the socket was opened */\n\t__u64   open_time;\n/* The epoch time at which the socket was closed */\n\t__u64   close_time;\n/* The source address of the socket */\n\tchar srcaddr[INET6_ADDRSTRLEN_NAP];\n/* The destination address of the socket */\n\tchar dstaddr[INET6_ADDRSTRLEN_NAP];\n/* The name of the process which created the socket */\n\tchar process_name[PROCESS_NAME_LEN_NAP];\n/* The name of the parent process which created the socket */\n\tchar parent_process_name[PROCESS_NAME_LEN_NAP];\n/*  The Domain name associated with the ip address of the socket. The size needs to be in sync with the userspace implementation */\n\tchar domain_name[DOMAIN_NAME_LEN_NAP];\n/* The uid which originated the dns request */\n\tuid_t   knox_uid_dns;\n/* The parent process id under which the socket was created */\n\tpid_t   knox_ppid;\n/* The interface used by the flow to transmit packet */\n\tchar interface_name[IFNAMSIZ];\n/* The flow type is used identify the current state of the network flow*/\n\tint   flow_type;\n};\n\n/* The list of function which is being referenced */\nextern unsigned int check_ncm_flag(void);\nextern void knox_collect_conntrack_data(struct nf_conn *ct, int startStop, int where);\nextern bool kfifo_status(void);\nextern void insert_data_kfifo_kthread(struct knox_socket_metadata* knox_socket_metadata);\nextern unsigned int check_intermediate_flag(void);\nextern unsigned int get_intermediate_timeout(void);\n\n/* Debug */\n#define NCM_DEBUG        1\n#if NCM_DEBUG\n#define NCM_LOGD(...) printk("ncm: "__VA_ARGS__)\n#else\n#define NCM_LOGD(...)\n#endif /* NCM_DEBUG */\n#define NCM_LOGE(...) printk("ncm: "__VA_ARGS__)\n\n/* IOCTL definitions*/\n#define __NCMIOC    0x120\n#define NCM_ACTIVATED_OPEN       _IO(__NCMIOC, 2)\n#define NCM_DEACTIVATED          _IO(__NCMIOC, 4)\n#define NCM_ACTIVATED_CLOSE      _IO(__NCMIOC, 8)\n#define NCM_ACTIVATED_ALL        _IO(__NCMIOC, 16)\n#define NCM_GETVERSION           _IO(__NCMIOC, 32)\n#define NCM_MATCH_VERSION        _IO(__NCMIOC, 64)\n\n#endif\n\n// KNOX NPA - END\n'


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

    def test_ncm_header_stubs_only_when_knox_ncm_is_off(self):
        out = self.apply('include/net/ncm.h', NCM)
        blk = out.split('#ifndef CONFIG_KNOX_NCM\n', 1)[1].split('#endif /* CONFIG_KNOX_NCM */', 1)[0]
        on, off = blk.split('#else\n', 1)
        for fn in ('check_ncm_flag', 'knox_collect_conntrack_data', 'check_intermediate_flag', 'get_intermediate_timeout'):
            self.assertIn('static inline', [l for l in on.split('\n') if fn in l][0])   # stub when KNOX_NCM is off
            self.assertIn('extern', [l for l in off.split('\n') if fn in l][0])   # real declaration when on
        self.assertEqual(out.count('#ifndef CONFIG_KNOX_NCM'), 1)

    def test_changed_makefile_is_refused(self):
        with self.assertRaises(AssertionError):
            self.apply('fs/fat/Makefile', FAT + '# x\n')


if __name__ == '__main__':
    unittest.main()
