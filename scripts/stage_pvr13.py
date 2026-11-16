#!/usr/bin/env python3
"""Stage the pinned PowerVR 1.13 driver in Lenovo's 4.9 source tree.

This is a build candidate, not firmware compatibility or flash approval.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

BASE_COMMIT = '7f6a59c5b8d6ee27b29c91d07f77ec97393f3544'
DONOR_COMMIT = '8167c8c1087f057d2ef302fc93b47554291687ec'
VERSION = 'm1.13ED5776728'

def revision(path):
    return subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()

def stage(base, donor, receipt):
    if revision(base) != BASE_COMMIT or revision(donor) != DONOR_COMMIT:
        raise ValueError('Unexpected source identity')
    source = donor / 'drivers/gpu/mediatek/gpu_rgx' / VERSION
    parent = base / 'drivers/misc/mediatek/gpu/gpu_rgx'
    target = parent / VERSION
    if target.exists():
        raise ValueError('Refusing to overwrite an existing staged driver')
    for p in source.rglob('*'):
        if p.is_symlink():
            raise ValueError('Unexpected donor symlink: ' + str(p))
    shutil.copytree(source, target)
    makefile = target / 'Makefile'
    text = makefile.read_text()
    original_make_sha = hashlib.sha256(makefile.read_bytes()).hexdigest()
    text = 'MTK_PLATFORM := $(subst \",,$(CONFIG_MTK_PLATFORM))\nMTK_GPU_VERSION := $(subst \",,$(CONFIG_MTK_GPU_VERSION))\n' + text
    text = text.replace('drivers/gpu/mediatek/ged/include', 'drivers/misc/mediatek/gpu/ged/include')
    text = text.replace('drivers/gpu/mediatek/gpufreq/include', 'drivers/misc/mediatek/base/power/$(MTK_PLATFORM)')
    text = text.replace('drivers/gpu/mediatek/gpu_bm', 'drivers/misc/mediatek/gpu/hal')
    makefile.write_text(text)
    for config in target.glob('include/config_kernel_*mt6765*.h'):
        config_text = config.read_text()
        config_text = config_text.replace('../drivers/staging/android/aosp_ion/ion.h',
                                          '../drivers/staging/android/ion/ion.h')
        config.write_text(config_text)
    # Older ION's exported allocator API is already handled by the donor's
    # <4.12 branch. Supply Lenovo's allocator declarations at the new layout.
    ion_header = parent / 'm1.10ED5130912/services/system/rgx_mtk/mtk_ion_support.h'
    shutil.copy2(ion_header, target / 'services/system/rogue/rgx_mtk/mtk_ion_support.h')
    selector = parent / 'Makefile'
    previous = selector.read_text()
    selector.write_text('ifeq ($(findstring pvr13,$(CONFIG_MTK_GPU_VERSION)),pvr13)\nobj-y += ' + VERSION + '/\nelse\n' + previous + '\nendif\n')
    files = [{'path': str(p.relative_to(target)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
             for p in sorted(target.rglob('*')) if p.is_file()]
    receipt.write_text(json.dumps({
        'base_source': BASE_COMMIT, 'donor_source': DONOR_COMMIT,
        'driver': '1.13@5776728', 'gpu_bvnc': '22.87.104.18',
        'original_makefile_sha256': original_make_sha, 'staged_files': files,
        'firmware_validation': False, 'userspace_validation': False,
        'shipping_kernel_source_match': False, 'device_validation': False,
        'scope': 'Compile port against available Lenovo 4.9.117 interfaces; shipping kernel is 4.9.190+',
    }, indent=2) + '\n')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('base', type=Path)
    parser.add_argument('donor', type=Path)
    parser.add_argument('receipt', type=Path)
    args = parser.parse_args()
    stage(args.base.resolve(), args.donor.resolve(), args.receipt.resolve())
