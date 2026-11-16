#!/usr/bin/env python3
"""Inspect the pinned DDK's RGX firmware footer without running firmware."""
import hashlib
import json
from pathlib import Path
import struct
import sys


def inspect(path):
    data = Path(path).read_bytes()
    if len(data) <= 4096:
        raise ValueError('Firmware is too short')
    offset = len(data) - 4096
    version, size, count, stride, packed, page, flags = struct.unpack_from('<IIIIQII', data, offset)
    if version != 1 or size != 32 or stride != 24 or not 0 < count <= 15:
        raise ValueError('Unexpected RGX_FW_INFO_HEADER layout')
    if size + count * stride > 4096:
        raise ValueError('Layout table extends outside footer')
    bvnc = [(packed >> shift) & 65535 for shift in (48, 32, 16, 0)]
    if bvnc != [22, 87, 104, 18] or page != 4096 or flags != 0:
        raise ValueError('Unexpected target, page size or compatibility flags')
    entries = []
    for i in range(count):
        section, kind, base, maximum, allocation, allocation_offset = struct.unpack_from(
            '<IIIIII', data, offset + size + i * stride)
        if section > 14 or kind not in (1, 2, 3, 4) or allocation > maximum:
            raise ValueError('Invalid section layout')
        entries.append(dict(section=section, kind=kind, base=base, maximum=maximum,
                            allocation=allocation, allocation_offset=allocation_offset))
    return dict(path=str(path), sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                bvnc='.'.join(map(str, bvnc)), info_version=version, page_size=page,
                flags=flags, sections=entries, footer_validation=True,
                ddk_build_validation=False, runtime_validation=False,
                scope='Footer and target validation only; DDK build is checked by the running driver')


if __name__ == '__main__':
    print(json.dumps(inspect(sys.argv[1]), indent=2))
