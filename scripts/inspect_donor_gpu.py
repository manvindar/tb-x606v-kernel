#!/usr/bin/env python3
"""Extract only graphics libraries/firmware from the donor vendor partition."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from lpunpack import Sparse, parse

source, output = Path(sys.argv[1]), Path(sys.argv[2])
output.mkdir(parents=True, exist_ok=True)
sp = Sparse(source)
parts = [(name, ext) for name, _, ext in parse(sp) if name in ('vendor', 'vendor_a') and ext]
if len(parts) != 1:
    raise ValueError('Expected exactly one vendor partition')
vendor = output / 'vendor.img'
with vendor.open('wb') as f:
    for sectors, kind, sector, block_device in parts[0][1]:
        if block_device != 0 or kind not in (0, 1):
            raise ValueError('Unsupported vendor extent')
        left = sectors * 512
        offset = sector * 512
        while left:
            count = min(left, 8 * 1024**2)
            block = bytes(count) if kind == 1 else sp.read(offset, count)
            if len(block) != count:
                raise ValueError('Short vendor read')
            f.write(block)
            offset += count
            left -= count

def read(path):
    result = subprocess.run(['debugfs', '-R', 'cat ' + path, str(vendor)], capture_output=True, check=True)
    return result.stdout

def listing(path):
    return subprocess.run(['debugfs', '-R', 'ls -p ' + path, str(vendor)], capture_output=True, text=True, check=True).stdout

inventory = {}
for path in ('/build.prop', '/lib/egl', '/lib64/egl', '/firmware'):
    inventory[path] = read(path).decode(errors='replace') if path.endswith('.prop') else listing(path)
(output / 'vendor-inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')
files = []
libraries = ('libsrv_um.so', 'libusc.so', 'libIMGegl.so', 'libglslcompiler.so',
             'libpvrANDROID_WSEGL.so', 'libPVRScopeServices.so',
             'libPVRMtkutils.so', 'libgpu_aux.so', 'libgpud.so',
             'libgralloc_extra.so', 'libged.so')
for abi in ('lib', 'lib64'):
    for name in libraries:
        files.append('/' + abi + '/' + name)
    for name in ('libEGL_mtk.so', 'libGLESv1_CM_mtk.so', 'libGLESv2_mtk.so', 'libGLES_meow.so', 'libMEOW_trace.so'):
        files.append('/' + abi + '/egl/' + name)
for line in inventory['/firmware'].splitlines():
    fields = line.split('/')
    if len(fields) > 5 and fields[5].startswith('rgx'):
        files.append('/firmware/' + fields[5])
records = []
for path in files:
    payload = read(path)
    if not payload:
        continue
    dst = output / path.lstrip('/')
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(payload)
    records.append({'path': path, 'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()})
vendor.unlink()
(output / 'gpu-files.json').write_text(json.dumps({'files': records, 'device_validation': False,
    'source': 'rabbit-hmi-oss/firmware v0.8.293', 'scope': 'Host-only extraction, not Lenovo compatibility'}, indent=2) + '\n')
print(json.dumps(records, indent=2))
