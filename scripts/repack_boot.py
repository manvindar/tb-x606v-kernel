#!/usr/bin/env python3
"""Replace the kernel in a stock Android boot.img (header v2) and keep ramdisk, dtb and cmdline.
usage: repack_boot.py STOCK_BOOT.img NEW_Image.gz-dtb OUT_BOOT.img"""
import struct, sys, hashlib
FMT = '<8s10I16s512s32s1024sIQIIQ'
HLEN = struct.calcsize(FMT)
pad = lambda b, p: b + b'\0' * (-len(b) % p)

stock, kern, out = sys.argv[1:4]
d = open(stock, 'rb').read()
f = list(struct.unpack(FMT, d[:HLEN]))
assert f[0] == b'ANDROID!' and f[9] == 2, 'expected an Android boot header v2'
page = f[8]
ksz, rsz, ssz, dtbsz = f[1], f[3], f[5], f[-2]
off = page
kold = d[off:off + ksz]; off += len(pad(kold, page))
ramdisk = d[off:off + rsz]; off += len(pad(ramdisk, page))
off += len(pad(b'\0' * ssz, page))
dtb = d[off:off + dtbsz]
knew = open(kern, 'rb').read()
f[1] = len(knew)
sha = hashlib.sha1(knew + struct.pack('<I', len(knew)) + ramdisk + struct.pack('<I', rsz) +
                   struct.pack('<I', 0) + dtb + struct.pack('<I', dtbsz)).digest()
f[13] = sha + b'\0' * 12
hdr = struct.pack(FMT, *f)
img = pad(hdr, page) + pad(knew, page) + pad(ramdisk, page) + pad(dtb, page)
open(out, 'wb').write(img)
print(f'{out}: kernel {len(knew)} B (was {ksz}), ramdisk {rsz} B, dtb {dtbsz} B, total {len(img)} B')
