#!/usr/bin/env python3
"""Gate a candidate kernel build against the shipping Lenovo 4.9.190+ kernel and module set. Host-only.

PASS (exit 0) requires ALL of:
  1. kernel release is exactly 4.9.190+ and every installed module's vermagic equals the vermagic string in the kernel image;
  2. the inventory holds exactly the EXPECTED installed modules (Wi-Fi/GPS/FM/BT/fpsgo/met included), each parsed with
     a non-empty __versions and module_layout;
  3. every import of every module resolves, with an equal CRC, to a vmlinux export in the candidate Module.symvers or to an
     export of another inventoried module; a missing import or a CRC mismatch fails.
Total export drift against the shipping kernel is reported but NOT gated (use --strict-exports to gate it).
PASS is necessary only: DTB, board/peripheral source differences and GPU userspace/firmware pairing remain separate gates."""
import argparse, json, re, sys, zlib
from pathlib import Path

RELEASE = '4.9.190+'
EXPECTED = ['bt_drv', 'fmradio_drv', 'fpsgo', 'gps_drv', 'met', 'wlan_drv_gen4m', 'wmt_chrdev_wifi', 'wmt_drv']
REMAINING_GATES = ['DTB/appended-DTB vs retained carrier', 'board/peripheral source differences', 'GPU userspace/firmware pairing', 'guarded boot-only flash']


def kernel_identity(image):
    b = Path(image).read_bytes()
    i = b.find(b'\x1f\x8b\x08')
    if i < 0:
        raise ValueError('no gzip payload in image')
    k = zlib.decompressobj(31).decompress(b[i:])
    m = re.search(rb'Linux version (\S+)', k)
    if not m:
        raise ValueError('no Linux version string in kernel')
    release = m.group(1).decode()
    vermagics = {x.decode() for x in re.findall(re.escape(release.encode()) + rb' SMP[ -~]*?aarch64', k)}
    return release, vermagics


def read_symvers(path):
    kernel = {}
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        f = line.split('\t')
        if len(f) < 3:
            raise ValueError(f'invalid Module.symvers row {n}')
        crc, name, origin = int(f[0], 16), f[1], f[2]
        if origin == 'vmlinux':
            if kernel.get(name, crc) != crc:
                raise ValueError('conflicting vmlinux symbol CRCs')
            kernel[name] = crc
    if len(kernel) < 1000:
        raise ValueError('Module.symvers has too few vmlinux exports')
    return kernel


def gate(symvers, image, inventory, shipping=None, strict_exports=False):
    problems = []
    release, vermagics = kernel_identity(image)
    if release != RELEASE:
        problems.append(f'kernel release {release} != {RELEASE}')
    mods = json.loads(Path(inventory).read_text()).get('modules') if Path(inventory).is_file() else None
    if not mods:
        raise ValueError('empty or missing module inventory')
    missing, extra = sorted(set(EXPECTED) - set(mods)), sorted(set(mods) - set(EXPECTED))
    if missing or extra:
        problems.append(f'module inventory mismatch: missing {missing} extra {extra}')
    kernel = read_symvers(symvers)
    providers = {}
    for name, m in mods.items():
        for sym, crc in m.get('exports', {}).items():
            providers.setdefault(sym, []).append((name, crc))
    report_modules = {}
    for name, m in sorted(mods.items()):
        imports = m.get('imports') or {}
        if not imports or 'module_layout' not in imports:
            problems.append(f'{name}: empty __versions or no module_layout')
        if m.get('vermagic') not in vermagics:
            problems.append(f'{name}: vermagic {m.get("vermagic")!r} not in kernel {sorted(vermagics)}')
        bad = []
        for sym, crc in sorted(imports.items()):
            if sym in kernel:
                if kernel[sym] != crc:
                    bad.append((sym, 'kernel CRC differs'))
            else:
                p = [c for n, c in providers.get(sym, []) if n != name]
                if not p:
                    bad.append((sym, 'unresolved'))
                elif crc not in p:
                    bad.append((sym, 'provider CRC differs'))
        report_modules[name] = dict(imports=len(imports), failures=len(bad), first=bad[:5])
        if bad:
            problems.append(f'{name}: {len(bad)} import failures, e.g. {bad[:3]}')
    drift = absent = None
    if shipping:
        ship = json.loads(Path(shipping).read_text())['shipping_export_crcs']
        drift = sum(1 for s, c in ship.items() if s in kernel and kernel[s] != c)
        absent = sum(1 for s in ship if s not in kernel)
        if strict_exports and (drift or absent):
            problems.append(f'strict exports: {drift} drifted, {absent} absent')
    return dict(release=release, kernel_vermagics=sorted(vermagics), modules=report_modules, export_drift=drift,
                shipping_exports_absent=absent, strict_exports=strict_exports, problems=problems,
                gate='PASS' if not problems else 'FAIL', necessary_not_sufficient=True, remaining_gates=REMAINING_GATES)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--symvers', required=True); p.add_argument('--image', required=True)
    p.add_argument('--inventory', required=True); p.add_argument('--shipping-exports')
    p.add_argument('--strict-exports', action='store_true'); p.add_argument('--report')
    a = p.parse_args()
    try:
        r = gate(a.symvers, a.image, a.inventory, a.shipping_exports, a.strict_exports)
    except (ValueError, OSError, zlib.error) as e:
        r = dict(gate='FAIL', problems=[f'gate error: {e}'])
    print(json.dumps(r, indent=1))
    if a.report:
        Path(a.report).write_text(json.dumps(r, indent=1))
    sys.exit(0 if r['gate'] == 'PASS' else 1)
