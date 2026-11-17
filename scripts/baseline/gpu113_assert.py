#!/usr/bin/env python3
"""Post-build assertions: which PowerVR DDK did the Image actually get? Selector, built objects, linked symbols, exports and the version string must all say the same thing.

usage: gpu113_assert.py --expect ddk113|none --tree SRC --config .config --nm vmlinux-nm.txt --vmlinux vmlinux --symvers Module.symvers
                        --symbols gpu113-symbols.json --compile-errors FILE --report OUT.json [--build-log build.log]
--expect ddk113: the 1.13 driver must be selected, built, linked, exported and version-stamped, and the 1.11 driver must be absent from all of those.
--expect none (the control build): the reverse, i.e. the shipping 1.11 driver and none of 1.13.
Each check is PASS, FAIL or NOT_MEASURED (an input is missing). Exit 0 = every check PASS, 1 = a FAIL, 2 = only NOT_MEASURED. The names come from the host measurement in
gpu113-symbols.json; a CI nm that disagrees is the finding, not an error of this tool. Passing says which driver was linked; it says nothing about firmware, userspace or runtime."""
import argparse, json, os, re, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gpu113_integrate as gi

SEL = 'drivers/misc/mediatek/gpu/gpu_rgx'
DEFINED = set('TDBRVWSAGC')   # nm type letters of a defined GLOBAL symbol (lower case = file-local, which says nothing about the driver's own global names; U undefined)


def read_nm(path):
    d = {}
    for l in Path(path).read_text(errors='ignore').splitlines():
        f = l.split()
        if len(f) == 3 and f[1] in DEFINED:
            d.setdefault(f[2], f[1])
    return d


def read_symvers(path):
    return {l.split('\t')[1] for l in Path(path).read_text(errors='ignore').splitlines() if l.count('\t') >= 1}


def config_value(path):
    m = re.search(r'^CONFIG_MTK_GPU_VERSION="([^"]*)"', Path(path).read_text(errors='ignore'), re.M)
    return m.group(1) if m else None


def chk(name, status, **detail):
    return {'check': name, 'status': status, **detail}


def run(a):
    sym = json.loads(Path(a.symbols).read_text())
    want, other = (sym['ddk113'], sym['ddk111']) if a.expect == 'ddk113' else (sym['ddk111'], sym['ddk113'])
    out = []
    tree = Path(a.tree)
    # 1. the selector, evaluated by GNU make on the real file with the real config value
    val = config_value(a.config) if a.config and os.path.isfile(a.config) else None
    sel = tree / SEL / 'Makefile'
    if val is None or not sel.is_file():
        out.append(chk('selector', 'NOT_MEASURED', why='no config value or selector file'))
    else:
        objs = gi.selector_value_objs(sel, val)
        out.append(chk('selector', 'PASS' if objs == [want['dir']] else 'FAIL', config_value=val, obj_y=objs, expected=[want['dir']]))
    if a.build_log and os.path.isfile(a.build_log):
        hits = [l.strip() for l in Path(a.build_log).read_text(errors='ignore').splitlines() if 'MTK_GPU_VERSION 2 =' in l]
        out.append(chk('build_log_selector_line', 'PASS' if hits and len(set(hits)) == 1 else 'FAIL', lines=sorted(set(hits))[:3]))
    # 2. the directories the build produced (out/ tree next to the selector)
    outdir = Path(a.out) if a.out else None
    if outdir and (outdir / SEL).is_dir():
        wd, od = outdir / SEL / want['dir'], outdir / SEL / other['dir']
        n_want = len([p for p in wd.rglob('*.o') if p.name not in ('built-in.o', 'pvrsrvkm.o')]) if wd.is_dir() else 0
        n_other = len([p for p in od.rglob('*.o')]) if od.is_dir() else 0
        ok = (wd / 'built-in.o').is_file() and n_other == 0 and (want.get('objects') is None or n_want == want['objects'])
        out.append(chk('built_objects', 'PASS' if ok else 'FAIL', wanted_dir_objects=n_want, expected_objects=want.get('objects'), other_dir_objects=n_other,
                       wanted_built_in=(wd / 'built-in.o').is_file()))
    else:
        out.append(chk('built_objects', 'NOT_MEASURED', why='no build output directory'))
    # 3. compile errors inside the chosen driver
    if a.compile_errors and os.path.isfile(a.compile_errors):
        errs = [l for l in Path(a.compile_errors).read_text(errors='ignore').splitlines() if 'gpu_rgx/' in l]
        out.append(chk('gpu_compile_errors', 'PASS' if not errs else 'FAIL', error_lines=len(errs), first=[e.strip()[:200] for e in errs[:3]]))
    else:
        out.append(chk('gpu_compile_errors', 'NOT_MEASURED', why='no compile-errors file'))
    # 4. linked symbols
    if a.nm and os.path.isfile(a.nm):
        nm = read_nm(a.nm)
        miss = [n for n in want['only'] if n not in nm]
        extra = [n for n in other['only'] if n in nm]
        out.append(chk('symbols', 'PASS' if not miss and not extra else 'FAIL', wanted_only=len(want['only']), wanted_missing=miss[:20], wanted_missing_count=len(miss),
                       other_only=len(other['only']), other_present=extra[:20], other_present_count=len(extra)))
    else:
        out.append(chk('symbols', 'NOT_MEASURED', why='no linked-symbol list (no vmlinux)'))
    # 5. exports of the module symbol table
    if a.symvers and os.path.isfile(a.symvers):
        have = read_symvers(a.symvers)
        miss = [n for n in want['exports'] if n not in have]
        extra = [n for n in set(other['exports']) - set(want['exports']) if n in have]
        out.append(chk('exports', 'PASS' if not miss and not extra else 'FAIL', wanted=len(want['exports']), wanted_missing=miss, other_only_present=sorted(extra)))
    else:
        out.append(chk('exports', 'NOT_MEASURED', why='no Module.symvers'))
    # 6. the version string compiled into the kernel image
    if a.vmlinux and os.path.isfile(a.vmlinux):
        data = Path(a.vmlinux).read_bytes()
        has_w, has_o = want['version_string'].encode() in data, other['version_string'].encode() in data
        out.append(chk('version_string', 'PASS' if has_w and not has_o else 'FAIL', wanted=want['version_string'], wanted_present=has_w, other_present=has_o))
    else:
        out.append(chk('version_string', 'NOT_MEASURED', why='no vmlinux'))
    # 7. the latent donor path that still passes a device index (MTKCalPowerIndex) must stay compiled out
    if a.expect == 'ddk113':
        d13 = tree / SEL / sym['ddk113']['dir']
        if d13.is_dir():
            hits = [str(p.relative_to(tree)) for p in d13.rglob('*') if p.is_file() and p.suffix in ('.h', '.mk', '') and re.search(rb'^\s*#\s*define\s+MTK_CAL_POWER_INDEX\b|-DMTK_CAL_POWER_INDEX', p.read_bytes(), re.M)]
            out.append(chk('latent_cal_power_index_off', 'PASS' if not hits else 'FAIL', defined_in=hits))
        else:
            out.append(chk('latent_cal_power_index_off', 'NOT_MEASURED', why='1.13 directory not staged'))
    return out


def verdict(checks):
    st = [c['status'] for c in checks]
    return 1 if 'FAIL' in st else 2 if 'NOT_MEASURED' in st else 0


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    for n in ('expect', 'tree', 'config', 'nm', 'vmlinux', 'symvers', 'symbols', 'compile-errors', 'report', 'build-log', 'out'):
        ap.add_argument('--' + n, default=None)
    a = ap.parse_args()
    a.compile_errors, a.build_log = getattr(a, 'compile_errors'), getattr(a, 'build_log')
    assert a.expect in ('ddk113', 'none')
    checks = run(a)
    rc = verdict(checks)
    Path(a.report).write_text(json.dumps({'expect': a.expect, 'exit': rc, 'checks': checks, 'not_claimed': 'firmware, userspace, runtime behaviour, or that the 1.13 driver works on this SoC'}, indent=1))
    for c in checks:
        print(f"{c['status']:12} {c['check']}")
    sys.exit(rc)
