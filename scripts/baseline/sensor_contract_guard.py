#!/usr/bin/env python3
"""Static contract guard for the camera sensor drivers listed in CONFIG_CUSTOM_KERNEL_IMGSENSOR. Host-only, no compiler.

usage: sensor_contract_guard.py IMGSENSOR_ROOT CONFIG RECEIPT.json
IMGSENSOR_ROOT is drivers/misc/mediatek/imgsensor of the candidate tree. Exit 0 only if, for every configured sensor:
  1. src/common/v1/<name>/ exists with a Makefile and at least one .c file;
  2. imgsensor_sensor_list.c has a '#if defined(<NAME>)' entry whose init function is defined by that sensor's sources;
  3. every 'case' label in the sensor's feature_control switch is an enumerator of ACDK_SENSOR_FEATURE_ENUM (or a number) in
     inc/kd_imgsensor_define.h, and no two labels have the same numeric value.
Findings are reported, never repaired: a driver that uses an enumerator its own tree's header lacks is a source mismatch."""
import json, re, sys
from pathlib import Path

ENUM = 'ACDK_SENSOR_FEATURE_ENUM'


def strip(t):
    t = re.sub(r'/\*.*?\*/', '', t, flags=re.S)
    return re.sub(r'//[^\n]*', '', t)


def enum_values(header_text):
    t = strip(header_text)
    defs = {m.group(1): int(m.group(2), 0) for m in re.finditer(r'#define\s+(\w+)\s+(0x[0-9a-fA-F]+|\d+)\b', t)}
    m = re.search(r'enum\s+' + ENUM + r'\s*\{(.*?)\}\s*;', t, flags=re.S)
    if not m:
        raise ValueError(f'enum {ENUM} not found')
    vals, cur = {}, -1
    for item in (x.strip() for x in m.group(1).split(',')):
        if not item:
            continue
        if '=' in item:
            k, v = (s.strip() for s in item.split('=', 1))
            cur = vals[v] if v in vals else defs[v] if v in defs else int(v, 0)
        else:
            k, cur = item, cur + 1
        vals[k] = cur
    return vals


def func_body(text, name):
    """Body of the first function definition called `name` (brace matched), or None."""
    for m in re.finditer(r'\b' + name + r'\s*\(', text):
        i = m.end()
        depth = 1
        while i < len(text) and depth:
            depth += {'(': 1, ')': -1}.get(text[i], 0)
            i += 1
        j = i
        while j < len(text) and text[j] in ' \t\r\n':
            j += 1
        if j < len(text) and text[j] == '{':
            k, depth = j + 1, 1
            while k < len(text) and depth:
                depth += {'{': 1, '}': -1}.get(text[k], 0)
                k += 1
            return text[j:k]
    return None


def case_labels(body):
    """Labels of the outermost switch in `body` only; nested switches (e.g. on the scenario id) are other contracts."""
    m = re.search(r'\bswitch\s*\(', body)
    if not m:
        return []
    i = body.index('{', m.end())
    depth, out = 0, []
    pat = re.compile(r'\bcase\s+([A-Za-z_]\w*|0x[0-9a-fA-F]+|\d+)\s*:')
    k = i
    while k < len(body):
        c = body[k]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                break
        elif depth == 1:
            mm = pat.match(body, k)
            if mm:
                out.append(mm.group(1))
                k = mm.end()
                continue
        k += 1
    return out


def check_sensor(name, root, values, list_text):
    d = root / 'src' / 'common' / 'v1' / name
    f = {'sensor': name, 'problems': []}
    srcs = sorted(d.glob('*.c')) if d.is_dir() else []
    macro = name.upper()
    m = re.search(r'#if\s+defined\(' + macro + r'\)\s*\{[^}]*?(\w+_SensorInit)\s*\}', list_text)
    if not m:
        f['problems'].append({'kind': 'missing-sensor-list-entry', 'macro': macro})
    if not d.is_dir() or not (d / 'Makefile').is_file() or not srcs:
        f['problems'].append({'kind': 'missing-driver-source', 'dir': str(d.relative_to(root))})
        return f
    text = '\n'.join(strip(p.read_text(errors='replace')) for p in srcs)
    if not m:
        pass
    elif not re.search(r'\b' + m.group(1) + r'\s*\(\s*struct\s+SENSOR_FUNCTION_STRUCT', text):
        f['problems'].append({'kind': 'init-function-not-defined', 'function': m.group(1)})
    body = func_body(text, 'feature_control')
    if body is None:
        f['problems'].append({'kind': 'no-feature_control'})
        return f
    seen = {}
    for lab in case_labels(body):
        if lab.isdigit() or lab.lower().startswith('0x'):
            v = int(lab, 0)
        elif lab in values:
            v = values[lab]
        else:
            f['problems'].append({'kind': 'undefined-case-label', 'label': lab})
            continue
        if v in seen and seen[v] != lab:
            f['problems'].append({'kind': 'duplicate-case-value', 'value': v, 'labels': [seen[v], lab]})
        elif v in seen:
            f['problems'].append({'kind': 'duplicate-case-label', 'label': lab})
        seen.setdefault(v, lab)
    f['case_labels'] = len(seen)
    return f


def run(root, config_text):
    root = Path(root)
    m = re.search(r'^CONFIG_CUSTOM_KERNEL_IMGSENSOR="([^"]*)"', config_text, re.M)
    if not m:
        raise ValueError('CONFIG_CUSTOM_KERNEL_IMGSENSOR not set')
    names = m.group(1).split()
    values = enum_values((root / 'inc' / 'kd_imgsensor_define.h').read_text(errors='replace'))
    list_text = strip((root / 'src' / 'common' / 'v1' / 'imgsensor_sensor_list.c').read_text(errors='replace'))
    sensors = [check_sensor(n, root, values, list_text) for n in names]
    return {'enum': ENUM, 'enumerators': len(values), 'sensors': sensors, 'ok': not any(s['problems'] for s in sensors)}


if __name__ == '__main__':
    root, cfg, out = sys.argv[1:4]
    r = run(root, Path(cfg).read_text())
    Path(out).write_text(json.dumps(r, indent=1))
    bad = [(s['sensor'], [p['kind'] for p in s['problems']]) for s in r['sensors'] if s['problems']]
    print('ok' if r['ok'] else f'FAIL {bad}')
    sys.exit(0 if r['ok'] else 1)
