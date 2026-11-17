#!/usr/bin/env python3
"""python3 lcm_registration.py TREE CONFIG [OUT.json]

Pre-build guard (run 44043020010 died at mt65xx_lcm_list.c:1272 because no CONFIG_CUSTOM_KERNEL_LCM panel was registered).
Evaluates the real lcm_driver_list[] of TREE for the panels named in CONFIG and checks, without a compiler:
  - the list is not empty (the COMPILE_ASSERT) and has no duplicate entry;
  - every enabled panel has exactly one entry, with an extern declaration in mt65xx_lcm_list.h;
  - that entry's symbol is defined (`struct LCM_DRIVER <sym> =`) by exactly one .c of the panel's own directory, and that directory's
    Makefile builds the file (obj-... += <file>.o); no other enabled panel defines the same symbol;
  - entries for panels that are not enabled stay conditional (they are ignored here, never required).
It also checks that the AW2016 LED driver's charger_class.h resolves through the per-object include path hook, if the file is present.
Exit 0 = all checks hold, 1 = a check failed. Static text evaluation of simple `#if defined(X)` groups; anything else in the list block fails loudly."""
import json, os, re, sys

LIST_C = 'drivers/misc/mediatek/lcm/mt65xx_lcm_list.c'
LIST_H = 'drivers/misc/mediatek/lcm/mt65xx_lcm_list.h'
LCM = 'drivers/misc/mediatek/lcm'


def read(tree, p):
    with open(os.path.join(tree, p), errors='ignore') as f:
        return f.read()


def config_panels(config_text):
    m = re.search(r'^CONFIG_CUSTOM_KERNEL_LCM="([^"]*)"', config_text, re.M)
    return m.group(1).split() if m else []


def list_entries(text, defined):
    """Entries of lcm_driver_list[] active under the defined macros. Only plain `#if defined(X)` / `#endif` groups are understood."""
    m = re.search(r'struct LCM_DRIVER \*lcm_driver_list\[\]\s*=\s*\{(.*?)\n\};', text, re.S)
    if not m:
        raise ValueError('lcm_driver_list[] block not found')
    active, depth, entries, allsyms = [], 0, [], []
    for line in m.group(1).split('\n'):
        s = line.strip()
        if not s:
            continue
        mi = re.fullmatch(r'#if\s+defined\(\s*(\w+)\s*\)', s)
        if mi:
            active.append(mi.group(1) in defined); depth += 1; continue
        if s == '#endif':
            if not active: raise ValueError('unbalanced #endif in lcm_driver_list')
            active.pop(); continue
        me = re.fullmatch(r'&(\w+),', s)
        if me:
            allsyms.append(me.group(1))
            if all(active): entries.append(me.group(1))
            continue
        raise ValueError(f'unsupported line in lcm_driver_list: {s!r}')
    if active: raise ValueError('unterminated #if in lcm_driver_list')
    return entries, allsyms


def check(tree, config_text):
    problems = []
    panels = config_panels(config_text)
    defined = {p.upper() for p in panels}
    if not panels:
        return ['CONFIG_CUSTOM_KERNEL_LCM names no panel'], {}
    try:
        entries, allsyms = list_entries(read(tree, LIST_C), defined)
    except ValueError as e:
        return [str(e)], {}
    header = read(tree, LIST_H)
    if not entries:
        problems.append('lcm_driver_list is empty for the configured panels (COMPILE_ASSERT mt65xx_lcm_list.c)')
    for sym in sorted({s for s in entries if entries.count(s) > 1}):
        problems.append(f'duplicate list entry {sym}')
    defs_seen, report = {}, {}
    for p in panels:
        d = os.path.join(tree, LCM, p)
        mk = os.path.join(d, 'Makefile')
        if not os.path.isdir(d):
            problems.append(f'{p}: directory missing'); continue
        defs = {}
        for fn in sorted(os.listdir(d)):
            if fn.endswith('.c'):
                for sym in re.findall(r'^struct LCM_DRIVER\s+(\w+)\s*=', read(tree, f'{LCM}/{p}/{fn}'), re.M):
                    defs.setdefault(sym, []).append(fn)
        mine = [s for s in entries if s in defs]
        if len(mine) != 1:
            problems.append(f'{p}: {len(mine)} enabled list entries resolve to its definitions {sorted(defs)} (need exactly 1)'); continue
        sym = mine[0]
        if len(defs[sym]) != 1: problems.append(f'{p}: {sym} defined in {defs[sym]}')
        if not re.search(r'^extern struct LCM_DRIVER %s;' % re.escape(sym), header, re.M):
            problems.append(f'{p}: no extern declaration of {sym} in mt65xx_lcm_list.h')
        if sym in defs_seen:
            problems.append(f'{sym} is defined by both {defs_seen[sym]} and {p}')
        defs_seen[sym] = p
        obj = defs[sym][0][:-2] + '.o'
        if not os.path.isfile(mk) or not re.search(r'^obj-\S+\s*\+?=.*\b%s\b' % re.escape(obj), read(tree, f'{LCM}/{p}/Makefile'), re.M | re.S):
            problems.append(f'{p}: Makefile does not build {obj}')
        report[p] = {'symbol': sym, 'file': defs[sym][0]}
    stray = [s for s in entries if s not in defs_seen]
    for s in stray:
        problems.append(f'enabled entry {s} belongs to no panel named in CONFIG_CUSTOM_KERNEL_LCM')
    return problems, {'panels': report, 'active_entries': entries, 'conditional_entries_in_list': len(allsyms)}


def check_aw2016(tree):
    f = os.path.join(tree, 'drivers/leds/leds-aw2016.c')
    if not os.path.isfile(f):
        return [], None
    mk = read(tree, 'drivers/leds/Makefile')
    paths = re.findall(r'^CFLAGS_leds-aw2016\.o\s*\+=\s*-I\$\(srctree\)/(\S+)', mk, re.M)
    if not paths:
        return ['leds-aw2016.c includes <charger_class.h> but drivers/leds/Makefile has no CFLAGS_leds-aw2016.o -I hook'], None
    hit = [p for p in paths if os.path.isfile(os.path.join(tree, p, 'charger_class.h'))]
    if not hit:
        return [f'charger_class.h not found under {paths}'], None
    return [], hit[0]


def main():
    tree, config = sys.argv[1], sys.argv[2]
    with open(config, errors='ignore') as f:
        problems, rep = check(tree, f.read())
    p2, inc = check_aw2016(tree)
    problems += p2
    out = {'problems': problems, 'ok': not problems, 'aw2016_charger_class_dir': inc, **rep}
    if len(sys.argv) > 3:
        with open(sys.argv[3], 'w') as f:
            json.dump(out, f, indent=1)
    print(json.dumps(out, indent=1))
    return 0 if out['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
