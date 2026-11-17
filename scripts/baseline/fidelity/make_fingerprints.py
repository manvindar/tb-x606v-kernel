#!/usr/bin/env python3
"""Build the hash-only shipping function fingerprint database.
usage: make_fingerprints.py IMAGE KALLSYMS OUT.json[.gz]
Per function name (kallsyms, '.isra/.constprop/.part/.cold' suffixes stripped): [[digest_full, digest_trimmed, nwords, "strhash,strhash", va_hex], ...] (one entry per
shipping function of that name; static names may repeat), then the function's shipping virtual address in hex. Digests are 12 hex chars of SHA-1 over the normalized instruction words (see README) + the
ordered branch/call target names. No shipping bytes are stored. 'alias' maps secondary kallsyms names of one address to the canonical (smallest) one."""
import hashlib, json, sys
sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
import fidelity_lib as L

img, ks, out = sys.argv[1:4]
S = L.Shipping(img, ks)
fn, seen = {}, set()
for a, name, size in S.functions:
    if (a, name) in seen:
        continue
    seen.add((a, name))
    full, trm, nw, strs, _, _ = S.fingerprint(a, size)
    fn.setdefault(name, []).append([full, trm if trm != full else '', nw, ','.join(strs), '%x' % a])
db = {'meta': {'image_sha256': hashlib.sha256(S.img).hexdigest(), 'kallsyms_sha256': hashlib.sha256(open(ks, 'rb').read()).hexdigest(),
               'functions': sum(len(v) for v in fn.values()), 'names': len(fn), 'window': L.WINDOW,
               'note': 'hash-only; digest = sha1(normalized instruction words + NUL + newline-joined branch/call target names)[:12]'},
      'alias': S.alias, 'fn': fn}
import gzip
(gzip.open if out.endswith('.gz') else open)(out, 'wt').write(json.dumps(db, separators=(',', ':'), sort_keys=True))
print(db['meta']['functions'], 'functions', db['meta']['names'], 'names', len(S.alias), 'aliases')
