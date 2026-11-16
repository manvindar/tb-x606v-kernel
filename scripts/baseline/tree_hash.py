#!/usr/bin/env python3
"""Content hash of a (gzip) tar: sha256 over sorted 'path kind exec file-sha256|target' lines.
Ignores tar/gzip timestamps and ordering, which git archive does not keep stable. usage: tree_hash.py ARCHIVE.tar.gz"""
import hashlib, sys, tarfile


def tree_hash(path):
    lines = []
    with tarfile.open(path, 'r:gz') as t:
        for m in t:
            if m.isdir():
                continue
            if m.isreg():
                h = hashlib.sha256(); f = t.extractfile(m)
                while b := f.read(1 << 20):
                    h.update(b)
                lines.append(f'{m.name}\tfile\t{int(bool(m.mode & 0o111))}\t{h.hexdigest()}')
            elif m.issym():
                lines.append(f'{m.name}\tsymlink\t0\t{m.linkname}')
            else:
                raise ValueError(f'unsupported member type: {m.name}')
    return hashlib.sha256('\n'.join(sorted(lines)).encode()).hexdigest(), len(lines)


if __name__ == '__main__':
    digest, n = tree_hash(sys.argv[1])
    print(digest, n)
