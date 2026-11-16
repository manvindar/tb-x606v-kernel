#!/usr/bin/env python3
"""Compare existing ARM64 modules' required CRCs with a candidate kernel.

A match is necessary, but does not establish board or runtime compatibility.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def versions(path):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Expected little-endian ELF64 module')
    header = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    if header[0] != 1 or header[1] != 183 or header[10] != 64:
        raise ValueError('Expected ARM64 relocatable module')
    offset, count, names_index = header[5], header[11], header[12]
    if not 0 <= names_index < count or offset + count * 64 > len(data):
        raise ValueError('Invalid section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * 64) for i in range(count)]
    def payload(section):
        off, size = section[4:6]
        if off + size > len(data):
            raise ValueError('Section outside module')
        return data[off:off + size]
    names = payload(sections[names_index])
    for section in sections:
        name = names[section[0]:].split(b'\0', 1)[0]
        if name == b'__versions':
            content = payload(section)
            if len(content) % 64:
                raise ValueError('Unexpected modversion layout')
            result = {}
            for i in range(0, len(content), 64):
                crc, raw_name = struct.unpack_from('<Q56s', content, i)
                symbol = raw_name.split(b'\0', 1)[0].decode('ascii')
                if not symbol or symbol in result:
                    raise ValueError('Invalid or duplicate versioned symbol')
                result[symbol] = crc & 0xffffffff
            return result
    raise ValueError('Module has no __versions section')


def compare(symvers, modules):
    candidate = {}
    for line in symvers.read_text().splitlines():
        fields = line.split()
        if len(fields) < 3:
            raise ValueError('Invalid Module.symvers row')
        crc, name = int(fields[0], 16), fields[1]
        if name in candidate and candidate[name] != crc:
            raise ValueError('Conflicting candidate symbol CRCs')
        candidate[name] = crc
    records = []
    for path in modules:
        required = versions(path)
        mismatches = [dict(symbol=name, required=f'{crc:08x}',
                           candidate=None if name not in candidate else f'{candidate[name]:08x}')
                      for name, crc in sorted(required.items()) if candidate.get(name) != crc]
        records.append(dict(module=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                            required_symbols=len(required), mismatches=mismatches))
    return dict(modules=records, symbol_versions_match=all(not r['mismatches'] for r in records),
                runtime_validation=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('symvers', type=Path)
    parser.add_argument('modules', type=Path, nargs='+')
    args = parser.parse_args()
    report = compare(args.symvers, args.modules)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['symbol_versions_match'] else 1)
