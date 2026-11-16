#!/usr/bin/env python3
"""Read DT_NEEDED and undefined dynamic symbols without executing an ELF."""
import json
from pathlib import Path
import struct
import sys

def inspect(path):
    data = Path(path).read_bytes()
    if data[:4] != b'\x7fELF' or data[5] != 1 or data[4] not in (1, 2):
        raise ValueError('Expected little-endian ELF32/ELF64')
    bits = 64 if data[4] == 2 else 32
    header = struct.unpack_from('<HHIQQQIHHHHHH' if bits == 64 else '<HHIIIIIHHHHHH', data, 16)
    section_offset, section_size, count, names_index = header[5], header[10], header[11], header[12]
    section_format = '<IIQQQQIIQQ' if bits == 64 else '<IIIIIIIIII'
    if section_size != struct.calcsize(section_format) or not count or names_index >= count:
        raise ValueError('Unsupported section layout')
    sections = [struct.unpack_from(section_format, data, section_offset + i * section_size) for i in range(count)]
    def payload(section):
        offset, size = section[4], section[5]
        if offset + size > len(data):
            raise ValueError('Section outside file')
        return data[offset:offset + size]
    names = payload(sections[names_index])
    def string(blob, index):
        end = blob.find(b'\0', index)
        if index >= len(blob) or end < index:
            raise ValueError('Invalid string index')
        return blob[index:end].decode('utf-8')
    named = {string(names, section[0]): section for section in sections}
    dynstr = payload(named['.dynstr'])
    dynamic = payload(named['.dynamic'])
    size = 16 if bits == 64 else 8
    values = [struct.unpack_from('<qQ' if bits == 64 else '<iI', dynamic, i) for i in range(0, len(dynamic), size)]
    needed = [string(dynstr, value) for tag, value in values if tag == 1]
    dynsym = payload(named['.dynsym'])
    symbol_size = 24 if bits == 64 else 16
    undefined = []
    exported = []
    weak = []
    for i in range(0, len(dynsym), symbol_size):
        symbol = struct.unpack_from('<IBBHQQ' if bits == 64 else '<IIIBBH', dynsym, i)
        name, section_index = symbol[0], symbol[3] if bits == 64 else symbol[5]
        if name and section_index == 0:
            undefined.append(string(dynstr, name))
            binding = (symbol[1] if bits == 64 else symbol[3]) >> 4
            if binding == 2:
                weak.append(string(dynstr, name))
        elif name:
            binding = (symbol[1] if bits == 64 else symbol[3]) >> 4
            if binding in (1, 2):
                exported.append(string(dynstr, name))
    return {'path': str(path), 'bits': bits, 'machine': header[1], 'needed': needed,
            'undefined_symbols': sorted(undefined), 'weak_undefined_symbols': sorted(weak),
            'exported_symbols': sorted(exported)}

if __name__ == '__main__':
    print(json.dumps([inspect(path) for path in sys.argv[1:]], indent=2))
