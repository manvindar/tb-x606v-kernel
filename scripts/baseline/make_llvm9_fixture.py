#!/usr/bin/env python3
"""Capture REAL llvm-objdump output for a small synthetic AArch64 function (no vendor code): builds a minimal linked ELF, runs $LLVM_OBJDUMP (CI: the pinned clang
r353983c, LLVM 9) with the exact flags fncompare uses, stores words + printed lines in fixtures/llvm9-operands.json. The unit test replays that capture, so the
operand syntax of the old toolchain is pinned without needing it at test time.
usage: LLVM_OBJDUMP=... make_llvm9_fixture.py"""
import json, os, struct, subprocess, sys, tempfile
from pathlib import Path

BASE = 0xffffff8008080000


def b(op, imm): return op | ((imm >> 2) & 0x3ffffff)
def cb(op, rt, imm): return op | (((imm >> 2) & 0x7ffff) << 5) | rt
def tb(op, rt, bit, imm): return op | ((bit >> 5) << 31) | ((bit & 31) << 19) | (((imm >> 2) & 0x3fff) << 5) | rt
def adrp(rd, pages): return 0x90000000 | ((pages & 3) << 29) | (((pages >> 2) & 0x7ffff) << 5) | rd
def adr(rd, off): return 0x10000000 | ((off & 3) << 29) | (((off >> 2) & 0x7ffff) << 5) | rd
def addi(rd, rn, imm): return 0x91000000 | (imm << 10) | (rn << 5) | rd
def ldrx(rt, rn, imm): return 0xf9400000 | ((imm // 8) << 10) | (rn << 5) | rt


FUNC = 0x30
EXT = 0x2000
WORDS = [0xa9bf7bfd,                    # 0x00 stp x29, x30, [sp, #-0x10]!
         b(0x94000000, EXT - 0x04),     # 0x04 bl ext_fn (outside the function)
         adrp(8, 1),                    # 0x08 adrp x8, +1 page
         addi(8, 8, 0x10),              # 0x0c add x8, x8, #0x10          -> string 'hi'
         adrp(9, 2),                    # 0x10 adrp x9, +2 pages
         ldrx(0, 9, 0x18),              # 0x14 ldr x0, [x9, #0x18]        -> PAGEOFF
         cb(0xb4000000, 0, 0x24 - 0x18),     # 0x18 cbz x0, +0x0c  (0x24)
         tb(0x37000000, 1, 5, 0x28 - 0x1c),  # 0x1c tbnz w1, #5 (0x28)
         cb(0x54000000, 0, 0x2c - 0x20),     # 0x20 b.eq 0x2c
         adr(2, 0x10),                  # 0x24 adr x2, +0x10
         b(0x14000000, EXT - 0x28),     # 0x28 b ext_fn
         0xd65f03c0]                    # 0x2c ret


def elf():
    text = bytearray(0x2100)
    for i in range(0, len(text), 4): text[i:i + 4] = struct.pack('<I', 0xd503201f)
    for i, w in enumerate(WORDS): text[4 * i:4 * i + 4] = struct.pack('<I', w)
    text[0x1010:0x1013] = b'hi\0'
    strtab = b'\0func\0ext_fn\0'
    sym = lambda n, val, size: struct.pack('<IBBHQQ', n, 0x12, 0, 1, val, size)
    symtab = bytes(24) + sym(1, BASE, FUNC) + sym(6, BASE + EXT, 0x10)
    shstr = b'\0.text\0.symtab\0.strtab\0.shstrtab\0'
    off = 64
    parts = [(bytes(text), off)]; off += len(text)
    parts.append((symtab, off)); off += len(symtab)
    parts.append((strtab, off)); off += len(strtab)
    parts.append((shstr, off)); off += len(shstr)
    off = (off + 7) & ~7
    sh = [struct.pack('<IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
          struct.pack('<IIQQQQIIQQ', 1, 1, 6, BASE, parts[0][1], len(text), 0, 0, 4, 0),
          struct.pack('<IIQQQQIIQQ', 7, 2, 0, 0, parts[1][1], len(symtab), 3, 1, 8, 24),
          struct.pack('<IIQQQQIIQQ', 15, 3, 0, 0, parts[2][1], len(strtab), 0, 0, 1, 0),
          struct.pack('<IIQQQQIIQQ', 23, 3, 0, 0, parts[3][1], len(shstr), 0, 0, 1, 0)]
    hdr = b'\x7fELF\2\1\1\0' + bytes(8) + struct.pack('<HHIQQQIHHHHHH', 2, 183, 1, BASE, 0, off, 0, 64, 0, 0, 64, 5, 4)
    return hdr + b''.join(p for p, _ in parts) + bytes(off - (64 + sum(len(p) for p, _ in parts))) + b''.join(sh)


if __name__ == '__main__':
    tool = os.environ['LLVM_OBJDUMP']
    here = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'f.elf'
        p.write_bytes(elf())
        ver = subprocess.run([tool, '--version'], capture_output=True, text=True).stdout.split('\n')
        r = subprocess.run([tool, '-d', '--no-show-raw-insn', '--print-imm-hex', f'--start-address={BASE:#x}', f'--stop-address={BASE + FUNC:#x}', str(p)],
                           capture_output=True, text=True, check=True).stdout
    import re
    lines = []
    for line in r.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+(\S+)\s*(.*)', line)
        if m: lines.append([int(m.group(1), 16), m.group(2), re.sub(r'\s*//.*$', '', re.sub(r' <[^>]*>', '', m.group(3))).strip()])
    (here / 'fixtures').mkdir(exist_ok=True)
    (here / 'fixtures/llvm9-operands.json').write_text(json.dumps(dict(tool=[l.strip() for l in ver if l.strip()][:2], raw=r, base=BASE, func_bytes=FUNC, words=WORDS, lines=lines), indent=1))
    print(len(lines), 'instructions captured')
