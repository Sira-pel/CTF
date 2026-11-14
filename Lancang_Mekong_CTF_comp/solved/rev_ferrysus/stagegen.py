#!/usr/bin/env python3
"""Solve stage 1 and verify the produced pass reproduces every op16 register."""
import struct, sys
sys.path.insert(0, '.')
from common import *

def build_stage(prog, order=None, regs=None, last=None):
    """Generic inverter: order = list of (w4,C) in execution order."""
    exp = regs if regs is not None else {x['tag']: x['imm'] for x in prog if x['op'] == 16}
    seed = [x for x in prog if x['op'] == 9][0]['imm']
    o10 = [x for x in prog if x['op'] == 10][0]
    mul, mode = o10['imm'], o10['tag'] & 3
    tgt = last if last is not None else [x for x in prog if x['op'] == 12][0]['imm']
    p0, acc = [], seed
    for i, (w4, C) in enumerate(order):
        want = exp.get(i, tgt)
        v = unstep(acc, want, w4, C, mul, i, mode)
        p0.append(v)
        acc = step(acc, v, w4, C, mul, i, mode)
        assert acc == want, (i, hex(acc), hex(want))
    return p0, acc, mul, mode, seed, tgt

def slot(w4, C, p0, D=0):
    w0, w1 = w4 & 0xff, (w4 >> 8) & 0xff
    return bytes([w0, w1]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', p0 & M) + bytes([D, (0xa5 ^ w0 ^ w1) & 0xff])

def section(stage, slots, X, H):
    n = len(slots)
    hdr = b'FS' + bytes([stage & 0xff, n]) + struct.pack('<H', X & 0xffff) + bytes([H & 0xff, 0])
    return hdr + b''.join(struct.pack('<H', 2*n + 8*k) for k in range(n)) + b''.join(slots)

if __name__ == '__main__':
    prog = toprog(parse_route()[0])
    pairs = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog if x['op'] == 15]
    p0, acc, mul, mode, seed, tgt = build_stage(prog, pairs)
    print('p0:', [hex(v) for v in p0])
    print('acc=0x%08x' % acc)
    for i, v in enumerate(p0):
        print('  i=%d w4=0x%04x C=0x%04x p0=0x%08x' % (i, pairs[i][0], pairs[i][1], v))
