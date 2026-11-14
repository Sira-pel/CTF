#!/usr/bin/env python3
"""Full chain solver with correct merge semantics (op5 sums C, XORs p0)."""
import struct, subprocess, sys
sys.path.insert(0, '.')
from common import *
from op10m import mode_of, sub
from chain2 import section, build, run, slot, op11, s16

def solve_for_merged(prog, pairs, merged, verbose=False):
    """merged: list of (w4, C, src_indices). Solve p0 assuming the fold sees
    merged entries in this order; duplicate sources get p0 split so XOR matches."""
    regs = {x['tag']: x['imm'] for x in prog if x['op'] == 16}
    o10 = [x for x in prog if x['op'] == 10][0]
    mul, tag, nib = o10['imm'], o10['tag'], o10['C'] & 0xff
    o12 = [x for x in prog if x['op'] == 12]
    last = o12[0]['imm'] if o12 else None
    seed = [x for x in prog if x['op'] == 9][0]['imm']
    o11s = [x for x in prog if x['op'] == 11]
    if o11s:
        seed = op11(seed, o11s[0]['tag'], o11s[0]['C'])
    acc = seed
    vals = []
    for i, (w4, C, src) in enumerate(merged):
        want = regs.get(i, last)
        md = mode_of(tag, acc)
        cl = cl_of(w4, i)
        v = (sub(want, C, mul, cl, md, w4) ^ acc) & M
        chk = step(acc, v, w4, C, mul, i, md)
        assert chk == want, (i, hex(chk), hex(want))
        D = (chk >> 28) & 0xf if nib == 1 else (chk & 0xf if nib == 2 else 0)
        vals.append((w4, C, v, D, src))
        acc = chk
    return vals, acc, nib

if __name__ == '__main__':
    recs = parse_route()
    prog1 = toprog(recs[0])
    pairs1 = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog1 if x['op'] == 15]
    merged1 = [(w, c, [i]) for i, (w, c) in enumerate(pairs1)]
    v1, acc1, nib1 = solve_for_merged(prog1, pairs1, merged1)
    p0_1 = [x[2] for x in v1]
    f1 = fold13([x for x in prog1 if x['op'] == 13][0]['imm'], p0_1, [c for _, c in pairs1])
    key1 = ((f1 ^ acc1) * 0x9e3779b1) & M
    H1 = [x for x in prog1 if x['op'] == 1][0]['imm'] & 0xff
    X1 = sum(c for _, c in pairs1) & 0xffff
    sec1 = section(1, [slot(pairs1[i][0], pairs1[i][1], p0_1[i], v1[i][3]) for i in range(8)], X1, H1)
    print('stage1 key=0x%08x' % key1)
    print('  run:', run(build(sec1)).stdout.strip())
