#!/usr/bin/env python3
"""Solve each stage against the *merged* item array the VM actually folds."""
import struct, subprocess, sys
sys.path.insert(0, '.')
from common import *
from op10m import mode_of, sub
from chain2 import solve_stage, section, build, run, slot, op11, s16

def fold_order(pairs, prog):
    """order items are folded: sorted by op3 key, then merged by w4."""
    n = len(pairs)
    order = list(range(n))
    o3 = [x for x in prog if x['op'] == 3]
    if o3:
        k = s16(o3[0]['imm'] & 0xffff); m = (o3[0]['imm'] >> 16) & 0xffff
        order = sorted(range(n), key=lambda i: (((s16(pairs[i][0]) * k) & 0xffff) ^ m) & 0xffff)
    merged, cur = [], None
    for si in order:
        w4, C = pairs[si]
        if merged and merged[-1][0] == w4:
            p, c = merged[-1][1], merged[-1][2]
            merged[-1] = (w4, p, (c + C) & 0xffff, merged[-1][3] + [si])
        else:
            merged.append((w4, 0, C, [si]))
    return merged

if __name__ == '__main__':
    recs = parse_route()
    s1 = solve_stage(toprog(recs[0]))
    print('stage1 p0:', [hex(v) for v in s1['p0']])
    seed2 = (s1['key'] ^ 0x46455252) & M
    prog2 = toprog(decrypt(recs[1], seed2))
    pairs2 = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog2 if x['op'] == 15]
    print('stage2 pairs:', [(hex(a), hex(b)) for a, b in pairs2])
    m = fold_order(pairs2, prog2)
    print('fold order (w4, C, src):', [(hex(w), hex(c), src) for w, _, c, src in m])
