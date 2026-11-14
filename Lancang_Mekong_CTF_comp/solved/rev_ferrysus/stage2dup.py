#!/usr/bin/env python3
"""Stage-2 handler: section count must be 7..8; duplicate w4 entries merge in op5."""
import struct, subprocess, sys, itertools
sys.path.insert(0, '.')
from common import *
from op10m import mode_of, sub
from chain2 import solve_stage, section, build, run, slot, op11, s16

def build_stage2(prog, dup_index, split_c=1, verbose=True):
    """dup_index: which of the 6 merged pairs to duplicate."""
    s = solve_stage(prog)
    pairs, p0, ds = s['pairs'], s['p0'], s['ds']
    n = len(pairs)
    items = []
    for i in range(n):
        w4, C = pairs[i]
        if i == dup_index:
            c1 = split_c
            c2 = (C - c1) & 0xffff
            items.append(slot(w4, c1, 0, 0))
            items.append(slot(w4, c2, p0[i], ds[i]))
        else:
            items.append(slot(w4, C, p0[i], ds[i]))
    if verbose:
        print('  dup %d -> %d items' % (dup_index, len(items)))
    return s, items

if __name__ == '__main__':
    recs = parse_route()
    prog1 = toprog(recs[0]); s1 = solve_stage(prog1)
    sec1 = section(1, [slot(s1['pairs'][i][0], s1['pairs'][i][1], s1['p0'][i], s1['ds'][i])
                       for i in range(s1['n'])], s1['X'], s1['H'])
    seed2 = (s1['key'] ^ 0x46455252) & M
    prog2 = toprog(decrypt(recs[1], seed2))
    for dj in range(6):
        for sc in (1, 0x80, 0x100, 0x1ff):
            s2, items = build_stage2(prog2, dj, sc, verbose=False)
            X2 = s2['X']
            d = build(sec1, section(2, items, X2, s2['H']))
            r = run(d)
            tag = 'dup=%d sc=0x%x' % (dj, sc)
            if 'ACCEPTED' in r.stdout:
                print('*** %s ACCEPTED ***' % tag)
                open('/tmp/solved.bin', 'wb').write(d)
            elif r.returncode != 1 or 'REJECTED' not in r.stdout:
                print('%s -> rc=%d %r' % (tag, r.returncode, r.stdout.strip()))
