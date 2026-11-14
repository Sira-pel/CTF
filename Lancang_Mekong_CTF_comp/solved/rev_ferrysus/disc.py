#!/usr/bin/env python3
"""Discover which section index the VM treats as 'current' (op2 tag=7)."""
import struct, subprocess, sys, itertools
sys.path.insert(0, '.')
from common import *
from chain2 import solve_stage, section, build, run, slot

recs = parse_route()
prog1 = toprog(recs[0]); s1 = solve_stage(prog1)
secA = section(1, [slot(s1['pairs'][i][0], s1['pairs'][i][1], s1['p0'][i], s1['ds'][i])
                   for i in range(s1['n'])], s1['X'], s1['H'])

seed2 = (s1['key'] ^ 0x46455252) & M
prog2 = toprog(decrypt(recs[1], seed2))
s2 = solve_stage(prog2)
pairs, p0, ds = s2['pairs'], s2['p0'], s2['ds']

def mk2(dj=0, c1=0):
    out = []
    for i in range(len(pairs)):
        w4, C = pairs[i]
        if i == dj:
            out.append(slot(w4, c1, 0, 0))
            out.append(slot(w4, (C - c1) & 0xffff, p0[i], ds[i]))
        else:
            out.append(slot(w4, C, p0[i], ds[i]))
    return out

if __name__ == '__main__':
    cands = {
        'A(stage1)': secA,
        'B(stage2 dup)': section(2, mk2(0, 0), s2['X'], s2['H']),
        'B2(stage2 plain6)': section(2, [slot(pairs[i][0], pairs[i][1], p0[i], ds[i]) for i in range(6)], s2['X'], s2['H']),
    }
    for name, secX in cands.items():
        for n_extra in (0, 1, 2):
            for X in {0x1178, 0xae0, 0x8a1}:
                d = build(secX, section(7, [slot(pairs[i][0], pairs[i][1], p0[i], ds[i]) for i in range(6)][:6], X, s2['H']))
                r = run(d)
                if 'ACCEPTED' in r.stdout:
                    print('*** %s X=0x%x n=%d' % (name, X, n_extra))
                    open('/tmp/win.bin', 'wb').write(d)
