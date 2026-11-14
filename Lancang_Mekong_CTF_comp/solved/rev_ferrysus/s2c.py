#!/usr/bin/env python3
"""Stage-2 builder: X is the sum of C over the items the VM actually folds.

The VM folds the *merged* list (op5 merges equal w4). With one duplicated w4 the
merged list has 6 items whose C is the full pair value, so the op8 sum is checked
against the merged C sum = same 0xae0.
"""
import struct, subprocess, sys
sys.path.insert(0, '.')
from common import *
from chain2 import solve_stage, section, build, run, slot

recs = parse_route()
s1 = solve_stage(toprog(recs[0]))
secA = section(1, [slot(s1['pairs'][i][0], s1['pairs'][i][1], s1['p0'][i], s1['ds'][i])
                   for i in range(s1['n'])], s1['X'], s1['H'])
seed2 = (s1['key'] ^ 0x46455252) & M
prog2 = toprog(decrypt(recs[1], seed2))
s2 = solve_stage(prog2)
pairs2, p0b, ds2 = s2['pairs'], s2['p0'], s2['ds']

def mk(dj, c1):
    out = []
    for i in range(len(pairs2)):
        w4, C = pairs2[i]
        if i == dj:
            out.append(slot(w4, c1, 0, 0))
            out.append(slot(w4, (C - c1) & 0xffff, p0b[i], ds2[i]))
        else:
            out.append(slot(w4, C, p0b[i], ds2[i]))
    return out

if __name__ == '__main__':
    merged_sum = sum(c for _, c in pairs2) & 0xffff
    for dj in range(len(pairs2)):
        for c1 in (0, 1, 0x100, 0x200):
            items = mk(dj, c1)
            d = build(secA, section(2, items, merged_sum, s2['H']))
            r = run(d)
            if 'ACCEPTED' in r.stdout:
                print('*** ACCEPTED dj=%d c1=0x%x' % (dj, c1))
                open('/tmp/w4.bin', 'wb').write(d)
                raise SystemExit
    print('merged_sum=0x%x no acceptance' % merged_sum)
