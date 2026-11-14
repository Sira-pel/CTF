#!/usr/bin/env python3
"""Test the off-by-one section hypothesis: stage k checks section k-1."""
import struct, subprocess, sys, itertools
sys.path.insert(0, '.')
from common import *
from chain2 import solve_stage, section, build, run, slot

recs = parse_route()
s1 = solve_stage(toprog(recs[0]))
pairs1, p0a, ds1 = s1['pairs'], s1['p0'], s1['ds']
itemsA = [slot(pairs1[i][0], pairs1[i][1], p0a[i], ds1[i]) for i in range(8)]

seed2 = (s1['key'] ^ 0x46455252) & M
prog2 = toprog(decrypt(recs[1], seed2))
s2 = solve_stage(prog2)
pairs2, p0b, ds2 = s2['pairs'], s2['p0'], s2['ds']

def dup(idx, c1):
    out = []
    for i in range(len(pairs2)):
        w4, C = pairs2[i]
        if i == idx:
            out.append(slot(w4, c1, 0, 0))
            out.append(slot(w4, (C - c1) & 0xffff, p0b[i], ds2[i]))
        else:
            out.append(slot(w4, C, p0b[i], ds2[i]))
    return out

if __name__ == '__main__':
    tot = sum(c for _, c in pairs2) & 0xffff
    prev = (tot - pairs2[-1][1]) & 0xffff
    print('stage2 C sums: total=0x%x prev=0x%x' % (tot, prev))
    for dj in range(6):
        for c1 in (0, 1):
            for X2 in {tot, prev}:
                d = build(section(1, itemsA, s1['X'], s1['H']), section(2, dup(dj, c1), X2, s2['H']))
                r = run(d)
                tag = 'dj=%d c1=0x%x X=0x%x' % (dj, c1, X2)
                if 'ACCEPTED' in r.stdout:
                    print('*** ACCEPTED ' + tag)
                    open('/tmp/w2.bin', 'wb').write(d)
                elif 'REJECTED' not in r.stdout:
                    print(tag, '->', r.returncode, r.stdout.strip())
