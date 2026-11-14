#!/usr/bin/env python3
"""Stage-2 builder using full C sum as X, plus duplicate items to satisfy count 7..8."""
import struct, subprocess, sys
sys.path.insert(0, '.')
from common import *
from chain2 import solve_stage, section, build, run, slot

recs = parse_route()
s1 = solve_stage(toprog(recs[0]))
itemsA = [slot(s1['pairs'][i][0], s1['pairs'][i][1], s1['p0'][i], s1['ds'][i]) for i in range(s1['n'])]
secA = section(1, itemsA, s1['X'], s1['H'])

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
    for dj in range(6):
        for c1 in range(0, 0x20):
            items = mk(dj, c1)
            X = sum(int.from_bytes(it[2:4], 'little') for it in items) & 0xffff
            d = build(secA, section(2, items, X, s2['H']))
            r = run(d)
            if 'ACCEPTED' in r.stdout:
                print('*** ACCEPTED dj=%d c1=0x%x X=0x%x' % (dj, c1, X))
                open('/tmp/w3.bin', 'wb').write(d)
                raise SystemExit
    print('no acceptance yet')
