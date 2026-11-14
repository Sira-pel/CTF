#!/usr/bin/env python3
"""Stage-2 builder: the duplicate item carries the merged D byte."""
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

def mk(dj, c1, firstD=0):
    out = []
    for i in range(len(pairs2)):
        w4, C = pairs2[i]
        if i == dj:
            out.append(slot(w4, c1, 0, firstD))
            out.append(slot(w4, (C - c1) & 0xffff, p0b[i], ds2[i]))
        else:
            out.append(slot(w4, C, p0b[i], ds2[i]))
    return out

if __name__ == '__main__':
    total = sum(c for _, c in pairs2) & 0xffff
    tries = 0
    for dj in range(len(pairs2)):
        for c1 in (0, 1, 0x80, 0x100):
            for firstD in (0, ds2[dj]):
                items = mk(dj, c1, firstD)
                d = build(secA, section(2, items, total, s2['H']))
                r = run(d)
                tries += 1
                if 'ACCEPTED' in r.stdout:
                    print('*** ACCEPTED dj=%d c1=0x%x D0=0x%x' % (dj, c1, firstD))
                    open('/tmp/w5.bin', 'wb').write(d)
                    raise SystemExit
    print('tried', tries, 'no acceptance')
