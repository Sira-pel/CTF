#!/usr/bin/env python3
"""Probe op8: which C-sum the check uses, and whether X must match exactly."""
import struct, subprocess, sys
sys.path.insert(0, '.')
from common import *
from chain2 import solve_stage, section, build, run, slot

recs = parse_route()
prog1 = toprog(recs[0]); s1 = solve_stage(prog1)
sec1 = section(1, [slot(s1['pairs'][i][0], s1['pairs'][i][1], s1['p0'][i], s1['ds'][i])
                   for i in range(s1['n'])], s1['X'], s1['H'])
seed2 = (s1['key'] ^ 0x46455252) & M
prog2 = toprog(decrypt(recs[1], seed2))
s2 = solve_stage(prog2)
pairs, p0, ds = s2['pairs'], s2['p0'], s2['ds']

def mkitems(dj, c1, x):
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
    base = sum(c for _, c in pairs) & 0xffff
    print('total C sum = 0x%x ; minus last = 0x%x' % (base, (base - pairs[-1][1]) & 0xffff))
    for dj in range(len(pairs)):
        for c1 in (0, 1, 0x80):
            for X in {base, (base - pairs[-1][1]) & 0xffff, 0x8a1, 0, 0xffff}:
                items = mkitems(dj, c1, X)
                d = build(sec1, section(2, items, X, s2['H']))
                r = run(d)
                if 'ACCEPTED' in r.stdout:
                    print('*** ACCEPTED dup=%d c1=0x%x X=0x%x' % (dj, c1, X))
                    open('/tmp/solved.bin', 'wb').write(d)
                elif 'REJECTED' != r.stdout.strip():
                    print('dup=%d c1=0x%x X=0x%x -> rc=%d %r' % (dj, c1, X, r.returncode, r.stdout.strip()))
