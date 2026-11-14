#!/usr/bin/env python3
"""Stage-2 with 7 items: op3 sorting must place the duplicate pair adjacently and
first, so op5 merges them and the fold order matches indices 0..5."""
import struct, subprocess, sys
sys.path.insert(0, '.')
from common import *
import merged2
from chain2 import section, build, run, slot, s16

recs = parse_route()
prog1 = toprog(recs[0])
pairs1 = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog1 if x['op'] == 15]
v1, acc1, nib1 = merged2.solve_for_merged(prog1, pairs1, [(w, c, [i]) for i, (w, c) in enumerate(pairs1)])
p0_1 = [x[2] for x in v1]
H1 = [x for x in prog1 if x['op'] == 1][0]['imm'] & 0xff
X1 = sum(c for _, c in pairs1) & 0xffff
sec1 = section(1, [slot(pairs1[i][0], pairs1[i][1], p0_1[i], v1[i][3]) for i in range(8)], X1, H1)
f1 = fold13([x for x in prog1 if x['op'] == 13][0]['imm'], p0_1, [c for _, c in pairs1])
key1 = ((f1 ^ acc1) * 0x9e3779b1) & M

prog2 = toprog(decrypt(recs[1], key1 ^ 0x46455252))
prog2b = [dict(x) for x in prog2]
for x in prog2b:
    if x['op'] == 9:
        x['imm'] = (rol(0xa58c0431, 9) ^ rol(0xa58c0431, 3) ^ 0xa58c0431) & M
pairs2 = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog2 if x['op'] == 15]
v2, acc2, nib2 = merged2.solve_for_merged(prog2b, pairs2, [(w, c, [i]) for i, (w, c) in enumerate(pairs2)])
p2 = [x[2] for x in v2]
d2 = [x[3] for x in v2]
H2 = [x for x in prog2 if x['op'] == 1][0]['imm'] & 0xff
tot = sum(c for _, c in pairs2) & 0xffff
o3 = [x for x in prog2 if x['op'] == 3][0]['imm']
k, msk = s16(o3 & 0xffff), (o3 >> 16) & 0xffff

def key_of(w4):
    return (((s16(w4) * k) & 0xffff) ^ msk) & 0xffff

if __name__ == '__main__':
    print('key1=0x%08x seed2=0x%08x' % (key1, prog2b[[i for i, x in enumerate(prog2b) if x['op'] == 9][0]]['imm']))
    print('sort keys:', [(hex(pairs2[i][0]), hex(key_of(pairs2[i][0]))) for i in range(6)])
    print('p2:', [hex(v) for v in p2])
    print('d2:', d2)
    print('X2=0x%x H2=0x%x' % (tot, H2))
    # try each dup position, splitting C at several points, all with the op11 seed
    for dup in range(6):
        w4d = pairs2[dup][0]
        for c1 in range(0, 0x10):
            items = []
            for i in range(6):
                w4, C = pairs2[i]
                if i == dup:
                    items.append(slot(w4, c1, 0, 0))
                    items.append(slot(w4, (C - c1) & 0xffff, p2[i], d2[i]))
                else:
                    items.append(slot(w4, C, p2[i], d2[i]))
            d = build(sec1, section(2, items, tot, H2))
            r = run(d)
            if 'ACCEPTED' in r.stdout:
                print('*** ACCEPTED dup=%d c1=0x%x' % (dup, c1))
                open('/tmp/win2.bin', 'wb').write(d)
                raise SystemExit
    print('none')
