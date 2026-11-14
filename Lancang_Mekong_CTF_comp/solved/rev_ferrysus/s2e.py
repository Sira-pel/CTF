#!/usr/bin/env python3
"""Stage-2: 7 items (one duplicated w4) so count is in 7..8 while merge yields 6 folds."""
import struct, subprocess, sys
sys.path.insert(0, '.')
from common import *
from merged2 import solve_for_merged
from chain2 import section, build, run, slot, s16
from op10m import mode_of, sub

def fold_order(pairs, prog, dup=None):
    n = len(pairs)
    idx = list(range(n)) if dup is None else list(range(n)) + [dup]
    o3 = [x for x in prog if x['op'] == 3]
    if o3:
        k = s16(o3[0]['imm'] & 0xffff); m = (o3[0]['imm'] >> 16) & 0xffff
        idx = sorted(idx, key=lambda i: (((s16(pairs[i % n][0]) * k) & 0xffff) ^ m) & 0xffff)
    return idx

recs = parse_route()
prog1 = toprog(recs[0])
pairs1 = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog1 if x['op'] == 15]
v1, acc1, nib1 = solve_for_merged(prog1, pairs1, [(w, c, [i]) for i, (w, c) in enumerate(pairs1)])
p0_1 = [x[2] for x in v1]
H1 = [x for x in prog1 if x['op'] == 1][0]['imm'] & 0xff
X1 = sum(c for _, c in pairs1) & 0xffff
sec1 = section(1, [slot(pairs1[i][0], pairs1[i][1], p0_1[i], v1[i][3]) for i in range(8)], X1, H1)
f1 = fold13([x for x in prog1 if x['op'] == 13][0]['imm'], p0_1, [c for _, c in pairs1])
key1 = ((f1 ^ acc1) * 0x9e3779b1) & M

prog2 = toprog(decrypt(recs[1], key1 ^ 0x46455252))
pairs2 = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog2 if x['op'] == 15]
merged2 = [(w, c, [i]) for i, (w, c) in enumerate(pairs2)]
v2, acc2, nib2 = solve_for_merged(prog2, pairs2, merged2)
p0_2 = [x[2] for x in v2]

if __name__ == '__main__':
    print('key1=0x%08x' % key1)
    print('stage2 p0:', [hex(v) for v in p0_2])
    print('stage2 D :', [v2[i][3] for i in range(6)])
    tot = sum(c for _, c in pairs2) & 0xffff
    for dup in range(6):
        for c1 in (0, 1, 2, 0x80):
            items = []
            for i in range(6):
                w4, C = pairs2[i]
                if i == dup:
                    items.append(slot(w4, c1, 0, 0))
                    items.append(slot(w4, (C - c1) & 0xffff, p0_2[i], v2[i][3]))
                else:
                    items.append(slot(w4, C, p0_2[i], v2[i][3]))
            d = build(sec1, section(2, items, tot, [x for x in prog2 if x['op'] == 1][0]['imm'] & 0xff))
            r = run(d)
            if 'ACCEPTED' in r.stdout:
                print('*** ACCEPTED dup=%d c1=0x%x' % (dup, c1))
                open('/tmp/w6.bin', 'wb').write(d)
                raise SystemExit
    print('none accepted')
