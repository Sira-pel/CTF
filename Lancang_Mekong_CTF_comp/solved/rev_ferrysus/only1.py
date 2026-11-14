#!/usr/bin/env python3
"""Build stage-1 pass and trace stage 2 with pass present."""
import struct, subprocess, sys
sys.path.insert(0, '.')
from fsolve import solve_chain, slot, section, build
from kvm import parse_route, toprog, M

recs = parse_route()
prog = toprog(recs[0])
w4 = {x['tag']: x['imm'] & 0xffff for x in prog if x['op'] == 15}
Cv = {x['tag']: x['imm'] >> 16 for x in prog if x['op'] == 15}
exp = {x['tag']: x['imm'] for x in prog if x['op'] == 16}
seed = [x for x in prog if x['op'] == 9][0]['imm']
o10 = [x for x in prog if x['op'] == 10][0]
tgt = [x for x in prog if x['op'] == 12][0]['imm']
n = len(w4)
items = [dict(w4=w4[i], C=Cv[i]) for i in range(n)]
p0, acc, aux = solve_chain(items, seed, o10['imm'], o10['tag'] & 3, targets=exp, last_target=tgt)
H = [x for x in prog if x['op'] == 1][0]['imm'] & 0xff
X = sum(Cv.values()) & 0xffff
sl = [slot(items[i]['w4'], items[i]['C'], p0[i], aux[i]) for i in range(n)]
d1 = section(1, sl, X, H)

if __name__ == '__main__':
    print(build(d1).hex())
