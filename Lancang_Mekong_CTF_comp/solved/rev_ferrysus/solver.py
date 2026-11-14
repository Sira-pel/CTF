#!/usr/bin/env python3
"""Solve the ferry staging chain stage by stage."""
import struct, sys
sys.path.insert(0, '.')
from vm2 import (rol, ror, inv32, cl_of, step, unstep, parse_route, progit,
                 section, build, run, M)

def fold13(seed_imm, imms, Cs):
    e = seed_imm
    for i in range(len(imms)):
        e = (e ^ imms[i]) & M
        e = rol((e * 0x1000193) & M, 5)
        e = (e ^ Cs[i]) & M
    return e

def xs(x):
    x &= M
    x ^= (x << 13) & M
    x ^= x >> 17
    x ^= (x << 5) & M
    return x & M

def keystream(seed, n):
    out, s = b'', seed & M
    while len(out) < n:
        s = xs(s)
        out += struct.pack('<I', s)
    return out[:n]

def dec(rec, seed):
    return bytes(a ^ b for a, b in zip(rec, keystream(seed, len(rec))))

def ops_ok(rec, seed):
    d = dec(rec, seed)
    return all(1 <= d[8 * k] <= 25 for k in range(len(d) // 8)), d

def find_seed(rec):
    """brute force stage/n combo: the program must start with op1"""
    for stage in range(256):
        for n in range(1, 9):
            pass

def solve_prog(prog, verbose=False):
    w4, Cv = {}, {}
    for x in prog:
        if x['op'] == 15:
            w4[x['tag']] = x['imm'] & 0xffff
            Cv[x['tag']] = x['imm'] >> 16
    n = len(w4)
    exp = {x['tag']: x['imm'] for x in prog if x['op'] == 16}
    seeds = [x for x in prog if x['op'] == 9]
    if not seeds:
        return None
    seed = seeds[0]['imm']
    o10 = [x for x in prog if x['op'] == 10]
    o12 = [x for x in prog if x['op'] == 12]
    if not o10 or not o12:
        return None
    mul, mode = o10[0]['imm'], o10[0]['tag'] & 3
    tgt = o12[0]['imm']
    p0, acc = [], seed
    for i in range(n):
        want = exp.get(i, tgt)
        v = unstep(acc, want, w4[i], Cv[i], mul, i, mode)
        p0.append(v)
        chk = step(acc, v, w4[i], Cv[i], mul, i, mode)
        if chk != want:
            return None
        acc = chk
    op13s = [x for x in prog if x['op'] == 13]
    key = None
    if op13s:
        f = fold13(op13s[0]['imm'], p0, [Cv[i] for i in range(n)])
        key = ((f ^ acc) * 0x9e3779b1) & M
    H = [x for x in prog if x['op'] == 1][0]['imm'] & 0xff
    stage = [x for x in prog if x['op'] == 2]
    st = stage[0]['tag'] if stage else 1
    return dict(n=n, w4=w4, Cv=Cv, p0=p0, acc=acc, key=key, H=H, stage=st,
                mul=mul, mode=mode, seed=seed, tgt=tgt)

def slot(w4, C, p0, D=0):
    w0, w1 = w4 & 0xff, (w4 >> 8) & 0xff
    return bytes([w0, w1]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', p0 & 0xffffffff) + bytes([D & 0xff, (0xa5 ^ w0 ^ w1), 0, 0])

if __name__ == '__main__':
    recs = parse_route()
    seed = 1
    for idx in range(len(recs)):
        ok, d = ops_ok(recs[idx], seed)
        print('rec%d seed=0x%08x ops_ok=%s' % (idx, seed, ok))
        if not ok:
            break
        prog = []
        for k in range(len(d) // 8):
            e = d[8 * k:8 * k + 8]
            prog.append(dict(op=e[0], tag=e[1], C=int.from_bytes(e[2:4], 'little'),
                             imm=int.from_bytes(e[4:8], 'little')))
        for x in prog:
            print('   op=%-2d tag=%-3d C=0x%04x imm=0x%08x' % (x['op'], x['tag'], x['C'], x['imm']))
        s = solve_prog(prog)
        print('  solved:', None if not s else 'key=0x%08x stage=%d H=0x%x n=%d' % (s['key'], s['stage'], s['H'], s['n']))
        break
