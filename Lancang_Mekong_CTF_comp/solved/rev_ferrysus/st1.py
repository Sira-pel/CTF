#!/usr/bin/env python3
"""Stage-1 pass builder with per-item nibble field."""
import struct, subprocess, sys
sys.path.insert(0, '.')
from vm2 import (rol, ror, inv32, cl_of, step, unstep, parse_route, progit,
                 section, build, run, M)

def solve(prog, verbose=True):
    w4, Cv = {}, {}
    for x in prog:
        if x['op'] == 15:
            w4[x['tag']] = x['imm'] & 0xffff
            Cv[x['tag']] = x['imm'] >> 16
    n = len(w4)
    exp = {x['tag']: x['imm'] for x in prog if x['op'] == 16}
    seed = [x for x in prog if x['op'] == 9][0]['imm']
    o10 = [x for x in prog if x['op'] == 10][0]
    mul, mode = o10['imm'], o10['tag'] & 3
    tgt = [x for x in prog if x['op'] == 12][0]['imm']
    p0, Ds = [], []
    acc = seed
    for i in range(n):
        want = exp.get(i, tgt)
        v = unstep(acc, want, w4[i], Cv[i], mul, i, mode)
        p0.append(v)
        acc = step(acc, v, w4[i], Cv[i], mul, i, mode)
        assert acc == want
        Ds.append((acc >> 28) & 0xf)
        if verbose:
            print('  i=%d cl=%2d p0=0x%08x acc=0x%08x D=%d' % (i, cl_of(w4[i], i), v, acc, Ds[-1]))
    return dict(n=n, w4=w4, Cv=Cv, p0=p0, D=Ds, acc=acc)

def slot(w4, C, p0, D=0):
    w0, w1 = w4 & 0xff, (w4 >> 8) & 0xff
    return bytes([w0, w1]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', p0 & 0xffffffff) + bytes([D & 0xff, (0xa5 ^ w0 ^ w1)])

if __name__ == '__main__':
    prog = progit(parse_route()[0])
    s = solve(prog)
    H = [x for x in prog if x['op'] == 1][0]['imm'] & 0xff
    X = sum(s['Cv'].values()) & 0xffff
    sl = [slot(s['w4'][i], s['Cv'][i], s['p0'][i], s['D'][i]) for i in range(s['n'])]
    p = build(section(1, sl, X=X, H=H))
    r = run(p)
    print('X=0x%x H=0x%x len=%d => rc=%d %r' % (X, H, len(p), r.returncode, r.stdout.strip()))
