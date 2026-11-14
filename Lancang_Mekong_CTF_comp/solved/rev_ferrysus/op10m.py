#!/usr/bin/env python3
"""Exact op10 model: mode is dynamic when tag==0xff."""
import struct, sys
sys.path.insert(0, '.')
from common import (rol, ror, inv32, cl_of, neg31, step, parse_route, toprog, M)

def mode_of(tag, acc):
    return (acc >> 8) & 3 if tag == 0xff else (tag & 3)

def inv_xor_shift_right(y, s):
    x = 0
    for i in range(31, -1, -1):
        bit = (y >> i) & 1
        nxt = (x >> (i + s)) & 1 if i + s < 32 else 0
        x |= (bit ^ nxt) << i
    return x & M

def sub(want, C, mul, cl, mode, w4=0):
    """compute p0 from the accumulator equation."""
    if mode == 2:
        y = (want ^ ((C * 0x1000193) & M)) & M
        return ror(y, cl) * inv32(mul) & M
    if mode == 0:
        return ror((((want - C) & M) * inv32(mul)) & M, cl)
    if mode == 3:
        return (ror((want * inv32(mul)) & M, cl) ^ (w4 | ((C << 16) & M))) & M
    if mode == 1:
        # want = (((t>>13) ^ t) + C); t = (x>>15 ^ x) * mul
        y = (want - C) & M
        t = inv_xor_shift_right(y, 13)
        t = (t * inv32(mul)) & M
        return inv_xor_shift_right(t, 15)
    raise NotImplementedError

def solve_stage(prog, pairs, regs, last, verbose=True):
    seed = [x for x in prog if x['op'] == 9][0]['imm']
    o10 = [x for x in prog if x['op'] == 10][0]
    mul, tag = o10['imm'], o10['tag']
    p0, acc = [], seed
    for i, (w4, C) in enumerate(pairs):
        want = regs.get(i, last)
        md = mode_of(tag, acc)
        cl = cl_of(w4, i)
        x = sub(want, C, mul, cl, md)
        v = (x ^ acc) & M
        chk = step(acc, v, w4, C, mul, i, md)
        if verbose:
            print('  i=%d mode=%d cl=%2d p0=0x%08x -> 0x%08x want 0x%08x %s' % (
                i, md, cl, v, chk, want, 'OK' if chk == want else 'BAD'))
        assert chk == want
        p0.append(v)
        acc = chk
    return p0, acc, mul, tag

if __name__ == '__main__':
    from common import decrypt, fold13
    recs = parse_route()
    prog1 = toprog(recs[0])
    pairs1 = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog1 if x['op'] == 15]
    regs1 = {x['tag']: x['imm'] for x in prog1 if x['op'] == 16}
    last1 = [x for x in prog1 if x['op'] == 12][0]['imm']
    p0, acc, mul, tag = solve_stage(prog1, pairs1, regs1, last1, verbose=False)
    f = fold13([x for x in prog1 if x['op'] == 13][0]['imm'], p0, [c for _, c in pairs1])
    key = ((f ^ acc) * 0x9e3779b1) & M
    print('stage1 key=0x%08x' % key)
    prog2 = toprog(decrypt(recs[1], key ^ 0x46455252))
    for x in prog2:
        print('  op=%-2d tag=%-3d C=0x%04x imm=0x%08x' % (x['op'], x['tag'], x['C'], x['imm']))
