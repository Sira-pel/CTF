#!/usr/bin/env python3
"""Solve stage 2: find pass items so the sorted/merged list matches op16 expectations."""
import struct, sys, itertools
sys.path.insert(0, '.')
from kvm import (rol, ror, inv32, cl_of, step, unstep, fold13, op11, s16,
                 parse_route, decrypt, toprog, M)

def stage2(prog, verbose=True):
    # collect pass-slot specs from op15 (w4, C) and op7 (first, last w4)
    pairs = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog if x['op'] == 15]
    op7 = [x for x in prog if x['op'] == 7][0]
    o3 = [x for x in prog if x['op'] == 3][0]
    o6 = [x for x in prog if x['op'] == 6][0]
    o11 = [x for x in prog if x['op'] == 11][0]
    o9 = [x for x in prog if x['op'] == 9][0]['imm']
    o10 = [x for x in prog if x['op'] == 10][0]
    o12 = [x for x in prog if x['op'] == 12][0]['imm']
    exp = {x['tag']: x['imm'] for x in prog if x['op'] == 16}
    w4list = [p[0] for p in pairs]
    Clist = [p[1] for p in pairs]
    if verbose:
        print('pairs:', [(hex(a), hex(b)) for a, b in pairs])
        print('op7 need first w4=0x%x last=0x%x' % (op7['imm'] & 0xffff, op7['imm'] >> 16))
        print('op3 key=%d mask=0x%x' % (s16(o3['imm'] & 0xffff), (o3['imm'] >> 16) & 0xffff))
        print('op6 lo=%d hi=%d' % (o6['imm'] & 0xff, (o6['imm'] >> 8) & 0xff))
        print('op11 tag=%d C=%d' % (o11['tag'], o11['C']))
        print('seed=0x%08x mul=0x%08x mode=%d tgt=0x%08x' % (o9, o10['imm'], o10['tag'] & 3, o12))
        print('exp:', {k: hex(v) for k, v in exp.items()})
    # sort by key
    key = s16(o3['imm'] & 0xffff)
    mask = (o3['imm'] >> 16) & 0xffff
    idxs = sorted(range(len(pairs)), key=lambda i: ((w4list[i] * key) & 0xffff) ^ mask)
    if verbose:
        print('sorted idx:', idxs, 'w4:', [hex(w4list[i]) for i in idxs])
    return None

if __name__ == '__main__':
    prog = toprog(decrypt(parse_route()[1], 0xfb408fa3))
    stage2(prog)
