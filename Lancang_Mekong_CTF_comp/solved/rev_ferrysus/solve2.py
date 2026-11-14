#!/usr/bin/env python3
"""Solve stage 2 and build the 2-section pass; test locally."""
import struct, subprocess, sys
sys.path.insert(0, '.')
from kvm import (rol, ror, inv32, cl_of, step, unstep, fold13, op11, s16,
                 parse_route, decrypt, toprog, section, build, run, M)

def solve1(prog):
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
    p0, acc = [], seed
    for i in range(n):
        want = exp.get(i, tgt)
        v = unstep(acc, want, w4[i], Cv[i], mul, i, mode)
        p0.append(v)
        acc = step(acc, v, w4[i], Cv[i], mul, i, mode)
        assert acc == want
    o13 = [x for x in prog if x['op'] == 13]
    key = None
    if o13:
        f = fold13(o13[0]['imm'], p0, [Cv[i] for i in range(n)])
        key = ((f ^ acc) * 0x9e3779b1) & M
    H = [x for x in prog if x['op'] == 1][0]['imm'] & 0xff
    return dict(n=n, w4=w4, Cv=Cv, p0=p0, acc=acc, key=key, H=H)

def solve2(prog, verbose=True):
    pairs = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog if x['op'] == 15]
    o3 = [x for x in prog if x['op'] == 3][0]
    o6 = [x for x in prog if x['op'] == 6][0]
    o11 = [x for x in prog if x['op'] == 11][0]
    o9 = [x for x in prog if x['op'] == 9][0]['imm']
    o10 = [x for x in prog if x['op'] == 10][0]
    o12 = [x for x in prog if x['op'] == 12][0]['imm']
    exp = {x['tag']: x['imm'] for x in prog if x['op'] == 16}
    key = s16(o3['imm'] & 0xffff)
    mask = (o3['imm'] >> 16) & 0xffff
    idxs = sorted(range(len(pairs)), key=lambda i: ((pairs[i][0] * key) & 0xffff) ^ mask)
    # order p0 computation follows sorted order, indexes 0..n-1
    mul, mode = o10['imm'], o10['tag'] & 3
    n = len(pairs)
    # op11 applies to the running acc BEFORE op10 chain? model: acc = op11(acc, tag, C)
    accs = {}
    acc = o9
    if o11:
        acc0 = acc
        acc = op11(acc, o11['tag'], o11['C'])
        if verbose: print('op11: 0x%08x -> 0x%08x' % (acc0, acc))
    p0 = []
    for i in range(n):
        si = idxs[i]
        want = exp.get(i, o12)
        v = unstep(acc, want, pairs[si][0], pairs[si][1], mul, i, mode)
        p0.append(v)
        acc = step(acc, v, pairs[si][0], pairs[si][1], mul, i, mode)
        if verbose: print('  i=%d w4=0x%04x C=0x%04x p0=0x%08x acc=0x%08x want=0x%08x %s' % (
            i, pairs[si][0], pairs[si][1], v, acc, want, 'OK' if acc == want else 'BAD'))
    o13 = [x for x in prog if x['op'] == 13]
    k2 = None
    if o13:
        imms = [p0[idxs.index(j)] for j in range(n)]
        f = fold13(o13[0]['imm'], imms, [pairs[j][1] for j in range(n)])
        k2 = ((f ^ acc) * 0x9e3779b1) & M
        if verbose: print('  fold=0x%08x key2=0x%08x' % (f, k2))
    H = [x for x in prog if x['op'] == 1][0]['imm'] & 0xff
    out = [dict(w4=pairs[si][0], C=pairs[si][1], p0=p0[i]) for i, si in enumerate(idxs)]
    return dict(items=out, key=k2, H=H, acc=acc)

if __name__ == '__main__':
    recs = parse_route()
    s1 = solve1(toprog(recs[0]))
    print('stage1 key=0x%08x' % s1['key'])
    sec1 = [bytes([s1['w4'][i] & 0xff, (s1['w4'][i] >> 8) & 0xff]) + struct.pack('<H', s1['Cv'][i]) +
            struct.pack('<I', s1['p0'][i]) + bytes([0, 0xa5 ^ (s1['w4'][i] & 0xff) ^ ((s1['w4'][i] >> 8) & 0xff)])
            for i in range(s1['n'])]
    sec1s = section(1, sec1, sum(s1['Cv'].values()) & 0xffff, s1['H'])
    p2 = toprog(decrypt(recs[1], s1['key'] ^ 0x46455252))
    s2 = solve2(p2)
    print('stage2 key=0x%08x H=0x%x' % (s2['key'], s2['H']))
    sec2 = [bytes([it['w4'] & 0xff, (it['w4'] >> 8) & 0xff]) + struct.pack('<H', it['C']) +
            struct.pack('<I', it['p0']) + bytes([0, 0xa5 ^ (it['w4'] & 0xff) ^ ((it['w4'] >> 8) & 0xff)])
            for it in s2['items']]
    sec2s = section(2, sec2, sum(it['C'] for it in s2['items']) & 0xffff, s2['H'])
    d = build(sec1s, sec2s)
    r = run(d)
    print('=> rc=%d %r %r' % (r.returncode, r.stdout.strip(), r.stderr.strip()[:100]))
