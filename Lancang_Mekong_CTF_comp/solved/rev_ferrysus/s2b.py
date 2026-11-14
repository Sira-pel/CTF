#!/usr/bin/env python3
"""Solve stage 2 with dynamic op10 modes + op11 seed tweak; test in the real binary."""
import struct, subprocess, sys
sys.path.insert(0, '.')
from common import (rol, ror, inv32, cl_of, neg31, step, parse_route, toprog,
                    decrypt, fold13, M)
from op10m import solve_stage, mode_of, sub

def op11(acc, tag, C):
    return (rol(acc, tag) ^ rol(acc, C) ^ acc) & M

def slot(w4, C, p0, D=0):
    w0, w1 = w4 & 0xff, (w4 >> 8) & 0xff
    return bytes([w0, w1]) + struct.pack('<H', C & 0xffff) + struct.pack('<I', p0 & M) + \
           bytes([D, (0xa5 ^ w0 ^ w1) & 0xff])

def section(stage, slots_, X, H):
    n = len(slots_)
    hdr = b'FS' + bytes([stage & 0xff, n]) + struct.pack('<H', X & 0xffff) + bytes([H & 0xff, 0])
    return hdr + b''.join(struct.pack('<H', 2*n + 8*k) for k in range(n)) + b''.join(slots_)

def build(*secs):
    return b'FJ\n\x00' + b''.join(secs)

def run(data):
    open('/tmp/x.bin', 'wb').write(data)
    return subprocess.run(['./ferry-inspect', 'route.bin', data.hex()], capture_output=True, text=True)

def s16(x):
    x &= 0xffff
    return x - 0x10000 if x & 0x8000 else x

if __name__ == '__main__':
    recs = parse_route()
    # ---- stage 1
    prog1 = toprog(recs[0])
    pairs1 = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog1 if x['op'] == 15]
    regs1 = {x['tag']: x['imm'] for x in prog1 if x['op'] == 16}
    last1 = [x for x in prog1 if x['op'] == 12][0]['imm']
    p0a, acc1, mul1, tag1 = solve_stage(prog1, pairs1, regs1, last1, verbose=False)
    f1 = fold13([x for x in prog1 if x['op'] == 13][0]['imm'], p0a, [c for _, c in pairs1])
    key1 = ((f1 ^ acc1) * 0x9e3779b1) & M
    H1 = [x for x in prog1 if x['op'] == 1][0]['imm'] & 0xff
    X1 = sum(c for _, c in pairs1) & 0xffff
    sec1 = section(1, [slot(w4, C, p0a[i]) for i, (w4, C) in enumerate(pairs1)], X1, H1)

    # ---- stage 2
    prog2 = toprog(decrypt(recs[1], key1 ^ 0x46455252))
    pairs2 = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog2 if x['op'] == 15]
    regs2 = {x['tag']: x['imm'] for x in prog2 if x['op'] == 16}
    last2 = [x for x in prog2 if x['op'] == 12][0]['imm']
    o3 = [x for x in prog2 if x['op'] == 3][0]['imm']
    o8 = [x for x in prog2 if x['op'] == 8][0]
    o11s = [x for x in prog2 if x['op'] == 11]
    key_s = s16(o3 & 0xffff); mask = (o3 >> 16) & 0xffff
    order = sorted(range(len(pairs2)), key=lambda i: (((s16(pairs2[i][0]) * key_s) & 0xffff) ^ mask) & 0xffff)
    print('sort order:', order, 'w4:', [hex(pairs2[i][0]) for i in order])
    ordered = [pairs2[i] for i in order]
    seed2 = [x for x in prog2 if x['op'] == 9][0]['imm']
    if o11s:
        seed2 = op11(seed2, o11s[0]['tag'], o11s[0]['C'])
        print('op11 seed -> 0x%08x' % seed2)
    # patch op9's imm by simulating: solve_stage uses prog's op9; emulate manually
    o10 = [x for x in prog2 if x['op'] == 10][0]
    mul, tag = o10['imm'], o10['tag']
    p0b, acc2 = [], seed2
    for i, (w4, C) in enumerate(ordered):
        want = regs2.get(i, last2)
        md = mode_of(tag, acc2)
        cl = cl_of(w4, i)
        v = (sub(want, C, mul, cl, md, w4) ^ acc2) & M
        chk = step(acc2, v, w4, C, mul, i, md)
        print('  i=%d mode=%d cl=%2d p0=0x%08x -> 0x%08x want 0x%08x %s' % (
            i, md, cl, v, chk, want, 'OK' if chk == want else 'BAD'))
        p0b.append(v)
        acc2 = chk
    # map back
    p0map = {order[i]: p0b[i] for i in range(len(order))}
    X2 = o8 and (sum(pairs2[i][1] for i in range(len(pairs2) - 1)) & 0xffff)
    print('X2(op8 sum first n-1) = 0x%x' % X2)
    H2 = [x for x in prog2 if x['op'] == 1][0]['imm'] & 0xff
    sec2 = section(2, [slot(pairs2[i][0], pairs2[i][1], p0map[i]) for i in range(len(pairs2))], X2, H2)
    d = build(sec1, sec2)
    r = run(d)
    print('=> rc=%d %r' % (r.returncode, r.stdout.strip()))
    open('/tmp/two.bin', 'wb').write(d)
