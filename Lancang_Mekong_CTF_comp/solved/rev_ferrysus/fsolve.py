#!/usr/bin/env python3
"""Full ferry solver: per-stage constraint inversion + pass construction."""
import struct, subprocess, sys
sys.path.insert(0, '.')
from kvm import (rol, ror, inv32, cl_of, step, unstep, fold13, op11, s16,
                 parse_route, decrypt, toprog, M)

def solve_chain(items, seed, mul, mode, mul_const_C=None, targets=None, last_target=None):
    """items: list of dict(w4, C). Inverts the op10 chain.
    targets[i] = required accumulator after step i (for i < n-1),
    last_target = required accumulator after step n-1."""
    p0, acc, aux = [], seed, []
    for i, it in enumerate(items):
        want = targets[i] if targets and i in targets else last_target
        v = unstep(acc, want, it['w4'], it['C'], mul, i, mode)
        p0.append(v)
        acc = step(acc, v, it['w4'], it['C'], mul, i, mode)
        if acc != want:
            raise AssertionError('step %d mismatch' % i)
        aux.append((acc >> 28) & 0xf)
    return p0, acc, aux

def slot(w4, C, p0, D):
    w0, w1 = w4 & 0xff, (w4 >> 8) & 0xff
    return bytes([w0, w1]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', p0 & 0xffffffff) + bytes([D & 0xff, (0xa5 ^ w0 ^ w1) & 0xff])

def section(stage, slots, X, H):
    n = len(slots)
    hdr = b'FS' + bytes([stage & 0xff, n]) + struct.pack('<H', X & 0xffff) + bytes([H & 0xff, 0])
    offs = b''.join(struct.pack('<H', 2 * n + 8 * k) for k in range(n))
    return hdr + offs + b''.join(slots)

def build(*secs):
    return b'FJ\n\x00' + b''.join(secs)

if __name__ == '__main__':
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
    p0, acc, aux = solve_chain(items, seed, o10['imm'], o10['tag'] & 3,
                               targets=exp, last_target=tgt)
    H = [x for x in prog if x['op'] == 1][0]['imm'] & 0xff
    X = sum(Cv.values()) & 0xffff
    sl = [slot(items[i]['w4'], items[i]['C'], p0[i], aux[i]) for i in range(n)]
    d1 = build(section(1, sl, X, H))
    open('/tmp/s1.bin', 'wb').write(d1)
    r = subprocess.run(['./ferry-inspect', 'route.bin', d1.hex()], capture_output=True, text=True)
    f13 = fold13([x for x in prog if x['op'] == 13][0]['imm'], p0, [Cv[i] for i in range(n)])
    key = ((f13 ^ acc) * 0x9e3779b1) & M
    print('stage1 ok, key=0x%08x' % key)
