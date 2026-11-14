#!/usr/bin/env python3
"""Final chain solver for ferry-inspect."""
import struct, subprocess, sys
sys.path.insert(0, '.')
from common import *
from op10m import mode_of, sub

M32 = 0xffffffff

def rol32(v, n):
    n &= 31; v &= M32
    return ((v << n) | (v >> (32 - n))) & M32 if n else v

def op11(x, tag, C):
    return (rol32(x, tag) ^ rol32(x, C) ^ x) & M32

def inv_op11(target, tag, C):
    cols = [op11(1 << i, tag, C) for i in range(32)]
    mat = [[(cols[i] >> b) & 1 for b in range(32)] +
           [((1 << i) >> b) & 1 for b in range(32)] for i in range(32)]
    for c in range(32):
        p = next((r for r in range(c, 32) if mat[r][c]), None)
        if p is None:
            raise ValueError('singular')
        mat[c], mat[p] = mat[p], mat[c]
        for r in range(32):
            if r != c and mat[r][c]:
                mat[r] = [a ^ b for a, b in zip(mat[r], mat[c])]
    out = 0
    for b in range(32):
        if (target >> b) & 1:
            out ^= sum(mat[b][32 + k] << k for k in range(32))
    return out & M32

def s16(x):
    x &= 0xffff
    return x - 0x10000 if x & 0x8000 else x

def slot(w4, C, p0, D=0):
    w0, w1 = w4 & 0xff, (w4 >> 8) & 0xff
    return bytes([w0, w1]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', p0 & M32) + bytes([D & 0xff, (0xa5 ^ w0 ^ w1) & 0xff])

def section(stage, slots, X, H, count=None):
    n = count if count is not None else len(slots)
    hdr = b'FS' + bytes([stage & 0xff, n]) + struct.pack('<H', X & 0xffff) + bytes([H & 0xff, 0])
    return hdr + b''.join(struct.pack('<H', 2 * n + 8 * k) for k in range(n)) + b''.join(slots)

def build(*secs):
    return b'FJ\n\x00' + b''.join(secs)

def run(data):
    open('/tmp/x.bin', 'wb').write(data)
    return subprocess.run(['./ferry-inspect', 'route.bin', data.hex()], capture_output=True, text=True)

def solve_stage(prog, pairs, regs, last, seed, verbose=False):
    o10 = [x for x in prog if x['op'] == 10][0]
    mul, tag, nib = o10['imm'], o10['tag'], o10['C'] & 0xff
    p0, ds, acc = [], [], seed
    for i, (w4, C) in enumerate(pairs):
        want = regs.get(i, last)
        md = mode_of(tag, acc)
        v = (sub(want, C, mul, cl_of(w4, i), md, w4) ^ acc) & M32
        chk = step(acc, v, w4, C, mul, i, md)
        assert chk == want, (i, hex(chk), hex(want))
        p0.append(v)
        ds.append((chk >> 28) & 0xf if nib == 1 else (chk & 0xf if nib == 2 else 0))
        acc = chk
        if verbose:
            print('   i=%d p0=0x%08x acc=0x%08x D=%d' % (i, v, chk, ds[-1]))
    return p0, ds, acc

if __name__ == '__main__':
    recs = parse_route()
    # ---------- stage 1 ----------
    prog1 = toprog(recs[0])
    pairs1 = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog1 if x['op'] == 15]
    regs1 = {x['tag']: x['imm'] for x in prog1 if x['op'] == 16}
    last1 = [x for x in prog1 if x['op'] == 12][0]['imm']
    seed1 = [x for x in prog1 if x['op'] == 9][0]['imm']
    p0_1, d1, acc1 = solve_stage(prog1, pairs1, regs1, last1, seed1)
    H1 = [x for x in prog1 if x['op'] == 1][0]['imm'] & 0xff
    X1 = sum(c for _, c in pairs1) & 0xffff
    sec1 = section(1, [slot(pairs1[i][0], pairs1[i][1], p0_1[i], d1[i]) for i in range(len(pairs1))], X1, H1)
    k1 = fold13([x for x in prog1 if x['op'] == 13][0]['imm'], p0_1, [c for _, c in pairs1])
    key1 = ((k1 ^ acc1) * 0x9e3779b1) & M32
    print('stage1 key=0x%08x' % key1)
    print('  sec1 alone  ->', run(build(sec1)).stdout.strip())

    # ---------- stage 2 ----------
    prog2 = toprog(decrypt(recs[1], key1 ^ 0x46455252))
    pairs2 = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog2 if x['op'] == 15]
    regs2 = {x['tag']: x['imm'] for x in prog2 if x['op'] == 16}
    seed2 = [x for x in prog2 if x['op'] == 9][0]['imm']
    o11 = [x for x in prog2 if x['op'] == 11][0]
    o12 = [x for x in prog2 if x['op'] == 12][0]['imm']
    o13 = [x for x in prog2 if x['op'] == 13]
    # op11 runs AFTER op10, so op10 must land on inv_op11(o12)
    last2 = inv_op11(o12, o11['tag'], o11['C'])
    p0_2, d2, acc2 = solve_stage(prog2, pairs2, regs2, last2, seed2, verbose=True)
    print('  stage2 op10 ends at 0x%08x' % acc2)
    H2 = [x for x in prog2 if x['op'] == 1][0]['imm'] & 0xff
    tot = sum(c for _, c in pairs2) & 0xffff
    k2 = fold13(o13[0]['imm'], p0_2, [c for _, c in pairs2])
    key2 = ((k2 ^ o12) * 0x9e3779b1) & M32
    print('  stage2 key=0x%08x' % key2)

    n = len(pairs2)
    for dup in range(n):
        for split in (0, 1):
            items = []
            for i in range(n):
                w4, C = pairs2[i]
                if i == dup:
                    items.append(slot(w4, split, 0, d2[i]))
                    items.append(slot(w4, (C - split) & 0xffff, p0_2[i], d2[i]))
                else:
                    items.append(slot(w4, C, p0_2[i], d2[i]))
            X2 = (tot) & 0xffff
            d = build(sec1, section(2, items, X2, H2))
            r = run(d)
            if 'ACCEPTED' in r.stdout:
                print('*** ACCEPTED dup=%d split=%d' % (dup, split))
                open('/tmp/final.bin', 'wb').write(d)
                raise SystemExit
    print('  stage2 not accepted')
