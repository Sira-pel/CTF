#!/usr/bin/env python3
"""Full ferry solver with correct D-byte semantics.

D check (opcode 10):  mode2 -> (acc & 0xf) == D ;  mode1 -> (acc >> 28) == D
"""
import struct, subprocess, sys
sys.path.insert(0, '.')
from common import (rol, ror, inv32, cl_of, neg31, step, parse_route, toprog,
                    decrypt, fold13, M)
from op10m import mode_of, sub

def op11(acc, tag, C):
    return (rol(acc, tag) ^ rol(acc, C) ^ acc) & M

def chain(prog, pairs, regs, last, seed=None):
    o10 = [x for x in prog if x['op'] == 10][0]
    mul, tag = o10['imm'], o10['tag']
    # nibble selector = instruction C low byte: 1 -> (acc>>28), 2 -> (acc&0xf)
    nib = o10['C'] & 0xff
    if seed is None:
        seed = [x for x in prog if x['op'] == 9][0]['imm']
    p0, ds, acc = [], [], seed
    for i, (w4, C) in enumerate(pairs):
        want = regs.get(i, last)
        md = mode_of(tag, acc)
        cl = cl_of(w4, i)
        v = (sub(want, C, mul, cl, md, w4) ^ acc) & M
        chk = step(acc, v, w4, C, mul, i, md)
        assert chk == want, (i, hex(chk), hex(want))
        p0.append(v)
        if nib == 1:
            ds.append((chk >> 28) & 0xf)
        elif nib == 2:
            ds.append(chk & 0xf)
        else:
            ds.append(0)
        acc = chk
    return p0, ds, acc

def slot(w4, C, p0, D=0):
    w0, w1 = w4 & 0xff, (w4 >> 8) & 0xff
    return bytes([w0, w1]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', p0 & M) + bytes([D, (0xa5 ^ w0 ^ w1) & 0xff])

def section(stage, slots_, X, H):
    n = len(slots_)
    hdr = b'FS' + bytes([stage & 0xff, n]) + struct.pack('<H', X & 0xffff) + bytes([H & 0xff, 0])
    return hdr + b''.join(struct.pack('<H', 2*n + 8*k) for k in range(n)) + b''.join(slots_)

def build(*secs):
    return b'FJ\n\x00' + b''.join(secs)

def run(data):
    open('/tmp/x.bin', 'wb').write(data)
    return subprocess.run(['./ferry-inspect', 'route.bin', data.hex()], capture_output=True, text=True)

if __name__ == '__main__':
    prog = toprog(parse_route()[0])
    pairs = [(x['imm'] & 0xffff, x['imm'] >> 16) for x in prog if x['op'] == 15]
    regs = {x['tag']: x['imm'] for x in prog if x['op'] == 16}
    last = [x for x in prog if x['op'] == 12][0]['imm']
    p0, ds, acc = chain(prog, pairs, regs, last)
    H = [x for x in prog if x['op'] == 1][0]['imm'] & 0xff
    X = sum(c for _, c in pairs) & 0xffff
    for i in range(len(pairs)):
        print('  i=%d w4=0x%04x C=0x%04x p0=0x%08x D=%d' % (i, pairs[i][0], pairs[i][1], p0[i], ds[i]))
    d = build(section(1, [slot(pairs[i][0], pairs[i][1], p0[i], ds[i]) for i in range(len(pairs))], X, H))
    r = run(d)
    print('=> rc=%d %r' % (r.returncode, r.stdout.strip()))
    open('/tmp/one.bin', 'wb').write(d)
