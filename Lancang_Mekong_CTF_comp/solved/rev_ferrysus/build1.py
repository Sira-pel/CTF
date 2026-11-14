#!/usr/bin/env python3
"""Build the stage-1 boarding pass from route record 0 constraints."""
import struct, subprocess

M = 0xffffffff

def rol(v, n):
    n &= 31; v &= M
    return ((v << n) | (v >> (32 - n))) & M if n else v

def ror(v, n):
    n &= 31; v &= M
    return ((v >> n) | (v << (32 - n))) & M if n else v

def inv32(a):
    x = 1
    for _ in range(5):
        x = (x * (2 - a * x)) & M
    return x

def parse_route(path='route.bin'):
    d = open(path, 'rb').read()
    off, recs = 8, []
    while off < len(d):
        cnt = struct.unpack_from('<H', d, off)[0]
        off += 2
        recs.append(d[off:off + cnt * 8])
        off += cnt * 8
    return recs

def route_items(rec):
    out = []
    for k in range(len(rec) // 8):
        e = rec[8 * k:8 * k + 8]
        out.append(dict(op=e[0], tag=e[1], C=int.from_bytes(e[2:4], 'little'),
                        imm=int.from_bytes(e[4:8], 'little')))
    return out

def op10_step(acc, imm, w4, C, mul, i):
    a = (w4 & 7) + 5 * i
    cl = (a % 31) + 1
    return (rol(((acc ^ imm) * mul) & M, cl) ^ ((C * 0x1000193) & M)) & M

def op10_unstep(acc, want, w4, C, mul, i):
    a = (w4 & 7) + 5 * i
    cl = (a % 31) + 1
    y = (want ^ ((C * 0x1000193) & M)) & M
    return ((ror(y, cl) * inv32(mul)) & M) ^ acc

def slot(op, tag, C, imm, D=0):
    chk = 0xa5 ^ (op & 0xff) ^ (tag & 0xff)
    return bytes([op & 0xff, tag & 0xff]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', imm & 0xffffffff) + bytes([D & 0xff, chk])

def sec(stage, slots, X=0, H=0):
    n = len(slots)
    hdr = b'FS' + bytes([stage, n]) + struct.pack('<H', X) + bytes([H, 0])
    offs = b''.join(struct.pack('<H', 2 * n + 8 * k) for k in range(n))
    return hdr + offs + b''.join(slots)

def build(*s):
    return b'FJ\n\x00' + b''.join(s)

def run(data, gate=None):
    open('/tmp/x.bin', 'wb').write(data)
    a = ['./ferry-inspect', 'route.bin', data.hex()]
    if gate: a.append(gate)
    p = subprocess.run(a, capture_output=True, text=True)
    return p

if __name__ == '__main__':
    it = route_items(parse_route()[0])
    w4, Cv = {}, {}
    for x in it:
        if x['op'] == 15:
            w4[x['tag']] = x['imm'] & 0xffff
            Cv[x['tag']] = x['imm'] >> 16
    n = len(w4)
    exp = {x['tag']: x['imm'] for x in it if x['op'] == 16}
    seed = [x for x in it if x['op'] == 9][0]['imm']
    mul = [x for x in it if x['op'] == 10][0]['imm']
    tgt = [x for x in it if x['op'] == 12][0]['imm']
    print('n=%d mul=0x%08x seed=0x%08x tgt=0x%08x' % (n, mul, seed, tgt))
    imms, acc = [], seed
    for i in range(n):
        want = exp.get(i, tgt)
        v = op10_unstep(acc, want, w4[i], Cv[i], mul, i)
        imms.append(v)
        chk = op10_step(acc, v, w4[i], Cv[i], mul, i)
        print('  i=%d imm=0x%08x chk=0x%08x want=0x%08x %s' % (i, v, chk, want, 'OK' if chk == want else 'BAD'))
        acc = chk
    slots = [slot(w4[i] & 0xff, (w4[i] >> 8) & 0xff, Cv[i], imms[i]) for i in range(n)]
    X = sum(Cv.values()) & 0xffff
    H = [x for x in it if x['op'] == 1][0]['imm'] & 0xff
    p = build(sec(1, slots, X=X, H=H))
    print('X=0x%x H=0x%x len=%d' % (X, H, len(p)))
    r = run(p)
    print('=>', r.returncode, r.stdout.strip(), r.stderr.strip()[:100])
