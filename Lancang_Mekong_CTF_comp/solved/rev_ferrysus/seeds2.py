#!/usr/bin/env python3
"""Recover xorshift32 seeds for route records (bit-exact inverse)."""
import struct

M = 0xffffffff

def xs(x):
    x &= M
    x ^= (x << 13) & M
    x ^= x >> 17
    x ^= (x << 5) & M
    return x & M

def xs_inv(y):
    y &= M
    # undo x ^= x << 5  (bitwise, low to high)
    x = 0
    for i in range(32):
        yi = (y >> i) & 1
        prev = (x >> (i - 5)) & 1 if i >= 5 else 0
        bit = yi ^ prev
        x |= bit << i
    y = x & M
    # undo x ^= x >> 17 (high to low)
    x = 0
    for i in range(31, -1, -1):
        yi = (y >> i) & 1
        nxt = (x >> (i + 17)) & 1 if i + 17 < 32 else 0
        bit = yi ^ nxt
        x |= bit << i
    y = x & M
    # undo x ^= x << 13 (low to high)
    x = 0
    for i in range(32):
        yi = (y >> i) & 1
        prev = (x >> (i - 13)) & 1 if i >= 13 else 0
        bit = yi ^ prev
        x |= bit << i
    return x & M

for t in [0, 1, 12345, 0xdeadbeef, 0x46455252, 0x9c49a52f]:
    assert xs_inv(xs(t)) == t, (hex(t), hex(xs_inv(xs(t))))
print('inverse OK')

def keystream(seed, n):
    out = b''
    s = seed & M
    while len(out) < n:
        s = xs(s)
        out += struct.pack('<I', s)
    return out[:n]

def parse_route(path='route.bin'):
    d = open(path, 'rb').read()
    off = 8
    recs = []
    while off < len(d):
        cnt = struct.unpack_from('<H', d, off)[0]
        off += 2
        recs.append(d[off:off + cnt * 8])
        off += cnt * 8
    return recs

def validate(p):
    if len(p) < 12 or p[:4] != b'FJ\n\x00':
        return None
    off = 4
    secs = []
    while off < len(p):
        if off + 8 > len(p) or p[off:off + 2] != b'FS':
            return None
        stage, n = p[off + 2], p[off + 3]
        X = struct.unpack_from('<H', p, off + 4)[0]
        if not (1 <= n <= 8) or p[off + 7] != 0:
            return None
        base = off + 8
        end = base + 12 * n
        if end > len(p):
            return None
        offs = [struct.unpack_from('<H', p, base + 2 * k)[0] for k in range(n)]
        for o in offs:
            if o < 2 * n or base + o + 10 > len(p):
                return None
        secs.append((off, stage, n, X, end))
        off = end
    return secs

def main():
    recs = parse_route()
    print('records:', [len(r) for r in recs])
    for i, rec in enumerate(recs):
        found = []
        for stage in range(256):
            for n in range(1, 9):
                want = b'FS' + bytes([stage, n])
                ks0 = bytes(a ^ b for a, b in zip(rec[:4], want))
                seed = xs_inv(struct.unpack('<I', ks0)[0])
                dec = bytes(a ^ b for a, b in zip(rec, keystream(seed, len(rec))))
                if dec[:4] == want:
                    secs = validate(dec)
                    found.append((seed, stage, n, secs, dec))
        print(f'--- rec{i} len={len(rec)} found={len(found)}')
        for seed, stage, n, secs, dec in found:
            print(f'   seed=0x{seed:08x} stage={stage} n={n} secs={secs}')
            if secs:
                print('     dec:', dec.hex(' '))

if __name__ == '__main__':
    main()
