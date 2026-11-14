#!/usr/bin/env python3
"""Recover the xorshift32 seeds that turn route records into valid FS programs."""
import struct

M = 0xffffffff

def xs(x):
    x &= M
    x ^= (x << 13) & M
    x ^= x >> 17
    x ^= (x << 5) & M
    return x & M

def unxshl_right(y, s):
    """invert x = y ^ (y >> s)"""
    x = 0
    for i in range(0, 32, s):
        part = (y >> i) & ((1 << s) - 1)
        if i == 0:
            x |= part
        else:
            prev = (x >> (i - s)) & ((1 << s) - 1)
            x |= (part ^ prev) << i
    return x & M

def xs_inv(y):
    y &= M
    # invert x ^= x<<5  =>  a = y ^ (y<<5) ^ (y<<10) ^ (y<<15) ^ (y<<20) ^ (y<<25)
    x = y
    x ^= (y << 5) & M
    x ^= (y << 10) & M
    x ^= (y << 15) & M
    x ^= (y << 20) & M
    x ^= (y << 25) & M
    y = x & M
    # invert x ^= x>>17
    x = y ^ (y >> 17)
    y = x & M
    # invert x ^= x<<13
    x = y
    for i in range(1, 32, 13):
        x ^= (y << i) & M
    return x & M

# sanity check
for t in [1, 12345, 0xdeadbeef, 0x46455252]:
    assert xs_inv(xs(t)) == t, (hex(t), hex(xs_inv(xs(t))))

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

def check_program(p):
    """Validate an FS-section program; return list of section info or None."""
    if len(p) < 12:
        return None
    off = 4
    sections = []
    while off < len(p):
        if off + 8 > len(p):
            return None
        if p[off:off + 2] != b'FS':
            return None
        stage, n = p[off + 2], p[off + 3]
        X = struct.unpack_from('<H', p, off + 4)[0]
        if not (1 <= n <= 8):
            return None
        if p[off + 7] != 0:
            return None
        base = off + 8
        if base + 2 * n > len(p):
            return None
        offs = [struct.unpack_from('<H', p, base + 2 * k)[0] for k in range(n)]
        end = base + 12 * n
        if end > len(p):
            return None
        # each target = base + off
        for o in offs:
            if o < 2 * n:
                return None
            t = base + o
            if t + 10 > len(p):
                return None
        sections.append(dict(off=off, stage=stage, n=n, X=X, offs=offs, base=base, end=end,
                            data=p[off:end], tail=p[end:]))
        off = end
    return sections

def main():
    recs = parse_route()
    print('records:', [len(r) for r in recs])
    for i, rec in enumerate(recs):
        cands = []
        for stage in range(0, 16):
            for n in range(1, 9):
                P = b'FS' + bytes([stage, n])
                k0 = bytes(a ^ b for a, b in zip(rec[:4], P))
                state1 = struct.unpack('<I', k0)[0]
                seed = xs_inv(state1)
                dec = bytes(a ^ b for a, b in zip(rec, keystream(seed, len(rec))))
                if dec[:2] == b'FS':
                    secs = check_program(dec)
                    cands.append((seed, stage, n, secs is not None, dec))
        print(f'--- rec{i} len={len(rec)} candidates={len(cands)}')
        for seed, stage, n, ok, dec in cands:
            print(f'   seed=0x{seed:08x} stage={stage} n={n} valid={ok}')
            if ok:
                secs = check_program(dec)
                for s in secs:
                    print(f'      section off={s["off"]} stage={s["stage"]} n={s["n"]} X=0x{s["X"]:04x} end={s["end"]} tail={len(s["tail"])}')
                print('      dec:', dec.hex(' '))

if __name__ == '__main__':
    main()
