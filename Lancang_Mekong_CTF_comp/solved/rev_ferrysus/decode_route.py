#!/usr/bin/env python3
import struct

def parse_route(path='route.bin'):
    d = open(path, 'rb').read()
    assert d[:4] == b'FSR2' and d[4] == 0x0a and d[5:8] == b'\x00\x00\x00'
    off = 8
    recs = []
    while off < len(d):
        cnt = struct.unpack_from('<H', d, off)[0]
        off += 2
        recs.append(d[off:off + cnt * 8])
        off += cnt * 8
    return recs

M32 = 0xffffffff
def xs(state):
    state &= M32
    state ^= (state << 13) & M32
    state ^= state >> 17
    state ^= (state << 5) & M32
    return state & M32

def keystream(n, seed=1):
    s = seed
    out = b''
    for _ in range((n + 3) // 4):
        s = xs(s)
        out += struct.pack('<I', s)
    return out[:n]

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

if __name__ == '__main__':
    recs = parse_route()
    for i, r in enumerate(recs):
        print(f'rec{i} len={len(r)}')
    print()
    ks = keystream(max(len(r) for r in recs))
    for i, r in enumerate(recs):
        dec = r if i == 0 else xor(r, ks)
        print(f'--- decoded rec{i} ({len(dec)} bytes)')
        for j in range(0, len(dec), 8):
            e = dec[j:j+8]
            print('  ', j // 8, e.hex(' '), 'a=', e[0], 'u16=', struct.unpack_from('<H', e, 2)[0],
                  'u32=', hex(struct.unpack_from('<I', e, 4)[0]))
