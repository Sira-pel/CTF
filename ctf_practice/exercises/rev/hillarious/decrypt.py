import struct, sys
M = (1<<64)-1
A, C, Dd = 0x5851f42d4c957f2d, 0x6c576fac43fd007c, 0x14057b7ef767814f
def keys(seed):
    h = 0xcbf29ce484222325
    for i in range(8): h = ((h ^ ((seed >> 8*i) & 0xff)) * 0x100000001b3) & M
    h ^= 0xdeadbeefcafebabe
    xk = h.to_bytes(8, 'little')
    s1 = (h*A + C) & M; s2 = (s1*A + Dd) & M; s3 = (s2*A + Dd) & M; s4 = (s3*A + Dd) & M
    m0 = (s1 | 1) & 0xff; m1 = s2 & 0xff; m2 = s3 & 0xff; m3 = (s4 | 1) & 0xff
    if (m0*m3 - m1*m2) & 1 == 0: m0 = (m0 + 2) & 0xff
    return xk, (m0, m1, m2, m3)
for fn in sys.argv[1:]:
    b = open(fn,'rb').read(); assert b[:4] == b'SNAR'
    seed, ln, ver = struct.unpack('<QII', b[4:20]); ct = b[20:]
    xk, (a, bb, c, d) = keys(seed)
    t = bytes(x ^ xk[i & 7] for i, x in enumerate(ct))
    det = (a*d - bb*c) % 256; di = pow(det, -1, 256)
    ia, ib, ic, id_ = d*di % 256, -bb*di % 256, -c*di % 256, a*di % 256
    out = bytearray()
    for i in range(0, len(t), 2):
        y0, y1 = t[i], t[i+1]
        out += bytes([(ia*y0 + ib*y1) & 0xff, (ic*y0 + id_*y1) & 0xff])
    print(f'== {fn} seed={seed} len={ln} m={a,bb,c,d}'); print(bytes(out[:ln]).decode(errors='replace'))
