#!/usr/bin/env python3
"""Build a pass section from an 8-byte-stride program (route record format)."""
import struct, subprocess, sys

def parse_route(path='route.bin'):
    d = open(path, 'rb').read()
    assert d[:4] == b'FSR2'
    off = 8
    recs = []
    while off < len(d):
        cnt = struct.unpack_from('<H', d, off)[0]
        off += 2
        recs.append(d[off:off + cnt * 8])
        off += cnt * 8
    return recs

def prog(rec):
    out = []
    for k in range(len(rec) // 8):
        e = rec[8 * k:8 * k + 8]
        out.append(dict(imm=int.from_bytes(e[0:4], 'little'), op=e[4], tag=e[5],
                        C=int.from_bytes(e[6:8], 'little')))
    return out

def slot(i, extra=b'\x00\x00\x00\x00'):
    return struct.pack('<I', i['imm']) + bytes([i['op'], i['tag']]) + struct.pack('<H', i['C']) + extra

def section(stage, ins, X=0, H=0):
    n = len(ins)
    hdr = b'FS' + bytes([stage & 0xff, n & 0xff]) + struct.pack('<H', X) + bytes([H & 0xff, 0])
    offs = b''.join(struct.pack('<H', 2 * n + 12 * k) for k in range(n))
    return hdr + offs + b''.join(ins)

def test(data, tag='', gate=None, route='route.bin'):
    open('/tmp/pass.bin', 'wb').write(data)
    a = ['./ferry-inspect', route, data.hex()]
    if gate: a.append(gate)
    p = subprocess.run(a, capture_output=True, text=True)
    print(f'[{tag}] len={len(data)} rc={p.returncode} {p.stdout.strip()!r} {p.stderr.strip()[:100]!r}')
    return p

if __name__ == '__main__':
    recs = parse_route()
    p0 = prog(recs[0])
    for H in [0x7c, 0, 1]:
        sec = section(1, [slot(i) for i in p0], X=0, H=H)
        test(b'FJ\n\x00' + sec, tag=f'rec0 H={H:#x}')
