#!/usr/bin/env python3
"""Ferry boarding pass builder — verified layout.

pass := 'FJ\n\x00'  section*

section := 'FS' stage(1) count(1) X(u16) H(1) 0(1)
           count * u16  offsets[k] = 2*count + 8*k
           count * 10B  slots (op, tag, C(u16), imm(u32), D, chk=0xa5^op^tag)
"""
import struct, subprocess

def slot(op, tag=0, C=0, imm=0, D=0, chk=None):
    c = (0xa5 ^ (op & 0xff) ^ (tag & 0xff)) if chk is None else chk
    return bytes([op & 0xff, tag & 0xff]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', imm & 0xffffffff) + bytes([D & 0xff, c & 0xff])

def section(stage, items, X=0, H=0):
    n = len(items)
    assert 1 <= n <= 8
    hdr = b'FS' + bytes([stage & 0xff, n]) + struct.pack('<H', X & 0xffff) + bytes([H & 0xff, 0])
    offs = b''.join(struct.pack('<H', 2 * n + 8 * k) for k in range(n))
    return hdr + offs + b''.join(items)

def build(*secs):
    return b'FJ\n\x00' + b''.join(secs)

def test(data, tag='', gate=None, show=False, route='route.bin'):
    open('/tmp/p.bin', 'wb').write(data)
    a = ['./ferry-inspect', route, data.hex()]
    if gate:
        a.append(gate)
    p = subprocess.run(a, capture_output=True, text=True)
    print('[%s] len=%d rc=%d %r %r' % (tag, len(data), p.returncode, p.stdout.strip(), p.stderr.strip()[:100]))
    if show:
        print('  ', data.hex())
    return p

if __name__ == '__main__':
    test(build(section(1, [slot(8)])), 's1-op8', show=True)
