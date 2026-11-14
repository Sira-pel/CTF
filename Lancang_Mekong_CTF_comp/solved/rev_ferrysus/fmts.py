#!/usr/bin/env python3
"""Correct ferry pass layout (verified from disassembly).

pass    := 'FJ\n\x00' section*
section := 'FS' stage(1) count(1) X(u16) H(1) 0(1)
           count*u16 offsets,  offsets[k] = 2*count + 10*k   (relative to entry pos base+2k)
           count*12B slots
slot    := op(1) tag(1) C(u16) imm(u32) D(1) chk(1) pad(2)
"""
import struct, subprocess

def slot(op, tag=0, C=0, imm=0, D=0, chk=None):
    c = (0xa5 ^ (op & 0xff) ^ (tag & 0xff)) if chk is None else chk
    return bytes([op & 0xff, tag & 0xff]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', imm & 0xffffffff) + bytes([D & 0xff, c & 0xff, 0, 0])

def section(stage, slots, X=0, H=0):
    n = len(slots)
    assert 1 <= n <= 8, n
    hdr = b'FS' + bytes([stage & 0xff, n]) + struct.pack('<H', X & 0xffff) + bytes([H & 0xff, 0])
    offs = b''.join(struct.pack('<H', 2 * n + 10 * k) for k in range(n))
    return hdr + offs + b''.join(slots)

def build(*secs):
    return b'FJ\n\x00' + b''.join(secs)

def run(data, gate=None, route='route.bin'):
    open('/tmp/x.bin', 'wb').write(data)
    a = ['./ferry-inspect', route, data.hex()]
    if gate:
        a.append(gate)
    return subprocess.run(a, capture_output=True, text=True)

def show(data, tag='', gate=None):
    r = run(data, gate)
    print('[%s] len=%d rc=%d %r %r' % (tag, len(data), r.returncode, r.stdout.strip(), r.stderr.strip()[:100]))
    return r

if __name__ == '__main__':
    show(build(section(1, [slot(8)])), 'op8-only')
