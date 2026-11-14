#!/usr/bin/env python3
"""Ferry pass builder: verified pass-item field order.

pass item (10 bytes) as stored by the VM's section parser:
  [0..1]  w4  (u16, small index/tag used by op15/op16/op7)
  [2..3]  C   (u16, per-item constant checked by op8 and used in folding)
  [4..7]  p0  (u32, the secret payload word)
  [8]     D   (u8, aux/high-nibble of the folded accumulator)
  [9]     chk = 0xa5 ^ [0] ^ [1]
"""
import struct, subprocess

def slot(w4, C, p0, D=0):
    w0, w1 = w4 & 0xff, (w4 >> 8) & 0xff
    return bytes([w0, w1]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', p0 & 0xffffffff) + bytes([D & 0xff, (0xa5 ^ w0 ^ w1) & 0xff])

def section(stage, slots, X=0, H=0):
    n = len(slots)
    hdr = b'FS' + bytes([stage & 0xff, n & 0xff]) + struct.pack('<H', X & 0xffff) + bytes([H & 0xff, 0])
    offs = b''.join(struct.pack('<H', 2 * n + 8 * k) for k in range(n))
    return hdr + offs + b''.join(slots)

def build(*secs):
    return b'FJ\n\x00' + b''.join(secs)

def run(data, gate=None):
    open('/tmp/x.bin', 'wb').write(data)
    a = ['./ferry-inspect', 'route.bin', data.hex()]
    if gate:
        a.append(gate)
    return subprocess.run(a, capture_output=True, text=True)

def show(data, tag=''):
    r = run(data)
    print('[%s] len=%d rc=%d %r' % (tag, len(data), r.returncode, r.stdout.strip()))
    return r
