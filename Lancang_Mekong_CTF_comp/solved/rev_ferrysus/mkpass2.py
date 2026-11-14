#!/usr/bin/env python3
"""Ferry boarding-pass builder + GDB tracer."""
import struct, subprocess, os

INSTR_SIZE = 12

def instr(op, tag=0, C=0, B=0, D=0, pad=0):
    chk = 0xa5 ^ (op & 0xff) ^ (tag & 0xff)
    b = struct.pack('<BBHIBB', op & 0xff, tag & 0xff, C & 0xffff, B & 0xffffffff, D & 0xff, chk)
    assert len(b) == 10
    return b + bytes([pad, 0])

def section(stage, ins, X=0, H=0):
    n = len(ins)
    hdr = b'FS' + bytes([stage & 0xff, n & 0xff]) + struct.pack('<H', X) + bytes([H, 0])
    return hdr + b''.join(ins)

def build(*sections):
    return b'FJ\n\x00' + b''.join(sections)

def test(data, gate=None, tag=''):
    open('/tmp/pass.bin', 'wb').write(data)
    args = ['./ferry-inspect', 'route.bin', data.hex()]
    if gate is not None:
        args.append(gate)
    p = subprocess.run(args, capture_output=True, text=True)
    print(f'[{tag}] len={len(data)} rc={p.returncode} out={p.stdout.strip()!r} err={p.stderr.strip()[:120]!r}')
    return p

if __name__ == '__main__':
    test(build(), tag='empty')
    test(build(section(1, [])), tag='sec-n0')
    test(build(section(1, [instr(9, B=0)])), tag='sec-op9')
    test(build(section(1, [instr(9, B=0)], X=0)), tag='sec-op9-x0')
