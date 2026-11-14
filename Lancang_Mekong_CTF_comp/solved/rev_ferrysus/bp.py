#!/usr/bin/env python3
"""Ferry boarding-pass builder.

Pass layout:
  'FJ\n\x00'
  then N sections:
    'FS' stage(1) count(1) X(u16) H(1) 0(1)        <- 8-byte header
    count * u16 offsets   (target - (section_start+8); == 2*count + 12*k)
    count * 12-byte instruction slots

Instruction slot (12 bytes; last 2 unused):
  [0] op                 opcode 1..25
  [1] tag                sub-selector / register / range low
  [2..3] C (u16)         range high / operand
  [4..7] imm (u32)       immediate
  [8]   D                aux byte
  [9]   checksum: 0xa5 ^ op ^ tag
"""
import struct, subprocess

def instr(op, tag=0, C=0, imm=0, D=0):
    b = bytes([op & 0xff, tag & 0xff]) + struct.pack('<H', C & 0xffff) + \
        struct.pack('<I', imm & 0xffffffff) + bytes([D & 0xff])
    chk = 0xa5 ^ (op & 0xff) ^ (tag & 0xff)
    return b + bytes([chk, 0, 0])

def section(stage, ins, X=0, H=0):
    n = len(ins)
    hdr = b'FS' + bytes([stage & 0xff, n & 0xff]) + struct.pack('<H', X) + bytes([H & 0xff, 0])
    offs = b''.join(struct.pack('<H', 2 * n + 12 * k) for k in range(n))
    return hdr + offs + b''.join(ins)

def build(*sections):
    return b'FJ\n\x00' + b''.join(sections)

def test(data, gate=None, tag='', route='route.bin'):
    open('/tmp/pass.bin', 'wb').write(data)
    args = ['./ferry-inspect', route, data.hex()]
    if gate is not None:
        args.append(gate)
    p = subprocess.run(args, capture_output=True, text=True)
    print(f'[{tag}] len={len(data)} rc={p.returncode} out={p.stdout.strip()!r} err={p.stderr.strip()[:160]!r}')
    return p

if __name__ == '__main__':
    test(build(section(1, [instr(9, imm=0x11111111)])), tag='S1 op9')
