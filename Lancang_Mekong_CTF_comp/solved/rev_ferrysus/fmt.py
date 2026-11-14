#!/usr/bin/env python3
"""Boarding pass builder + GDB VM tracer."""
import struct, subprocess

def instr(op, tag=0, C=0, imm=0, D=0):
    chk = 0xa5 ^ (op & 0xff) ^ (tag & 0xff)
    return bytes([op & 0xff, tag & 0xff]) + struct.pack('<H', C & 0xffff) + \
           struct.pack('<I', imm & 0xffffffff) + bytes([D & 0xff, chk, 0])

def section(stage, ins, X=0, H=0):
    n = len(ins)
    hdr = b'FS' + bytes([stage & 0xff, n & 0xff]) + struct.pack('<H', X) + bytes([H & 0xff, 0])
    offs = b''.join(struct.pack('<H', 2 * n + 12 * k) for k in range(n))
    return hdr + offs + b''.join(ins)

def build(*sections):
    return b'FJ\n\x00' + b''.join(sections)
