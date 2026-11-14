#!/usr/bin/env python3
"""Build a ferry boarding pass file for ferry-inspect and test it."""
import struct, subprocess, sys

SLOT = 10

def slot(op, tag_hi=0, B=0, value=0, X=None, pad=0):
    if X is None:
        X = 0xa5 ^ (op & 0xff) ^ (tag_hi & 0xff)
    return bytes([op & 0xff, tag_hi & 0xff, B & 0xff, (B >> 8) & 0xff,
                  value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff,
                  (value >> 24) & 0xff, X & 0xff, pad & 0xff])

def section(stage, cksum=0, H=0, instrs=None, slots=None, order=None):
    """instrs: list of 10-byte slots to use, in order.
    Emit: FS stage N cksum_lo cksum_hi H 0, then N u16 offsets, then slots."""
    n = len(instrs)
    hdr = b'FS' + bytes([stage, n, cksum & 0xff, (cksum >> 8) & 0xff, H, 0])
    # offsets: target = sec+8 + 2n + 10*k  => off = 2n + 10k
    offs = b''.join(struct.pack('<H', 2 * n + 10 * k) for k in range(n))
    body = b''.join(instrs)
    return hdr + offs + body

def build(sections):
    return b'FJ\n\x00' + b''.join(sections)

def run(passbytes, route='route.bin', gate=None, verbose=True):
    with open('/tmp/pass.bin', 'wb') as f:
        f.write(passbytes)
    args = ['./ferry-inspect', route, passbytes.hex()]
    if gate is not None:
        args.append(gate)
    p = subprocess.run(args, capture_output=True, text=True)
    if verbose:
        print(f'len={len(passbytes)} -> rc={p.returncode} out={p.stdout.strip()!r} err={p.stderr.strip()[:200]!r}')
    return p

if __name__ == '__main__':
    # experiment 1: single stage, one instruction opcode 13
    s = section(1, cksum=0, H=0, instrs=[slot(13, value=0)])
    run(build([s]))
