#!/usr/bin/env python3
"""Dump heap chunks after init and after a few stores. Local only."""
import os
from pwn import *

context.arch = "amd64"
context.log_level = "error"

WORK = "/home/sira/Documents/CTF/Lancang_Mekong_CTF_comp/solved/pwn_the_last_flush/work"
LD = f"{WORK}/ld-linux-x86-64.so.2"
BIN = f"{WORK}/chal"


def menu(p):
    p.recvuntil(b"archive> ")


def seal(p):
    lo, hi = 0, (1 << 64) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        menu(p)
        p.sendline(f"SEAL {mid:016x}".encode())
        line = p.recvline()
        if line.startswith(b"sealed"):
            return
        if line.startswith(b"higher"):
            lo = mid + 1
        else:
            hi = mid - 1
    raise SystemExit("seal fail")


def parse(heap, base):
    # main heap: first chunk often at base (no heap_info for brk heap)
    off = 0
    print(f"heap base {base:#x} size {len(heap):#x}")
    # skip if first qword looks like a prev_size 0
    n = 0
    while off + 16 <= len(heap) and n < 40:
        prev = u64(heap[off:off+8])
        sz = u64(heap[off+8:off+16])
        size = sz & ~7
        flags = sz & 7
        if size < 0x20 or size > 0x10000 or off + size > len(heap) + 0x20:
            print(f"  stop at {base+off:#x} prev={prev:#x} sz={sz:#x}")
            break
        user = base + off + 16
        data = heap[off+16:off+min(size, 48)]
        print(f"  {base+off:#x} user {user:#x} size {size:#x} flags {flags} data {data[:24].hex()}")
        if size == 0:
            break
        off += size
        n += 1


def main():
    p = process([LD, "--library-path", WORK, BIN])
    seal(p)
    maps = open(f"/proc/{p.pid}/maps").read().splitlines()
    heap_line = next(l for l in maps if "[heap]" in l)
    h0, h1 = heap_line.split()[0].split("-")
    h0, h1 = int(h0, 16), int(h1, 16)
    mem = open(f"/proc/{p.pid}/mem", "rb")
    mem.seek(h0)
    blob = mem.read(h1 - h0)
    print("=== after seal ===")
    parse(blob, h0)

    def store(n, fill):
        menu(p)
        p.sendline(f"STORE {n} {bytes([fill])*n}".encode().hex() if False else f"STORE {n} {(bytes([fill])*n).hex()}".encode())
        print(" ", p.recvline().strip())

    store(0x258, 0x41)
    store(0x4F8, 0x42)
    store(0x258, 0x43)
    mem.seek(h0)
    # heap may have grown
    maps = open(f"/proc/{p.pid}/maps").read().splitlines()
    heap_line = next(l for l in maps if "[heap]" in l)
    h0, h1 = [int(x, 16) for x in heap_line.split()[0].split("-")]
    mem.seek(h0)
    blob = mem.read(h1 - h0)
    print("=== after 3 stores ===")
    parse(blob, h0)

    # compact id 0 (0x258) and reparse the size byte of the next chunk
    menu(p)
    p.sendline(b"COMPACT 0")
    print("compact", p.recvline().strip())
    mem.seek(h0)
    maps = open(f"/proc/{p.pid}/maps").read().splitlines()
    heap_line = next(l for l in maps if "[heap]" in l)
    h0, h1 = [int(x, 16) for x in heap_line.split()[0].split("-")]
    mem.seek(h0)
    blob = mem.read(h1 - h0)
    print("=== after compact 0 ===")
    parse(blob, h0)
    p.close()


if __name__ == "__main__":
    main()
