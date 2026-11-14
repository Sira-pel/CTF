# ropfu (picoCTF 2022, Binary Exploitation / Hard)

**Target:** `nc xebec.cylabacademy.net 10355`
**Flag:** `academy{5n47ch_7h3_5h311_f34ae07d}`

## Summary

32-bit, statically linked, non-PIE ELF. `vuln()` reads into a 16-byte stack
buffer with `gets()` — classic unbounded overflow, no real canary enforced
(checksec reports one present in the static libc, but `vuln()` never checks
it). Goal: get a shell via ROP since the binary ships no `/bin/sh` string and
no `system`/`execve` symbols (fully static, stripped-ish of libc helpers for
this).

## Approach: ret2syscall

1. **Offset to return address:** 28 bytes (`buf[16]` + 8 bytes padding +
   4-byte saved `ebp`), confirmed with a cyclic pattern + core dump
   (`cyclic_find(core.eip)` → 28).
2. Since there's no `/bin/sh` string or `system()` in the binary, write
   `"/bin/sh\x00"` into a fixed writable `.bss` address by looping back
   into the binary's own internal `gets()` (`_IO_gets` @ `0x0804cb70`) a
   second time.
3. Build registers for a raw `execve("/bin/sh", NULL, NULL)` syscall and
   trigger `int 0x80`.

Gadgets used (all static libc, no ASLR/PIE issues since binary is non-PIE):
- `pop ecx ; ret` — `0x08049a31`
- `mov eax, ecx ; ret` — `0x08099b90`
- `pop edx ; pop ebx ; pop esi ; ret` — `0x0805848e`
- `int 0x80` — `0x08049f12`
- `_IO_gets` — `0x0804cb70`
- scratch `.bss` address — `0x080e5500`

## Two gotchas that cost the most time

1. **cdecl stack imbalance in ROP:** `gets()` takes one argument via the
   stack (cdecl). In a hand-rolled ROP "call", the callee's `ret` only pops
   the *return address*, never the argument — so after `gets()` returns,
   the argument word is still sitting on the stack, unconsumed. The very
   next gadget in the chain unexpectedly consumes it first. Fix: land on a
   throwaway `pop reg; ret` right after the fake call to re-sync the stack
   before the "real" gadgets run.
2. **`gets()` truncates on any `0x0a` byte, including inside addresses.**
   The obvious `pop eax ; ret` gadget lived at `0x080ab50d` — the 3rd byte
   of that little-endian address is `0x0a`, so `gets()` stopped reading
   right there and corrupted the rest of the chain. Had to pick registers/
   gadgets whose encoded addresses contain no `0x0a` byte in any position
   (used `mov eax, ecx ; ret` instead of popping `eax` directly).

## Files

- [`ctf_practice/ropfu/vuln`](../../ctf_practice/ropfu/vuln) — challenge binary
- [`ctf_practice/ropfu/vuln.c`](../../ctf_practice/ropfu/vuln.c) — provided source
- [`ctf_practice/ropfu/solve.py`](../../ctf_practice/ropfu/solve.py) — working pwntools exploit (local + remote)

## Tools

pwntools, ROPgadget, gdb (pwndbg) for verifying stack layout/registers at
the crash point.
