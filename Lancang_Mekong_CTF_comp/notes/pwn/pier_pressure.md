# Pier Pressure (pwn, 400 pts)

**Target:** `nc 47.131.225.172 19106`
**Files:** `pier_pressure`, `libc.so.6` (Debian GLIBC 2.36-9+deb12u14), `ld-linux-x86-64.so.2`

## Protections
Full RELRO, canary, NX, PIE — all enabled. Stripped, no `puts`/`printf` imported (only `write`, `read`, `strncmp`, `strtol`, `strlen`, `memset`, `setvbuf`).

## Vulnerability
A small menu (`NOTE`, `PREVIEW`, `FILE`, `QUIT`) operates on one 40-byte (`0x28`) stack
buffer `s` inside the command-loop function.

- `NOTE <len>` and `PREVIEW <len>` correctly bound-check `len` against `0x28`/`0x48`.
- **`FILE <len>` bound-checks `len` against `0xc8` (200) but reuses the same 40-byte
  buffer** — a classic stack buffer overflow (up to 160 bytes past the buffer end,
  easily covering the canary, saved RBP, and return address).
- **`PREVIEW <len>` allows reading up to 72 bytes from a 40-byte buffer** — an
  out-of-bounds stack *read* that leaks the canary (offset 40) and the saved return
  address (offset 56), which is a PIE-relative code pointer back into `main`.

## Exploit chain
1. `PREVIEW 72` → leak canary + return address → compute PIE base
   (`base = leaked_ret - 0x16a1`).
2. First `FILE` overflow: ROP using a found `pop rdi; pop rsi; pop rdx; ret` gadget
   (incidental bytes between two functions, `base+0x12f3`) to call
   `write(1, &GOT[__libc_start_main], 8)`, then return straight back into the start
   of the vulnerable command-loop function itself (`base+0x1382`) — a "ret2self" to
   get a second shot at the bug with a fresh stack frame.
3. Trigger that return by sending `QUIT` (matches the loop's `QUIT` compare →
   canary-checked `leave; ret`).
4. Parse the leaked `__libc_start_main` address → compute libc base (offset
   `0x27280` in the supplied libc) → compute `system()` address (offset `0x4c490`).
5. Second `FILE` overflow: ROP to `system(binsh)`, where `binsh` points at the
   `"/bin/sh"` string already present inside libc (offset `0x197031`) — avoids
   needing a writable scratch buffer, since the global command buffer gets
   clobbered by whatever text triggers the final return (`QUIT`).
6. Trigger with `QUIT` again → shell spawns → `cat flag*`.

Full exploit script (tested locally against the provided libc/loader before hitting
the remote host): `/tmp/.../pier_pressure_extract/exploit.py` (pwntools).

## Flag
```
LMC{too_many_notes_for_one_pier}
```

## Better approach (2026 retro)

Clean leak+ret2libc, nothing wrong with it. Two small speedups for next time:
`one_gadget ./libc.so.6` — with the stack state after the second `FILE` overflow a single
execve gadget may remove the whole `system("/bin/sh")` stage; and `angrop`/`Ropper` to
locate the `pop rdi; pop rsi; pop rdx` gadget instead of reading inter-function bytes by hand.
