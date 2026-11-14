# Pier Pressure

Pwn. `nc 47.131.225.172 19106`. Files: `pier_pressure`, `libc.so.6` (2.36), `ld-linux-x86-64.so.2`.

Protections: Full RELRO, canary, NX, PIE.

## Bug

Menu on a 0x28-byte stack note at `rbp-0x30`.

- `NOTE <len>` reads up to 0x28 bytes.
- `PREVIEW <len>` writes that many bytes from the note. Limit is 0x48, so 72 bytes leaks the canary, saved RBP, and the return address (`main+0x53` = PIE+`0x16a1`).
- `FILE <len>` reads up to 0xc8 bytes into the same 0x28-byte buffer. Canary is checked only on `QUIT`.

Gadget at PIE+`0x12ef`: `push rbp; mov rbp, rsp; pop rdi; pop rsi; pop rdx; ret`. `rdi` comes from the saved RBP slot.

## Exploit

1. `PREVIEW 72` leaks canary and PIE.
2. `FILE` overflow restores the canary and returns into `write(1, write@GOT, 8)`, then back into the menu. libc base = leak − `write`.
3. Second `FILE` overflow: the same gadget calls `write` (this `ret` also fixes `system` stack alignment), then `pop rdi; ret` (`libc+0x277e5`) loads `/bin/sh` and calls `system`.
4. `cat /run/challenge/flag`.

Flag: `LMC{too_many_notes_for_one_pier}`
