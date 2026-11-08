# handoff (picoCTF 2025, Binary Exploitation, Hard)

Target: `nc xebec.cylabacademy.net 17455` (official instance; expires quickly)
Files: `ctf_practice/handoff/handoff`, `ctf_practice/handoff/handoff.c`

## Bug
Option 3 reads 32 bytes into `feedback[8]` (`rbp-0xc`). `fgets` returns that buffer in `rax`, then `leave; ret` runs. Byte 7 of the buffer is cleared. Stack is executable (`GNU_STACK` RWE). `0x401014` is `call rax`.

## Exploit
1. Add one recipient, then write `endbr64` + `execve("/bin/sh")` (no newline bytes) into `entries[0].msg` (`rbp-0x2d8`).
2. On exit, send a 5-byte `jmp` back 716 bytes to that message, 7 bytes pad, fake saved rbp, and return address `0x401014`.
3. `ret` -> `call rax` -> shellcode. Flag is `/app/flag.txt`.

Flag: `academy{p1v0ted_ftw_a428d700}`
