# cfl (HTB "CFI++", pwn, Hard): UNSOLVED, partial progress

- Category: pwn
- Target: HTB challenge instance (official challenge host), handout `cfl.zip` (zip password `hackthebox`)
- Files: `ctf_practice/exercises/pwn/cfl/` (`extracted/pwn_cfi/challenge/cfi`, `exploit.py`)
- Flag: not obtained

## Binary
- x86-64 PIE, full RELRO, canary, NX, not stripped. Built with clang CFI + SafeStack + a hand-rolled shadow stack (`shstk`, `shstk_stack_ptr`).
- Remote env: Ubuntu 22.04 (glibc 2.35), run via socat. Flag file is not in the handout (`flag.txt` line is commented out in the Dockerfile).
- Menu: options 1-4 print protection previews. Option 1 leaks a real-stack address and a PIE address. Option 5 runs the vuln path.

## Bug
- Option 5: `vuln()` calls `gets()` into a 0x28-byte buffer on the SafeStack unsafe stack. No length limit.
- `meme()` then does `read(0, unsafe_sp-0x30, 0x28)` (a second small write on its own unsafe frame).
- main's function-pointer calls are CFI-checked (only `boo`/`foo` allowed). Returns on the safe stack are checked against the shadow stack.

## Findings
- On the remote, the unsafe stack is mapped directly below the static TLS block, so the `gets()` overflow reaches TLS about 0x7b0 bytes past the buffer. A 256-byte overflow survives remotely but crashes locally under glibc 2.43.
- To reproduce the layout locally: download Ubuntu 22.04 `libc6_2.35-0ubuntu3`, extract `libc.so.6`, `libm.so.6`, `ld-linux-x86-64.so.2`, and run `ld-linux ... --library-path lib ./cfi` (`setarch -R` for ASLR off).
- TLS targets: canary at `fs:0x28`, `__safestack_unsafe_stack_ptr` (TLS offset 0), and `__libc_tsd_LOCALE` (libc TLS offset 0, used by `strtol` in main's menu parsing, so a fake locale is needed to keep the menu working).
- Round 1 of `exploit.py` (TLS overwrite + `meme()` read that moves `unsafe_stack_ptr` onto the real stack) works on the remote and locally under glibc 2.35.

## Open problem
- Round 2 (making `gets()` clobber its own libc return address, which has no shadow-stack check) does not give a shell. Locally under 2.35 it ends in SIGABRT; a gdb replay (different stack addresses from the real run) showed vuln's `__stack_chk_fail`, so the canary or frame values in round 2 may be wrong. Not confirmed.

## Next steps
1. Attach gdb to the live local process just before round 2 and break on `abort`, `__stack_chk_fail`, and `gets` return.
2. Check the canary/rbx/r14/r15 values vuln pops from the unsafe stack after round 1 against what round 2 expects.

## Process notes
- A safety classifier stopped the assistant twice while debugging round 2, so debugging stopped there. Feedback draft queued with `/feedback`.
