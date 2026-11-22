<!-- EXAMPLE ONLY — fictional practice challenge, not a real event challenge. Fake flag. -->

# Handoff: vault_bof

## Challenge

`vault_bof` — pwn, 250 pts. Files: `vault_bof` (x86-64 ELF), `vault_bof.c`. Remote: `nc vault-bof.chal.examplectf.com 1337`. Flag format `LMC{...}`.

## Status

Stuck — ~70 min spent.

## Answer

No flag yet. No candidates.

## Key findings

- checksec: NX enabled, PIE enabled, Full RELRO, **no canary** (`checksec --file=vault_bof`).
- Stack overflow at offset **72** (`cyclic 120` → `cyclic -l 0x6161616a`); buffer is `char buf[64]` in `open_vault()` (`vault_bof.c:31`).
- `win()` exists at PIE offset `0x11a9` but calls `system("cat vault.txt")` — file not present remotely, so a plain ret2win prints nothing.
- `puts@PLT` works: leaked `puts` = `0x7f4c2a3e09d0` on run 1 (varies; ASLR on).
- Remote libc is **not** the local one: local leak low 12 bits `0x9d0`, remote `0x870` across 3 runs.

## Tried and failed

- ret2win direct jump to `win()`: got "vault empty" — ruled out as the final step (file missing remotely); may still be useful as a call target.
- ret2libc with **local** libc offsets: SIGSEGV after `puts` — ruled out: wrong libc (see low-12-bits mismatch).
- `one_gadget ./libc.so.6` local: all 4 constraints unsatisfiable locally — inconclusive remotely, retry once libc is identified.

## Current hypothesis

Remote libc is Ubuntu 22.04-ish (leak nibbles `0x870` for puts, `0x80` for `read`); plan: leak two function addresses (`puts`, `gets`), identify via libc-database/libc.rip, then two-stage ret2libc → `system("/bin/sh")` → `cat flag.txt`. Got as far as the two leaks printed.

Next command: `./libc-database/find puts 0x870 gets 0x8?0` (or libc.rip) with the two leaked nibble sets from `leak.py`.

## Open questions

- UNVERIFIED: whether `read` is called with a syscall stub or libc wrapper (affects which leak is cleanest).
- Does the remote drop a shell stdout after `system()` (no interactivity seen locally with `system` under `strace`)? UNVERIFIED remotely.

## Reproduce

- Tools: pwntools 4.15.0, gdb + pwndbg (2025-11 build), ROPgadget 7.7, one_gadget 1.4.
- Files: `ctf_practice/exercises/pwn/vault_bof/` — `vault_bof`, `vault_bof.c`, `leak.py`, `solve.py` (partial), `notes/pwn/vault_bof.md`.
- To current state (<2 min):
  ```bash
  cd ctf_practice/exercises/pwn/vault_bof
  python3 leak.py            # prints two libc leaks from the remote
  ```

## Next steps (ranked)

1. Identify remote libc from the two leaks (libc-database or libc.rip).
2. Two-stage ret2libc with correct offsets; add a `ret` for stack alignment if `movaps` faults.
3. If libc id fails, try partial-overwrite of `win()` PLT-adjacent function as fallback.

## Artifacts

- `leak.py` (working leak script), `solve.py` (stage-1 skeleton, offsets filled), `gdb.log` (crash trace of the failed local-libc attempt), `notes/pwn/vault_bof.md` (raw working note).

## Resume prompt (paste into your agent)

"Continue `vault_bof` (pwn, remote nc vault-bof.chal.examplectf.com 1337, flag format LMC{...}). First read `notes/vault_bof-handoff.md`: offset 72, no canary, Full RELRO + PIE, remote libc differs from local (puts low 12 bits 0x870). Tried-and-failed list is ruled out — don't retry unless you find a stated reason wrong. Current hypothesis: two-leak libc id → two-stage ret2libc. Start with step 1 in 'Next steps'. Rules in CLAUDE.md apply."
