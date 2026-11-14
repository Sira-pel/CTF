# Spillway To Heaven (challenge 027, PWN, 500 pts, author Cyrus)

**Target:** `nc 47.131.225.172 19306`
**Binary:** `Lancang_Mekong_CTF_comp/solved/pwn_spill_way_to_heaven/spillway` — x86-64 PIE, Full RELRO, canary, NX, stripped, libseccomp. sha256 `dce999b8d637b134825dc459c1cc855da8d89a1747208cd4cce9f30ec289e6bb`
**Flag:** `LMC{the_spillway_found_a_way_out}`

## Bug

Menu: `UPLOAD <off> <hex>`, `SNAPSHOT <n>`, `EMERGENCY <hex>`, `QUERY <mask> <guess>`, `QUIT`.

`SNAPSHOT` memset's 0x20 bytes to `'S'` then hex-dumps up to 0x40 bytes from that stack slot, so `SNAPSHOT 64` overreads the canary, saved rbp, and the return address into `main` (`ret = pie + 0x1c8c`).

`EMERGENCY` hex-decodes up to 0x30 bytes into a global buffer, then `memcpy`s that length onto a stack buffer at `rbp-0x20`. The canary is 0x18 bytes later, so 48 decoded bytes overwrite the canary, saved rbp, and return address.

Seccomp is default-deny and allows `read/write/open/openat/close/exit/brk/mmap/mprotect/lseek/fstat/...`. A raw `syscall` wrapper at `0x12e0` only runs after the dword at `0x5050` is nonzero. Gadgets at `0x134b`–`0x135a`: `pop rdi/rsi/rdx/rcx/rax`, `mov rsi, rax`, `leave; ret`.

## Exploit

1. `SNAPSHOT 64` leaks canary and PIE.
2. `UPLOAD 0` plants a ROP chain in the BSS upload buffer (`pie+0x4040`).
3. `EMERGENCY` restores the canary, sets saved rbp to that buffer, and returns to `leave; ret` to pivot.
4. Chain `memcpy`s a nonzero dword onto `0x5050`, then `open` / `read` / `write` through the gate. `mov rsi, rax` feeds the opened fd straight into `read`.

The service cwd holds `flag` (binary is `/srv/service`). Same contents via `./flag`.

`QUERY` is a hamming oracle over the four random shipment words at `0x5048` (budget 80). Not needed: the unlock flag is writable BSS, so the chain sets it directly.

Script: `Lancang_Mekong_CTF_comp/solved/pwn_spill_way_to_heaven/solve.py` (`python3 solve.py remote`).
