# The Last Flush

Pwn. `nc 47.131.225.172 19706`. Files: `last_flush`, `libc.so.6` (Debian 2.36), `ld-linux-x86-64.so.2`.

Protections: Full RELRO, canary, NX, PIE. 32 records, sizes `0x258..0x1000`.

## Bugs

- `SEAL <hex16>` is a higher/lower oracle for an 8-byte secret (budget 80). `PROBE <hex16>` returns the hamming similarity against a second secret (budget 100).
- `DROP` frees a record but keeps the pointer and only sets a dropped flag. `REVIEW` does not check that flag, so a freed chunk is still readable.
- `COMPACT` copies the record onto a `0x1010`-byte stack buffer, frees it, allocates the same size, copies it back, then writes a NUL at `ptr+len`. A request congruent to 8 (mod 16) fills its chunk exactly, so that NUL clears `PREV_INUSE` on the next chunk.
- `REVIEW_SUMMARY` reads the summary `FILE` and XORs the bytes with `secret1 ^ secret2 ^ unsorted_bin`. The real flag is the fd from `open("/run/challenge/flag")`. The journal text `FLAG{wrong_descriptor_keep_looking}` is a decoy. `fileno` is rejected only when it matches this connection's socket.

## Exploit

1. Binary-search `SEAL`, then flip one bit at a time with `PROBE`.
2. Free a tcache record and a neighbor. The safe-linked fd recovers both heap addresses, so the summary `FILE` (the chunk immediately before the first record) is known without a heap base.
3. `STORE` a `0x258` chunk whose first qwords point at its own header and whose last qword is `prev_size = 0x260`. Next chunk is `0x4f8` (chunk size `0x500`, so the NUL only clears the in-use bit) plus a guard.
4. `COMPACT` the first chunk, then `DROP` the `0x4f8` chunk. It consolidates backward. `REVIEW` of the dangling record leaks `main_arena` unsorted (`libc+0x1d3cc0`).
5. Reallocate that chunk, free a second same-sized chunk first so the tcache count stays nonzero, then free the dangling chunk and `WRITE` its fd to the summary `FILE` (XOR `addr>>12`).
6. The next `STORE` of that size overwrites the `FILE`: vtable `_IO_file_jumps` (`libc+0x1d05e0`), fileno of the flag, buffer on the known heap chunk. `REVIEW_SUMMARY` prints the XOR'd flag.

Remote fds: journal is 5 (decoy), flag is 6. Locally, with no extra fds, the flag is 4.

Script: `Lancang_Mekong_CTF_comp/solved/pwn_the_last_flush/work/src/solve.py`

Flag: `LMC{chunks_freed_and_the_seal_gave_way}`
