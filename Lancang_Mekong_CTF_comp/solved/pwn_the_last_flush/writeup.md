---
title: "The Last Flush"
ctf: "LMC"
date: 2026-11-11
category: pwn
difficulty: medium
points: 489
flag_format: "LMC{...}"
author: ""
---

# The Last Flush

## Summary

A record archive with a higher/lower seal and a hamming-similarity probe. `COMPACT` writes one NUL past an exact-fit chunk, and `DROP` leaves a readable dangling pointer. That is enough to poison tcache into the summary `FILE` and read the already-open flag fd.

## Solution

### Step 1: Recover both secrets and the flag fd

`SEAL` compares a 64-bit value (80 guesses). `PROBE` returns how many bits match a second 64-bit value (100 guesses). `REVIEW_SUMMARY` XORs file bytes with `secret1 ^ secret2 ^ unsorted_bin` (`libc+0x1d3cc0`). The journal string `FLAG{wrong_descriptor_keep_looking}` is not the flag. The flag fd is 6 on the remote service (5 is the journal).

### Step 2: NUL byte, dangling pointer, tcache into the FILE

`DROP` frees a record but `REVIEW` still prints it. `COMPACT` of a `0x258`-byte record clears `PREV_INUSE` on the next chunk. Freeing a following `0x4f8` chunk consolidates backward over the first record. Two same-sized frees keep the tcache count alive across one pop, and the dangling `WRITE` sets the next pointer to the summary `FILE`. The next allocation builds a `FILE` whose `fileno` is the flag and whose vtable is `_IO_file_jumps` (`libc+0x1d05e0`).

```bash
python3 "Lancang_Mekong_CTF_comp/solved/pwn_the_last_flush/work/src/solve.py" --remote
```

## Flag

```
LMC{chunks_freed_and_the_seal_gave_way}
```
