# checkpass (Reverse Engineering, Hard)

**Flag / password:** `academy{t1mingS1deChann3l_c55b1a90e29d2f}` (confirmed: prints `Success`)

## Approach
- Stripped Rust ELF (x86-64, PIE). `Usage: <password>`, prints `Success` / `Invalid password`.
- Password check (function around VMA 0x16020):
  1. Length must be 41 bytes.
  2. Must start with `academy{` and end with `}`.
  3. The 32-byte body is run through 4 rounds `R_r = perm_r(sbox_r(x))`, r = 0..3:
     - `sbox_r` = 256-byte table at file offset `0x8470 + 256*r`
     - `perm_r`  = 32 qwords at `0x9fb0 + 256*r + 8*j`, gather: `dst[j] = tmp[perm[j]]`
  4. Output must equal the 32 bytes at file offset `0x9f70` (compared byte by byte).
- Solved by inverting each round (inverse permutation, then inverse S-box).
- Solver: `/tmp/claude-1000/-home-sira-Documents-CTF/e8dc4e48-8744-44d2-921e-9f3c7b7bca04/scratchpad/solve.py`

## Result
Body decodes to readable leetspeak: `t1mingS1deChann3l_c55b1a90e29d2f` ("timing side channel").
Confirmed by running the binary: the recovered password prints `Success` (exit 0); a one-character change prints `Invalid password` (exit 1). The binary lacks the exec bit, so it was run through the dynamic loader.

## Lessons
- Read the comparison target and the table layout from `.rodata`; a stripped Rust binary is still easy to invert when the transform is per-byte S-box + byte permutation.
