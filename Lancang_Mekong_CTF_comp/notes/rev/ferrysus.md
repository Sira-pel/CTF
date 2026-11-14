# ferry-inspect (REV 500, "Ferry Sus")

## Challenge
- Binary `ferry-inspect` (Rust, x86-64 PIE, stripped): `./ferry-inspect route.bin PASS_HEX [GATE_HEX]`
- `route.bin`: `"FSR2\n" + 3 NUL`, then 10 records of `u16 count` + `count*8` bytes.
- Remote: `nc 47.131.225.172 31706` — commands `GATE`, `SUBMIT <pass_hex>`, `PLAIN`, `HELP`, `QUIT`.

## Pass format (verified against the binary)
```
pass    = "FJ\n\0" section*
section = "FS" stage(1) count(1) X(u16 LE) H(1) 0(1)
          count * u16 LE offsets,   offsets[k] = 2*count + 8*k
          count * 10-byte slots
slot    = w4(u16 LE)  C(u16 LE)  p0(u32 LE)  D(1)  chk(1)
          chk = 0xa5 ^ w4lo ^ w4hi
```
As stored by the VM's parser each item is 12 bytes:
`+0 p0(u32) +4 w4(u16) +6 C(u16) +8 D(u8)` and the slot body advances 10 bytes.

## VM (checker FUN_001101b0 @ 0x101b0)
- Each section's stage number selects the route record used as the VM program
  (`FS` sections are parsed sequentially; the section's `stage` byte must equal the
  running stage counter, which starts at 1).
- 8-byte program words: `imm(u32) op(1) tag(1) C(u16)`; 25 opcodes, jump table @ 0x41e0.
- Registers: `rsp+0x1b0 + 8*idx` = {flag(u32), value(u32)}, filled by op16.
- Items array: `rsp+0x18`, count `rsp[0]`.

Key opcode semantics (all verified in gdb):
- op1: `item0.p0 & 0xff == section H`
- op2: `count` must lie in `[tag, C]` (stage 1 uses tag=8,C=8; stage 2 uses 7..8)
- op3: stable insertion sort of items, key = `((s16(w4)*s16(imm.lo)) & 0xffff) ^ imm.hi`
- op5: merges *adjacent* equal w4: `C = sat_add(C1,C2)`, `p0 = p0_1 ^ p0_2`
- op6: expected merge count in `[imm.lo, imm.hi]`
- op7: first w4 == imm.lo and last w4 == imm.hi
- op8: saturating u16 sum of all C compared to section X (tag selects 0 vs 1 mode)
- op9: acc = imm
- op10: fold over items. With `tag == 0xff` the mode is dynamic `(acc>>8)&3`.
  Per step `cl = ((w4&7) + (1+5i) + neg31((w4&7)+5i)) & 31` where `neg31` is the
  binary's magic-division `q - 32q`. Modes:
  - 0 `acc = rol(acc^p0, cl) * mul + C`
  - 1 `t = ((acc^p0)>>15 ^ (acc^p0)) * mul; acc = ((t>>13) ^ t) + C`
  - 2 `acc = rol((acc^p0)*mul, cl) ^ (C*0x1000193)`
  - 3 `acc = rol(((w4|(C<<16)) ^ (acc^p0)), cl) * mul`
  - after each step, if the item's D nibble mode applies: D must equal `acc&0xf`
    (nibble selector == 2) or `acc>>28` (nibble selector == 1)
  - if i < 0xff and register i is set, `acc` must equal it
- op11: `acc = rol(acc,tag) ^ rol(acc,C) ^ acc`
- op12: `acc == imm`
- op13: `key = (fold13(imm) ^ acc) * 0x9e3779b1`, where
  `fold13: e ^= p0; e = rol(e*0x1000193, 5); e ^= C` per item in fold order
- op16: stores {1, imm} into register `tag`

Stage N's key seeds the next record: `record_{N} ^= xorshift32(key ^ 0x46455252)`.

## Stage 1 (SOLVED, verified end-to-end in gdb)
Record 0 is used as-is (seed 1). The 8 items:
```
i  w4     C      p0         D
0  0x143b 0x03ab 0xec8e7dca 3
1  0x2324 0x0221 0xfd1971fd 9
2  0xdfe8 0x02d7 0x44c32aa2 14
3  0xc49b 0x0052 0x76875986 11
4  0x1d01 0x00f3 0x39be7ab0 4
5  0xaad9 0x009a 0x6a0be226 3
6  0x4dba 0x0334 0xaddb0fae 8
7  0x8052 0x03c2 0x18257888 14
```
X = 0x1178, H = 0x7c, stage = 1. Stage key = **0xbd05ddf1**.
(`python3 chain2.py` produces the pass; gdb shows "stage done".)

## Stage 2 (in progress)
Program = record 1 decrypted with seed `0xbd05ddf1 ^ 0x46455252 = 0xfb408fa3`.
Ops: 1,2,3,5,6,7,15*6,8,9,16*5,10,11,12,13.
- op2 forces 7..8 items but there are only 6 distinct w4 → one item must be duplicated
  so op5 merges it back to 6.
- op3 key 12193, mask 0x4a9b → keys 0x3c79,0x4877,0x5a1e,0x60f9,0x7660,0xf7db,
  i.e. the natural order is already correct (duplicate of item 0 sorts adjacent).
- op8 wants X = full C sum = 0xae0.
- op11 (tag 9, C 3) must be applied to the op9 seed **before** op10:
  seed = `rol(0xa58c0431,9) ^ rol(0xa58c0431,3) ^ 0xa58c0431 = 0x91e446f7`.
- Solved p0 with that seed: `0x859f02eb, 0x52397abc, 0xbe535c7a, 0xbcd9f554,
  0x9e473a56, 0x6adfe9f7`; D nibbles 3,6,3,0,3,13.
- Remaining blocker: at op10 i=0 the binary expects the accumulator to become
  0x39303670 but computes 0x21320e63. Back-solving that step needs p0 = 0xec097533,
  while the merged array really contains 0x859f02eb. So one more detail of the fold
  (mode/rotate for the first step, or which item op10 starts from) is still unmodelled.

## Better approach (2026 retro)

This cost ~126 incremental scripts to pin opcode semantics by hand. Two changes make it an
afternoon next time:
1. **Emulate instead of re-implement.** Run `ferry-inspect` under `unicorn`/`qiling` and
   watch register/memory effects per opcode on crafted bytecode. That gives a byte-exact
   oracle immediately — the thing the 126 scripts were slowly reconstructing — including the
   op10 fold modes and D-nibble selectors, without gdb-scripting the live binary repeatedly.
2. **Symbolic-solve each stage.** Once the per-stage checker is isolated, let angr/z3 solve
   for `p0`/`D`/`w4` against the accept condition instead of hand back-solving (the op10 i=0
   mismatch that blocked the raw note is exactly the kind of thing z3 resolves in one shot).
The genuinely crypto stages (op24 Pohlig–Hellman, op25 factoring) were handled right — keep
those. See `ctf-reverse/SKILL.md` → "emulation" and "symbolic execution".
