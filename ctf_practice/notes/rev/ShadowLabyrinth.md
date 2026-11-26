# ShadowLabyrinth (HTB, rev, Hard)

**Flag:** `HTB{by_4dd1ng_nd_multiply1ng_w3_pl4y_4_l1ttl3_m3l0dy_tuturututu_n3v3r_g0nna_g1v3_y0u_up}`

Files: `shadow_labyrinth` (stripped x86-64 PIE, libcrypto + zlib) and `file.bin` (encrypted).
Solve scripts: `ctf_practice/exercises/rev/ShadowLabyrinth/solve/`.

## Stage 1: native linear check (first 48 inner chars)
- Input is 88 chars: `HTB{` + 83 + `}`. inner[0:48] is permuted by the table @0x22c0, giving buf.
- 12 groups of 4 bytes: `sum(coef[i][k]*buf[4i+k]) == tgt[i] (mod 2^64)`, with coefs @0x2140 and targets @0x20e0.
- 4 unknown bytes per equation, so meet-in-the-middle over 256²×256² gives a unique solution per group.
- Result: `by_4dd1ng_nd_multiply1ng_w3_pl4y_4_l1ttl3_m3l0dy`

## Stage 2: decrypt the VM bytecode
- file.bin is XORed with buf[32:48] (repeating), then AES-256-CBC with key=buf[0:32] and IV=.data@0x40c0, then zlib.
- The result is 127k dwords of VM code. The 16-entry handler table @0x3ce0 is filled by RELATIVE relocs, so read it with `objdump -R`.
- VM: code at M[0..], R[i]=M[0x100000+i], ip=R[0x3c], ZF byte after it.
  Ops: clr, one, addi, subi(ZF), shli, add, sub(ZF), xor, st/ld (ip-relative), jz, jnz, jmp, in (R35=next char), print, exit.
- Program: it stores the 35 chars and builds constants with shl/add. It multiplies by a char with a decrement loop (a char of 0 would loop about 2^32 times). It then computes two 35-vectors and checks `A[i] ^ B[i] == 0`.

## Stage 3: solve
- Wrote an exact Python emulator. The difference A-B is **affine** in the input (checked on random inputs).
  I probed the coefficients with base=all 1s and +e_j.
- Coefficients are small (|c|≤299). Fraction Gaussian elimination gives a unique integer solution:
  `_tuturututu_n3v3r_g0nna_g1v3_y0u_up`. z3 BV over 35 vars was far slower, so I killed it.
- Verified with the emulator: "Authentication complete!" (I did not run the real binary.)

## Lessons
- For a huge straight-line VM program, test linearity with a concrete emulator before reversing it fully.
- Don't name scratch scripts `dis.py`, because that shadows stdlib `dis` (z3 import broke). `python3 -I` hides the user-site z3.
- r2 wrapper at ~/.local/bin/r2 points to a missing tools/radare2 build, so I used objdump.
