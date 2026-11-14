# MATRIX (picoMini by redpwn, Reverse Engineering, Hard)

**Flag:** `picoCTF{y0uv3_3sc4p3d_th3_m4ze...f0r_n0w-hYkq2D9PmrA5GpEq}`

## Challenge
- `matrix` is a stripped x86-64 PIE binary. `nc mars.cylabacademy.net 31259`.
- Running it just prints a "Welcome to the M A T R I X" / "Can you make it out alive?" banner, reads some input, and prints "You were eaten by a grue." — classic Zork reference.

## Solution
1. `main` mallocs two 0x800 buffers and builds a small context struct, then calls `fcn.1350` in a loop until it returns 0. That function executes **exactly one bytecode instruction per call** — it's a custom stack-based VM/bytecode interpreter, and the real "game" is the bytecode blob at `.rodata+0x20f0` (len 0x5d2), not the x86 code.
2. Context struct: `+0x00` code ptr, `+0x08` pc (u16), `+0x10` stack1 ptr, `+0x18` aux-stack ptr, `+0x20` getc wrapper, `+0x28` putc wrapper.
3. Reversed the jump table at `0x201c` (53 entries) to get the opcode set:
   - `0x00` NOP, `0x01` HALT (pop word = exit code; main prints `flag.txt` iff exit code == 0)
   - `0x10` DUP, `0x11` DROP, `0x12` ADD, `0x13` SUB(B-A), `0x14` SWAP
   - `0x20` TO_AUX, `0x21` FROM_AUX (move top between the two stacks)
   - `0x30` JMP (pop target), `0x31` JZ, `0x32` JNZ, `0x33` JLT, `0x34` JLE (pop target, pop cond)
   - `0x80` PUSHB imm8 (sign-extended), `0x81` PUSHW imm16 (LE)
   - `0xc0` INPUT (getc, push as word), `0xc1` OUTPUT (pop, putc)
   - everything else = invalid opcode → HALT with failure flag
   - Strings are stored as reversed bytes + a 0 sentinel, printed by a shared loop at `0x13b`, with the "return address" pushed *before* the string and popped via JMP after the sentinel — a cheap call/return convention using the data stack itself as a call stack.
4. The game keeps three state words under the input: `X, Y, C` (`C` = a light/lamp counter, starts at 0). `u/d/l/r` keys decrement/increment Y or X; any other character is instant death. New position `idx = Y*16 + X` indexes a **256-entry jump table at `0x174`** (one 16x16 grid, 4 bytes/entry: `PUSHW target; JMP`, or a bare `JMP;NOP;NOP;NOP` for "safe, just continue").
5. Extracted the whole table from the binary and classified each cell (script-built, not played interactively):
   - default target `0xfb` → DEATH (wall)
   - bare JMP → SAFE
   - target `0x574` → LIGHT-1 (dies if C==0, else C-=1)
   - target `0x57f` → LIGHT+1 (C+=1)
   - target `0x585` → WIN (prints "Congratulations, you made it!" then HALTs with exit code 0)
   - Rendered as a 16x16 ASCII maze; start is (1,1), light pickups at (6,1),(10,1),(6,5), light drains at (4,2),(13,4),(7,11),(13,13),(10,14), win at (14,15).
6. Wrote a from-scratch Python emulator for the bytecode (validated byte-for-byte against the real binary's stdout for arbitrary input), then solved the maze as a graph search over `(x, y, light)` respecting the light constraint (can't step on a drain cell with light==0).
7. Solution path (63 moves, one move = one raw stdin byte, **no newlines in between** — the VM reads literally every byte including `\n` as a move attempt):
   `rrrrrlrlrlrlrllddddddlddrrddrrrdrddrruuuruuuuuuurrddddddddlddrd`
8. Sent that raw byte string to `nc mars.cylabacademy.net 31259` → "Congratulations, you made it!" / "Have a flag!" / flag.

## Lessons
- When `main`'s only job is a tight "call interpreter-step in a loop" pattern, stop reversing the x86 and dump+reverse the embedded bytecode instead — it's the real program.
- Jump-table opcode numbers must be read from the actual computed jump table (`base + op*4` dereferenced), not guessed from code order — got bitten once by assuming adjacent case blocks matched sequential opcode values when they didn't.
- Validate a from-scratch emulator against real stdout before trusting it for search/exploration.
- Character-mode I/O: don't append `\n` after each simulated keypress if the VM consumes every raw byte as input; stdio buffering on the real server still delivers them one at a time to `getc`.
- This was the official remote instance named in the challenge (`nc mars.cylabacademy.net 31259`), so connecting to it with the solved input was in scope, not a separate target.
