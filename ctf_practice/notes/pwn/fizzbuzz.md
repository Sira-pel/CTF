# FizzBuzz (picoCTF 2021, madStacks) — IN PROGRESS

Service: `nc xebec.cylabacademy.net 11712`
Binary: `ctf_practice/vuln (1)` — ELF 32-bit i386, dynamically linked, stripped.
Desc: "FizzBuzz was too easy... there's a buffer overflow." Hints point at objdump, binary instrumentation, angr.

## What it is
A giant (~1 MB .text, ~348k lines of objdump) generated **FizzBuzz state machine**.

- Imports: setbuf, strcmp, strncmp, strnlen, scanf, fgets, fopen, strtol, printf, puts, exit.
- rodata strings: `flag.txt`, `%zu? ` (prompt), `%9s` (scanf fmt), `fizzbuzz`, `fizz`, `buzz` — **answers are lowercase**.

### Checker function @ 0x8049261 (arg = n)
Loops counter i = 1..n-1, prints `i? `, reads `%9s`, strips trailing `\n`, then:
- i%15==0 → must equal `fizzbuzz`
- i%3==0  → must equal `fizz`
- i%5==0  → must equal `buzz`
- else    → strtol(buf) must == i
On first wrong answer it **returns i** (the failing round). If all pass it **returns n**.
=> To force the checker to return value k (k<n): answer rounds 1..k-1 correctly, answer round k WRONG. (k==n: answer everything correctly.)

### Node functions
Each node: `call checker(n)`; then `cmpl $k,-0xc(%ebp)` dispatch. For each possible return value k, the branch either:
- does a harmless `fgets` (small size) and returns, or
- `call <child node>` / `je <far block that calls child>` → descends deeper.
Nodes form a large **DAG with shared children** (backward walk explodes — this is the "running in circles" the hints warn about; intended tools = binary instrumentation / angr).

### Root = main @ 0x814cdd8 (main is `jmp` from 0x804911d)
main calls a flat sequence of level-1 node functions (811e15f, 811e4ed, 811f67e, ...) interleaved with `puts("fizz"/"buzz"/"fizzbuzz")` (prints a fizzbuzz board).

## The bug (ret2win)
- Win function @ **0x8049206**: `fopen("flag.txt")` → `fgets` → `puts` → `exit`. It is **never called/referenced anywhere** (addr 0x08049206 appears 0 times as call target or immediate) → only reachable by overwriting a saved return address.
- **Exactly one overflowing fgets** in the whole binary:
  - Node function **@ 0x808ba1f**, checker n=20. When its checker returns **1** (fail round 1):
    `fgets(buf = ebp-0x63, size = 0x15c = 348, stdin)` — buffer is 99 bytes to ebp. 348 >> 99+4 → overwrites saved ret.
  - Overflow offset: 0x63 (99) + 4 (saved ebp) = **103 bytes padding**, then 4-byte ret = `0x08049206` (little-endian `\x06\x92\x04\x08`).
- One static caller of 0x808ba1f: 0x810ab46 in node 0x810aab4 (n=46), guarded by `cmpl $5; jne` → reached when parent returns **5**.

## Plan / TODO (where I stopped)
1. Build forward successor graph: for each node F and each ret value k → child node (or terminal fgets). Script started: `analyze.py` in scratchpad (backward walk explodes due to shared nodes — switch to FORWARD BFS).
2. From main's ordered list of entry nodes, find the earliest entry Ei that reaches 0x808ba1f; record the descent ret-sequence Ei → ... → 0x810aab4(ret5) → 0x808ba1f(ret1).
3. For entry nodes before Ei: answer their checker ALL CORRECT (ret==n) so they return cleanly to main without consuming extra input.
4. Build interactive solver (reads `N? ` prompts, counter resets to 1 mark node boundaries) that walks the descent, then at 0x808ba1f fails round 1 and the 348-byte fgets receives: 103 bytes padding + `\x06\x92\x04\x08`.
5. Verify locally with a dummy `flag.txt`, then point solver at `xebec.cylabacademy.net:11712` for the real flag.

## Notes
- angr NOT installed; pwntools IS installed. Local run confirmed lowercase fizzbuzz answers advance through nested rounds (counter resets to 1 per new node).
- Scratchpad: /tmp/claude-1000/-home-sira--claude-spares-spare-dO4rjt/975d0a79-c21d-4e72-b66f-74b12cb10596/scratchpad/fizz  (vuln copy, dis.txt, analyze.py, solve2.py)
