# bizfuz (picoCTF 2021, madStacks) — IN PROGRESS, not solved yet

**Target:** `nc xebec.cylabacademy.net 11712`
**Binary:** [`ctf_practice/bizfuz/vuln`](../../ctf_practice/bizfuz/vuln) — 32-bit, dynamically linked, stripped, NX enabled, no canary, no PIE, Partial RELRO.

## What the binary actually is

Despite looking like a pwn challenge, `main` is NOT a loop — it's ~100 statically
unrolled "print FizzBuzz for i" calls. But each call doesn't just print: it
drops into **a huge obfuscated maze of ~740 generated functions**, each shaped
like:

```c
score = run_quiz();              // calls fcn.08049261 (always identical)
if (score == SOME_CONST) {
    goto shared_success_label;   // -> leave; ret  (clean return)
} else {
    call some_other_giant_function();  // unconditional "noise" subtree
    // ... repeat with next SOME_CONST ...
}
```

`fcn.08049261` (`0x08049261`) is the **real interactive FizzBuzz quiz**:
prints `"%zu? "` for i=1,2,3,..., reads your answer with `scanf("%9s", buf)`
(buf is `ebp-0x19`, 25 bytes — this one is safe), compares against
`"fizz"`/`"buzz"`/`"fizzbuzz"` (mod 15/3/5, verified via the binary's actual
string bytes) or the literal number (via `strtol`), and **returns the count of
consecutive correct answers once you get one wrong**. That returned score is
what every maze node's `cmp`/`je` tests.

Answering wrong immediately (score=1) is a trap: none of the maze node
constants we found are `1`, so you always fall into the "else" noise-subtree
call, which itself is another maze node — this cascades for hundreds of
thousands of calls deep until the process exhausts its stack and segfaults
(confirmed via gdb backtrace: 500k+ frames cycling between 3 addresses).
This is almost certainly what hint 4 ("binary instrumentation... keep you
from running in circles") refers to.

## The actual vulnerability (found and confirmed)

Diffed **all 19,757** `fgets()` call sites in the binary (buffer offset from
`ebp` vs. requested read size) with a small Python/objdump-based script.
Exactly one is anomalous:

- Function starting at `0x0808ba1f`, vulnerable call at **`0x0808ba5c`**:
  `fgets(ebp-0x63, 0x15c, stdin)` — reads **348 bytes** into a buffer only
  **99 bytes** from `ebp` → **249-byte stack overflow**, easily enough to
  control saved `ebx`/`ebp`/return address and place a ROP chain (NX is on,
  so shellcode won't run — need ROP/ret2libc; dynamically linked, so libc
  gadgets/`system` are available but libc is likely ASLR'd — would need a
  leak, e.g. via `puts(strtol@got)` then compute offset, or check if ASLR is
  actually disabled in this environment).

- Triggered only when, on entry to `0x0808ba1f`, the local quiz (fresh,
  starts at i=1) returns **score == 1** (i.e. answer wrong on the very first
  prompt inside that function specifically).

## Path from `main` to the vulnerable function (confirmed via static call-graph BFS)

Built a caller-graph BFS over the whole disassembly (script:
`find_scanf.py`/`chain2.py` style). Shortest path, 5 hops:

```
main (0x0814cde2)
  -> call 0x813d5dc   @ 0x814d0f1   (37th non-puts call in main)
       -> call 0x8144ba9 @ 0x813d6da   (after 2 quiz checks: need score != 0xe, != 0xd)
            -> call 0x8131f64 @ 0x8144bea  (after 2 quiz checks: score != 0x11, != 0x5)
                 -> call 0x810aab4 @ 0x81321dc (after 3 quiz checks: score != 0x7, != 0x7, != 0x2)
                      -> call 0x0808ba1f @ 0x810ab46   ** needs score == 5 ** on 0x810aab4's own quiz
                           -> vulnerable fgets @ 0x0808ba5c  ** needs score == 1 ** on this function's own quiz
```

Each of `0x813d5dc` / `0x8144ba9` / `0x8131f64` also has "noise" calls to
other giant maze subtrees interleaved between their checks (e.g.
`0x813d6bf -> call 0x8133e1a`) — these execute unconditionally whenever a
check fails and are themselves deep mazes; this is why "just answer wrong
every time" blows the stack before ever reaching our 5-hop path for real.

**Also important:** our target call (`0x814d0f1`) is the ~37th call in
`main`, meaning ~18 earlier FizzBuzz numbers' own maze subtrees must all
*return* (not crash) before main even reaches it — and naively failing
immediately on any of them also recurses forever (tested: constant
"fail at item N" for N=1..8 all segfault from stack exhaustion within
~500k calls / 2 seconds, regardless of N).

## Planned approach (not yet working)

Rather than solving the maze "honestly" (infeasible by hand — would need to
know the right target constant to match at every single node to get a clean
early return), use **GDB scripting to patch control flow directly**:

1. Skip (via `$pc += 5`, i.e. treat as no-op) all of main's ~35 earlier
   "number handler" calls before `0x814d0f1`, and the 4 known "noise subtree"
   calls inside our 5 target functions — we don't need their side effects.
2. Breakpoint on `fcn.08049261` (`0x08049261`) itself (hit from *any*
   caller, but since noise is skipped, only our 9 wanted invocations should
   remain): force `$eax` to a scripted value and jump straight to the return
   address, completely skipping the interactive quiz body. Score sequence
   needed: `[0,0, 0,0, 0,0,0, 5, 1]` (zeros are "any non-matching value" for
   the 7 fall-through checks, then 5 and 1 for the two that must match).
3. Once all 9 are handled, the vulnerable `fgets` call executes for real —
   send the actual ROP payload there.

## Review (2026-11-08) — approach check

- **Confirmed:** `0x808ba5c` is `fgets(ebp-0x63, 0x15c, stdin)` (348 into 99 bytes); the `0x3e` call at `0x808ba7c` is safe. Quiz at `0x8049261` is FizzBuzz, `ebp-0xc` starts at 1, and the return value is the 1-based index of the first wrong answer.
- **Not confirmed:** the 5-hop chain. Under the GDB skip script, the 9 forced returns are applied, but the run segfaults before `0x808ba5c` is ever hit (`scripts/skip_maze.py` with a VulnBP at `0x808ba5c` never fires).
- **Script bugs:** `skip_maze.py` is run via `gdb -ex 'run < in' -x skip_maze.py`, so breakpoints are installed after the program has already finished. Use `starti < in` first. Also, after the 9 forced calls, `QuizBP` keeps firing (calls #10+) because it never disables itself. `chain2.py` still points at a `/tmp/...scratchpad/vuln_disasm.txt` path that no longer exists.
- **Remote validity:** forcing registers in GDB cannot be done on the remote. A real payload has to be real stdin. Any valid plan has to fit that: each quiz call with score `s` consumes exactly `s-1` correct FizzBuzz answers and then one wrong answer, so the whole input stream is determined by the sequence of scores. Skipping calls changes the stream, so the skip plan does not transfer.
- **Next:** find a score sequence for every quiz call (not just 9) that reaches `0x808ba5c` without recursing forever, then generate the matching stdin. The remote instance has expired, so the flag cannot be fetched until a fresh one is available.

Wrote this as `skip_maze.py` (a GDB Python script) + a driver. Hit a plumbing
snag getting GDB to own the process's stdin via a named pipe cleanly
(`pwntools gdb.debug(..., api=True)` needs `gdbserver`, which isn't
installed; manual FIFO + `gdb --args` ran into ordering/blocking issues) —
this is the next thing to fix, not a problem with the exploit logic itself.

## Next steps

1. Fix the GDB/FIFO plumbing (or switch to `gdb.debug()` without `api=True`,
   or drive it with `python3-gdb` directly spawning the inferior, or use
   `pwntools process()` + `ptrace_scope` workaround) so the script in
   `skip_maze.py` actually runs against a live process with controllable
   stdin.
2. Once the vulnerable `fgets` is reached reliably, build the actual
   ROP chain (need a libc leak first — check `getconf` / whether ASLR is
   disabled locally; if so, can hardcode a `system("/bin/sh")` style chain
   for local testing and then re-leak for the remote instance).
3. Re-verify the whole flow against the real remote instance once ready
   (**instance was reported expired by the user — need a fresh one before
   final testing**).

## Files

- [`ctf_practice/bizfuz/vuln`](../../ctf_practice/bizfuz/vuln) — challenge binary
- [`ctf_practice/bizfuz/scripts/find_fgets.py`](../../ctf_practice/bizfuz/scripts/find_fgets.py)
  — parses an objdump disassembly dump, finds the overflowing `fgets` call
  (needs `objdump -d -M intel vuln > scripts/vuln_disasm.txt` first — not
  checked in, it's 19MB; regenerate it before rerunning these scripts)
- [`ctf_practice/bizfuz/scripts/chain2.py`](../../ctf_practice/bizfuz/scripts/chain2.py)
  — static call-graph BFS from `main` to the vulnerable function (same
  `vuln_disasm.txt` dependency)
- [`ctf_practice/bizfuz/scripts/skip_maze.py`](../../ctf_practice/bizfuz/scripts/skip_maze.py)
  — GDB Python script with the maze-bypass breakpoints described above
  (addresses are hardcoded from this specific binary's disassembly)
