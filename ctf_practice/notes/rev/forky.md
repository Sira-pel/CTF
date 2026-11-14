# Forky (picoCTF 2019, Reverse Engineering, Hard)

## Challenge
Binary: `ctf_practice/Forky/vuln` (32-bit ELF, PIE, not stripped, dynamically linked i386).
Task: find the last integer value passed as a parameter to `doNothing()`.
Flag format: `academy{IntegerYouFound}`

## Static analysis

`objdump -d --disassemble=main vuln` / `--disassemble=doNothing vuln`

`doNothing(int x)` just stores its argument into a local variable and returns — it does nothing observable, so there's no point tracing output; the value has to be derived from the logic that computes it.

`main()`:
```c
int *shared = mmap(NULL, 4, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
*shared = 0x3b9aca00;      // 1,000,000,000

fork(); fork(); fork(); fork();   // 4 forks, no branching on return value
                                   // => 2^4 = 16 processes total reach the code below

*shared = *shared + 0x499602d2;   // 1,234,567,890 (classic magic constant)
doNothing(*shared);
```

Key trick: the buffer is `mmap`'d with `MAP_SHARED` (flags `0x21` = `MAP_ANONYMOUS|MAP_SHARED`), **not** a normal stack/heap variable. Normally a fork'd child gets a private copy-on-write copy of memory, so each of the 16 processes would only ever see its own isolated increment. Because this page is explicitly shared, all 16 processes (the original process plus every descendant from the 4 forks) increment the *same* shared 32-bit integer.

Each process performs: `v = shared_val + 0x499602D2; shared_val = v; doNothing(v)`. Whichever process is scheduled last sees the cumulative result of all 16 increments (writes to the shared int are totally ordered on x86, and since every process adds the exact same constant, order doesn't change the final sum as long as no read-modify-write race drops an update — with the OS scheduling 16 cheap forked processes this is effectively guaranteed in practice).

## Computation

```
start = 0x3b9aca00 = 1,000,000,000
inc   = 0x499602d2 = 1,234,567,890
n     = 2^4 = 16 processes

total = (start + n*inc) mod 2^32
      = (1,000,000,000 + 16*1,234,567,890) mod 2^32
      = 20,753,086,240 mod 4,294,967,296
      = 3,573,217,056            (unsigned 32-bit)
      = -721,750,240             (as signed int32, since doNothing takes `int`)
```

## Flag

```
academy{-721750240}
```

## Notes
- Couldn't dynamically verify by running the 32-bit binary in this sandbox — no i386 libc installed (`libc6:i386` not present, `dpkg --print-foreign-architectures` shows `i386` added but packages not installed). Did not install anything without asking first. Solved entirely via static disassembly/reasoning instead.
- If dynamic confirmation is wanted later: `sudo apt-get install libc6:i386 libgcc-s1:i386` (needs confirmation/sudo), then trace all forked children with GDB (`set detach-on-fork off`, `set schedule-multiple on`, `catch fork`, breakpoint on `doNothing`) and take the value of the last hit.
