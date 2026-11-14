# Dock Block (REV, 500) — SOLVED

**Flag:** `LMC{the_quay_released_cargo_at_last}`

## Setup
- `player.zip` → `dockctl` (stripped, garble-obfuscated static Go ELF) + `ledger.bin` (46 B).
- Remote: `nc 47.131.225.172 31806` — a "dock desk" shell. Commands: `ASSIGN`, `PROBE <t1;t2;..>` (6/conn), `SUBMIT <t1;t2;..>` (8 tries), `PLAIN`, `HELP`, `QUIT`.
- `ASSIGN` gives a per-connection work order: `ORDER k:t-t,...` (exact departure tick per cargo), `GATE 9e???` (5 hex digits, low 12 bits hidden), `PROBES 6`.
- `PROBE` returns only `DEP <tick or -> x8` (departure tick per cargo). `SUBMIT` returns the flag if the transcript SEALs.

## How dockctl works (reversed)
`dockctl LEDGER GATE_HEX [ORDER]`, transcript on stdin, prints `VERDICT OPEN|SEALED` on `END`.
- Ledger: `DK 01 n | caps(4,3,4) | 6,30 | seed(4B) | n x (type a, size b, arrival c, dep d)`.
  Cargo status: 0 absent, 1 pending (at tick c), 2 held, 3 berthed, 4 departed.
- Commands (≤4 queued per tick, executed on the NEXT tick, sorted by (type desc, (5*i+p58)&7)):
  `HOLD cN slot` (status1→2, slot cap 4/3/4 by size, fallback slot (p60+arg)%3, hold expires after p50 ticks),
  `BERTH cN slot` (2→3, slot must match), `INSP cN`, `DEPART cN` (needs status 3, inspected, dependency departed), `DROP cN`.
  `T n` (1..8) advances ticks, max 30.
- Inspector: one cargo at a time, higher type first, duration `((p68 + type) % 3) + 1`.
- Params p48..p68 come from gate+seed; **re-rolled at tick 7** from an FNV hash of all events so far.
- `END` → SEALED iff every ORDER cargo is status 4 with departure tick inside its window.
- Anti-debug gotcha: if a tracer is attached, gate is XORed with `0x5bd1e995` (affects gdb-derived tables).

## Solve
1. Built a Python simulator of the rules (validated 0 mismatches vs the binary on eviction-free runs).
2. Used 3 `PROBE`s (short eviction-free transcripts chosen to split the 4096 candidate gates) → 5 gates left
   (`9e2bd, 9e558, 9e7a2, 9e7fb, 9ecb0`).
3. Searched for one transcript that SEALs all 5 gates, verified with the real untraced binary, `SUBMIT`ted it → flag.

Submitted transcript (this connection's ORDER `0:10,1:7,2:9,3:10,4:15,6:13,7:5`):
`T 2;HOLD c7 2;INSP c7;T 1;BERTH c7 2;T 1;HOLD c1 0;INSP c1;DEPART c7;T 1;INSP c0;BERTH c1 0;HOLD c2 2;T 1;HOLD c0 0;DEPART c1;BERTH c2 2;INSP c2;T 1;BERTH c0 0;HOLD c3 2;INSP c3;T 1;DEPART c2;BERTH c3 2;T 1;DEPART c0;DEPART c3;HOLD c4 1;INSP c6;T 1;BERTH c4 1;T 1;HOLD c6 2;T 1;INSP c4;BERTH c6 2;DEPART c6;T 2;DEPART c4;T 1;END`

## Notes / lessons
- The work order is per connection and the session must stay open between ASSIGN and SUBMIT (used a detached Python socket holder).
- A 91-token/773-char probe was rejected as "invalid probe"; 38–44 tokens (~350 chars) were accepted.
- Used 3 of 6 probes and 1 of 8 submits; no brute force against the server.

## Better approach (2026 retro)

This was a garble-obfuscated static Go ELF reversed cold into a simulator. Run symbol-recovery
*first* next time: **GoReSym** (`GoReSym -t -d -p ./dockctl` + its IDA script), **redress**, or
**unstrip**. Go keeps `pclntab` even when stripped/garbled, so these recover function boundaries,
types and many strings — which would have shortened building the rule simulator. The 3-probe
candidate-gate narrowing and the untraced-binary verification (dodging the tracer-XOR anti-debug)
were both good; keep them. See `ctf-reverse/SKILL.md` → "Stripped / garble-obfuscated Go".
