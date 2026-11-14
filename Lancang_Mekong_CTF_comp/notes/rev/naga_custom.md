# Naga Customs (REV, 489 pts) — SOLVED

**Flag:** `LMC{not_a_single_baht_unaccounted_for}`

- Target: `nc 47.131.225.172 31906`; handout `player.zip` -> `naga` (static-pie x86-64, stripped; big toolbox with OpenSSL/Lua/etc.; the `FLAG{the_naga_remembers_every_chart}` string in it is a decoy).
- Service commands (uppercase): `PLAIN` (stop animation), `ASSIGN` (12 target lines for *this connection*), `PROBE <decl>` (12-bit fingerprint, 6/conn), `SUBMIT <decl>` (8 tries). Declaration lines joined with `;`.
- `naga [-k KEY] [-t TARGET] [-l] [-f] DECL`: DECL = 72 lines `%02d %04d %03d %03d %04x` (cargo 0..11, qty, price, day, hex tag), 6 posts x 12. `-k` is a hex 16-bit key (per-connection secret on server). `-t` prints OPEN when all target snapshots match.
- Reversed `main` (0xa2380) into `model.py` (xorshift world gen from key, per-entry levy/treasury update with chained hash H, CRC16, Adler-like; snapshots after 6th sorted entry and at post end). Validated against the binary (60 random decls, all 13 regs) and `-t`.
- Key recovery: `PROBE` fingerprints of fixed decls vs. a precomputed table of all 65536 keys (`fptab.py`) -> unique key after 2 probes.
- Solve: `solver.py` builds a declaration constructively (increasing days so order is fixed; per-post: 2 adjuster entries brute-forcing T masks, filler entries solving Adler via meet-in-the-middle / CRC via scanning tag / HW / hash, then 3 adjusters for end-of-post treasuries). ~5-10 s. `client.py --submit` does the whole flow in one connection.
- Tools: python3, gdb (world-table dump to find a bug: generator makes 7 groups, not 8).

## Better approach (2026 retro)

The simulator + fingerprint-table key recovery (2 probes → unique 16-bit key) was efficient
and is the right template. One speedup for the constructive declaration search (the per-post
Adler meet-in-the-middle / CRC tag scan): angr or a z3 model of the per-entry update can
solve the adjuster masks directly instead of brute-forcing T masks. Reaching `model.py` would
also have been faster by emulating `main` under unicorn than by gdb world-table dumps.
