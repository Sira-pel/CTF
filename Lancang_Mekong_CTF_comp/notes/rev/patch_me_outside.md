# Patch Me Outside

REV. Local validator is `Lancang_Mekong_CTF_comp/unsolved/rev_patch_me_outside/ex/mekong-fix`. Desk is `nc 47.131.225.172 32116`.

The shop string `FLAG{the_river_keeps_no_receipts}` is a decoy (the binary says the cash box is not in there).

## BREAKTHROUGH (session 2, Nov 11 ~15:45-16:00): desk config is per-connection, oracle decodes it

**The desk's engine config (profile AND/OR zone) changes per connection.** Evidence:
- `PROBE 41*96` gave `FP 14` on conn A (15:44), `FP 1e` on conn B (15:47), `14 14 26 34 1d 28` on six conns ~12 s apart (15:51-52).
- Same order, different FP across connections => config differs. Two adjacent conns both gave 14 (collision or short stability window).
- The 12 ASSIGN constraint lines are IDENTICAL across all connections observed (`/tmp/target12.txt` is NOT stale). Constraints are static; only the engine config rotates.

**Desk oracle semantics (decoded from binary disassembly):**
- `PROBE <hex>` -> `FP <x>` = final fingerprint (6 bits, `h>>26`) after running the order, exactly `vm.c`'s `fingerprint()`.
- `GAUGE <hex>` -> `GAUGE <a> <b>` with `a = (mem[0xC0] >> 12) & 0xF`, `b = mem[0xC4] & 0xF` (disassembled at 0xa25ee: `shr $0xc,%edx; and $0xf,%esi; and $0xf,%edx`). Confirmed order-dependent (`41`*96 -> `6 f`; order2 -> `c b`).
- PROBE and GAUGE share a budget of **6 per connection** (resets each connection). `SUBMIT` has 8 tries. `GAUGE` without arg = unknown command. Banner shows `patched 00/08` (meaning unknown, 8 = SUBMIT tries?).
- Desk streams an endless animation until `PLAIN` is sent; send `PLAIN` first, then read.
- Dummy `SUBMIT 41*96` -> `DENIED`.

**Per-connection observations table (order1 = `41`*96, order2 = `e389b050...c365eec` in `/tmp/probe_orders.txt`):**
| conn | FP(order1) | GAUGE(order1) | GAUGE(order2) |
|------|-----------|---------------|---------------|
| A    | 14        | 6 f           | -             |
| B    | 1e        | 6 f           | -             |
| C0   | 14        | -             | c b           |
| C1   | 14        | -             | c b           |
| C2   | 26        | -             | d c           |
| C3   | 34        | -             | e 8           |
| C4   | 1d        | -             | 9 e           |
| C5   | 28        | -             | d d           |

Note: GAUGE(order1)=(6,15) appeared on BOTH A and B despite different FPs — either coincidence or gauge nibbles are partly config-independent. Untested whether G(order1) varies.

**Sweeps done (negative results):** p 0..1023 z 0, p 0..255 z 0..63 searched for FP(41)=14 alone (many hits, ~1/64 as expected), for all-4-FP match (none), for full-value gauges (none — was wrong extraction), and with correct nibble extraction jointly vs the observation table (`work/sweep_id.c`, aborted before running — the 22-way parallel launch failed to spawn).

## What is verified

`work/vm.c` is a native reimplementation. For profile 12, zone 0, order `41`*96 it matches the binary: reg0 `0x363a96ee`, period 6, step-0 JIT bytes, fingerprint 52. A full eval is ~1.5 ms (measured 6-22 ms in practice). Sweeping all 65536 windows at one step is ~35 ms because the LCG (`0x4000` rounds) does not depend on the window and is hoisted.

An order is 48 little-endian u16 windows. Checkpoints are steps 3,7,11,...,47. Each window selects a 2–4 instruction JIT snippet; the snapshot after the step's post-processing must match the masks. OPEN is just those masks. The flag is not printed locally; the desk returns it on `SUBMIT` of a 192-hex-char order that opens the target from that same connection.

`TARGET 12` is the line count, not a confirmed `-p` value. `-p` default in the binary is `0x5ea5`, `-z` default is 0. Profile/zone range used by the desk: UNKNOWN (0..1023 x z0 and 0..255 x z0..63 ruled out for the observed FP/G combos; try 16-bit profiles next).

## Search (profile-12 line of attack — now likely obsolete, config differs)

Random orders match about half of the ~341 constrained bits. One checkpoint is ~30 bits. The window at the checkpoint alone tops out around 26/30; the three preceding windows move that ceiling.

A bit-flip hill climb on the true sweep-max, profile 12 zone 0, found a perfect checkpoint 3:
- windows `37f8 9252 d342`, checkpoint window `1fd7` (all u16, little-endian in the order)
- confirmed 30/30 by `vm.c`

The same climb usually stalls at 28/30; 29 sometimes; 30 was 1 success in ~8 runs. Continuing from that opening, checkpoint 7 reaches 29/30 and sticks. `vm.c` has a chained `solve_all` mode (seeds the p12 opening, climbs checkpoint by checkpoint) — on p12 it reached step 7 at 29/30 before being killed.

`work/emu.py` is the earlier Python emulator (fingerprint 52). `work/vm.c` is the one to extend. `work/sweep_fp.c`, `work/sweep_fp2.c`, `work/sweep_gauge.c`, `work/sweep_id.c` are config-sweep helpers (sweep_id is the joint FP+gauge identifier; fix/finish it).

## Next (recommended plan)

1. **Finish the config identifier.** Fix the parallel launch of `sweep_id` (the `&&`-chain with `for`+`&` aborted; run plainly). Widen space: p 0..65535 x z 0..63 (16-bit profile guess; ~4.2M configs, ~2 ms each, ~2.4 h single-core, ~7-10 min on 22 cores). Filter against the 8-connection observation table above. If no hits, question assumptions (maybe desk pipeline differs, e.g. patched binary — "patched 00/08", "do not touch the patches").
2. **Estimate config pool size.** Sample ~20 fresh connections, `PLAIN`+`PROBE 41*96`+`QUIT` each (1 probe). Count distinct FPs. Small pool (<=64) => precompute a full OPEN order per pool config offline, then live-identify with 2-3 probes and `SUBMIT` within seconds.
3. **Test desk idle timeout**: connect, `ASSIGN`, wait 3-5 min (keep-alive with free `HELP`/`PLAIN` lines?), then `PROBE`. If the connection survives minutes, the flow can be: connect -> probe-identify config -> solve offline with connection held open -> `SUBMIT` on same connection.
4. Only then continue the per-config checkpoint chain solve (checkpoint 3 -> 7 -> ... as before, but for the desk's actual configs). Verify with `./mekong-fix -p P -z Z -t /tmp/target12.txt order` printing OPEN before `SUBMIT`.
5. Do not brute the desk; budget is 6 probes + 8 submits per connection.
