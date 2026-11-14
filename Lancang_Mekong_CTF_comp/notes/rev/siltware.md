# siltware (RE, Android APK) — fresh analysis

Previous notes discarded; this is an independent redo.

## Result
**FLAG{levee_levee_gauge_84316400}**  (recovered statically; see caveat)

The plaintext `FLAG{silt_naga_ferry_1673657d}` in `libsilt.so` .rodata is a **decoy**: no code references it.

## Steps
1. `player.zip` -> `siltware.apk` (org.mekong.siltware). Decompiled with jadx 1.5.1 (downloaded, user-approved) into scratchpad.
2. Java side: `Calibrator.run(cassette)` parses a 132-byte "SW" cassette, packs it to 64 ints, runs native `Core.a` 8x
   (with `settle()` between) producing a 32-int state. `CertActivity` -> `Certifier.print(state)` -> native `Core.b(state, byte[96])`.
   `Calibrator.<clinit>` seeds natives via `Core.c(Seeds.build(786031321))` (fills .bss tables used by `a`).
3. Native `b` (x86_64 @0x4cd0): FNV-1a (basis 0x811c9dc5, prime 0x1000193) over state[0..23];
   if hash == 0x7b223c7b then LCG (x = x*0x41c64e6d + 0x3039, take bits 16..23) keystream, seeded with that SAME constant,
   XORs the 32-byte blob at .rodata 0x630. Returns 32 on success, 0 otherwise.
   Plaintext string at 0x5d0 is never referenced.
4. Since the keystream seed is the constant (not derived from the state), the output is static. Decrypting gives the flag above.
5. Cross-checks: blob byte-identical in all 4 ABIs; arm64 has the same FNV basis, 0x7b223c7b and LCG multiplier immediates.

## Hypotheses tested (per rules)
- H1 plaintext rodata string is the real flag — refuted (unreferenced by `b`, differs from decrypted output).
- H2 `b` decrypts a blob with a constant-seeded stream, so flag is static — supported (decrypt gave valid FLAG{...}).
- H3 `Core.c` modifies the blob/keystream — refuted (c only fills .bss tables read by `a`).

## Update: levee_levee_gauge REJECTED by platform (user report). Full candidate sweep:
All `FLAG{` strings in the APK (all rejected by user):
- libsilt.so rodata (unreferenced): silt_naga_ferry_1673657d
- Core.b decrypted output (needs hash gate): levee_levee_gauge_84316400
- SettingsActivity.SERIAL (unused): weir_delta_ferry_859772b4
- ReportsActivity.FOOTER: naga_sluice_lotus_eac5982c
- WizardActivity.RECEIPT (shown on wizard "Registered"): silt_silt_silt_e32d4a83
- assets/stations.json: naga_naga_monsoon_e31adc1b
Checked: RegisterNatives maps a/b/c to 0x4900/0x4cd0/0x4df0 as assumed; arm64 `b` is logically identical to x86_64
(FNV gate 0x7b223c7b, per-byte LCG, same blob); no other crypto/file/asset code paths; PNG has no trailing data/extra chunks;
no zip comment; manifest has no extra components. Settings screen says "validating desk applies its own site profile; this
device cannot read it" -> likely a remote/offline validator not in the APK. No challenge description or host available to me.

## Caveat / not done
Did NOT construct a cassette that satisfies the FNV gate in-app (would require inverting `Core.a`'s seeded state machine).
Flag comes from static decryption of exactly what the app prints on a passing gate. Nothing was sent to the platform.

## Update (remote desk, correct approach)
Real target is the desk at nc 47.131.225.172 32006 (cmds: ASSIGN, PROBE x6, SUBMIT x8). Per connection: random profile (16-bit,
recovered uniquely from 6 FP probes using the exact model in work/solve.py) and a 20-value ORDER (slot:ch:kind=val on state after step).
Need a 64-record cassette hitting all 20 exactly -> flag. work2/: C beam search (beam.c, model verified exact vs Python),
port.py (20-way parallel heuristic portfolio), live3.py (live flow, submits only if locally 20/20).
Offline: solves hard random orders in ~2-5 min. Live attempt 1: UNSOLVED after 900s (nothing submitted). Next: longer/wider beam, retry on new connection.
