# Treaty Of Six Gates (Crypto, 456 pts, author Cyrus) — IN PROGRESS, NOT SOLVED

Service: nc 47.131.225.172 14606 (official challenge host)

## Service behaviour
- Each TCP connection = new session (new signer keys, new session id). Keep all work within one connection.
- Budget: 560 signing requests per session.
- 7 signers on NIST P-256. Menu: `1 <gate_id>` = stamp routine doc (returns r, s, signer, msg);
  `3 <id1> <r1> <s1> <id2> <r2> <s2>` = file final memo (needs quorum 2); `q` = quit.
- Target per session = hex of `ratify_six_gates_treaty:<session>`. Need 2 valid sigs over the target from distinct signers.
- Routine msg = JSON `{doc, nonce(10 random bytes hex), session, signer, title}`; signature = ECDSA over sha256(msg) (verified offline).

## Checked so far
- r values did not repeat across 8 signatures (7 signers + repeat signer) -> no simple nonce reuse.
- Candidate k derivations tested offline against r (no match): int(nonce), sha256(nonce), sha256(msg), doc index,
  Python `random.Random(seed)` seeded with doc / nonce / sha256(msg), getrandbits(256) and randrange(1,n).

## Hypotheses (ranked)
1. Nonce bias / leakage (HNP lattice across many sigs from one signer). Likely given the 560 budget. Test cost: collect ~40-60 sigs from one signer in one session, then lattice test. Not yet run.
2. Verifier flaw in `3` filing: TESTED, no bypass found. Duplicate signer (same valid routine sig twice) -> `[rejected] malformed forged packet`. Zeros `3 0 0 0 1 0 0` -> `[rejected] invalid gate quorum`. Still open: r+n malleability, and whether a single valid sig over target can count twice.
3. Predictable k from a non-Python PRNG (MT seeded by time, LCG). Ruled out only for the simple Python-random seeds above.

## Round 2 testing (lattice + protocol probes)

### Nonce-bias (HNP) — RULED OUT
- Fixed collect.py socket-timeout bug (recv timeout was 5s regardless of intended read duration -> caused hangs).
- Validated hnp.py lattice construction against SYNTHETIC data: generated 60 sigs with a known d and k < 2^64 (strong
  bias); tool correctly recovered the exact true d. Construction confirmed correct.
- Ran same tool against 50 REAL signatures from signer 0 (North Floodgate) in one session, testing bit-bounds
  L = 64,96,128,160,180,200,220,240. No d recovered at any bound (240 bits = 94% of full 256-bit range) -> no
  detectable MSB/range-style nonce bias. With only 50 samples, HNP theory says even a ~16-bit deficit (L=240) should
  be recoverable with a handful of samples, so this is a solid negative result, not a sample-size issue.
- Checked for exact r-value collisions in the 50-sig batch: 50/50 unique -> no catastrophic nonce reuse.
- Re-tested nonce-field (JSON "nonce" string) as a literal/derived k across all 50 sigs: int(nonce), reversed bytes,
  nonce XOR h, nonce + h, sha1(nonce), sha256(nonce_hex_str), md5(nonce), doc-index -> zero hits.
- Conclusion: the "nonce" field in the signed JSON is an anti-replay nonce, unrelated to the ECDSA k. The actual
  ECDSA nonce generation for routine signing appears cryptographically sound.

### Protocol / verifier probes — RULED OUT
- Hidden command "2" between menu items 1 and 3: tested "2", "2 0 0", "help" -> all `[denied] unknown command`.
  Genuinely absent, not a hidden feature.
- gate_id boundary/type confusion: "-1", "7", "100", "abc", "0.5", "00" -> all denied except "00" (parses as 0,
  normal). No negative-index wraparound or type-confusion bug.
- Filing verifier error disambiguation:
  - Same signer id used twice (duplicate), even with a real valid routine signature -> `[rejected] malformed
    forged packet` (structural check: ids must differ, checked BEFORE signature verification).
  - Two DISTINCT signer ids, both with real but ROUTINE (non-target) signatures -> `[rejected] invalid gate
    quorum` (semantic: signature verification against target fails, as expected).
  - This confirms clean, correctly-ordered validation logic. No bypass found.

## Hypotheses (updated ranking)
1. ~~Nonce bias (HNP)~~ — RULED OUT (see above, high confidence).
2. ~~Verifier flaw in `3` filing~~ — RULED OUT (see above).
3. Weak/guessable per-session PRNG seed for signer key generation (e.g. Python `random` seeded by time or a small
   counter, not a CSRNG). Classic CTF pattern. Test: record exact connect wall-clock time + published pubkeys,
   then offline-search a bounded window of candidate seeds (e.g. +/-300s) with a few plausible derivation schemes
   (`random.Random(seed).randrange(1,n)` called per-signer) and check against published Q. This is offline
   cracking over a small bounded space (CLAUDE.md allows offline cracking). NOT YET RUN.
4. (new, lower priority) Possibly related private keys across the 7 signers within one session (e.g. d_i = d_0 + i
   or derived from one shared seed) — would be revealed by hypothesis 3's seed search if it works, or would need
   its own test otherwise.

### Weak PRNG seed hypothesis — tested, no hit (not fully ruled out)
- Grabbed one session's 7 public keys plus precise wall-clock timestamps around the connect (t_before, t_connect,
  t_after).
- Offline-searched a ±300s window around connect time (601 candidate integer seeds) against 3 plausible Python
  `random` derivation schemes: single RNG with sequential `randrange(1,n)` across all 7 signers; single RNG with
  sequential `getrandbits(256) % n`; separate `random.Random(seed+i)` per signer index. No match against any
  published public key.
- Also checked r-value uniqueness across ALL collected sessions so far (single-signer batches of 50/60/3/8 sigs,
  and one mixed-signer batch) -> always 100% unique r, including across different signers in the same session.
  No shared/reused nonce in any dataset collected.
- This doesn't rule out weak PRNG entirely (only 3 specific schemes + a 10-minute window were tried), but the
  naive/classic versions of this bug are not present.

## Status: no working hypothesis yet
All cheap/light tests for the obvious hypotheses (nonce bias, verifier logic bypass, hidden commands, naive weak-PRNG
seeding, nonce/cross-signer reuse) have come back negative. Nothing here looks like a broken challenge (the service
is internally consistent and well-formed), so this is likely intended to need either: (a) a less obvious nonce-bias
variant (e.g. LSB bias / small-subgroup-style leak requiring a different lattice setup) at larger sample counts, or
(b) a genuine algebraic ECDSA weakness I haven't identified yet, or (c) protocol logic I haven't probed (e.g.
behavior exactly at the signature_budget limit, or some other message/field not yet explored).
Next step: pause and check in with the user rather than guess further without evidence.

## Round 3 testing (deeper structural hypotheses)

### Budget exhaustion — RULED OUT
- Pipelined 565 `1 0` requests in one connection. Exactly 560 signatures issued (budget matches stated value), then
  clean `[denied] signature budget exhausted` for every request after. No relaxed checks or different behavior at
  or after the limit. Last-issued signature happened to have title "Six Gates Ratification Memo" — coincidence,
  not special (see below).

### "Six Gates Ratification Memo" title (red herring) — RULED OUT
- One of 8 rotating routine-document titles is "Six Gates Ratification Memo", suspiciously similar to the real
  target. Live-tested: got a routine signature with exactly that title, then tried filing it as one of the two
  quorum signatures. Rejected with the same generic `[rejected] invalid gate quorum` as any other non-matching
  signature. Confirms the filing verifier checks the actual signed hash/target, not title text. Flavor/decoy only.

### Shared-seed key relationships between the 7 signers — RULED OUT
- Tested Q_i == Q_0 + i*G (additive) and Q_i == (i+1)*Q_0 (scalar multiple) against one session's full set of 7
  published public keys. No match for either pattern, and consecutive Q_i - Q_{i-1} differences are not constant.

### Counter-based / polynomial-in-doc-index nonce — RULED OUT
- Collected a full 560-signature dataset from signer 0 in one session (pipelined, ~90s, well within budget).
- Tested k_i = C + i (unknown constant offset from doc index): solved the resulting 2x2 linear system mod n from
  2 samples, checked recovered d against Q. No match.
- Tested k_i = C + a*i (unknown linear-in-index, 3 unknowns C,a,d): solved 3x3 linear system mod n from 3 samples.
  No match.
- Anti-replay "nonce" field itself: 560/560 unique nonces (via earlier 50-sample check, consistent here), no small
  gaps or periodicity suggesting a weak/short-period generator for that field either.

### LCG-recurrence nonce (k_{i+1} = a*k_i + b mod n) — RULED OUT
- Derived the bilinear elimination (2 unknowns a,d via resultant elimination of the a*d cross term from 3
  consecutive-pair equations, then quadratic solve for d, verified against Q) to recover (a,b,d) from 4 consecutive
  signatures assuming nonces follow a stationary LCG mod n.
- First implementation had an algebra bug (conflated two elimination stages); caught it by validating against
  synthetic LCG-nonce data first (CLAUDE.md-aligned: validate methodology before trusting a real-data negative).
  Fixed version correctly recovers the true (a,b,d) on synthetic data.
- Ran the corrected solver against 50 different consecutive 4-signature windows across the real 560-signature
  dataset (signer 0). No window produced a d matching the published public key.

## Status after round 3: still no working hypothesis
Exhaustively tested and ruled out (with validated tooling, not just "didn't look right"): magnitude-biased nonces
(HNP, any bound up to 240 bits), catastrophic/cross-signer nonce reuse, nonce-field-as-k in multiple transformed
forms, counter/polynomial-in-index nonces, stationary-LCG nonces mod n, three weak-PRNG-seed schemes for keygen,
additive/scalar key relationships between signers, budget-exhaustion bypass, duplicate-signer/zero-value/
out-of-range filing bypasses, and the title-based red herring. The service's ECDSA implementation looks
cryptographically sound from pure black-box analysis.
Next step: this is likely source-code-dependent now (i.e. needs the actual server implementation to spot the real
bug, rather than more blind-box guessing) — check whether this challenge has downloadable files (not just the nc
connection) before continuing further black-box probing.

## Better approach (2026 retro, unsolved)

The HNP work was exhaustive and correctly ruled out magnitude-biased nonces at every bound up
to 240 bits — don't repeat it. Two escalations that the lattice can't see, and that the large
560-sig/session budget actually points toward:
1. **Bleichenbacher FFT/Fourier attack** — recovers `d` from a *sub-bit* nonce bias (a fraction
   of a bit of skew) given many thousands of signatures. This is the natural next tool after a
   clean HNP result, and the generous budget is the hint. (collect one signer's full 560, FFT.)
2. **Minerva** — if the real leak is nonce *bit-length* rather than top-bits-zero, ~500–2000
   sigs suffice with a different lattice setup.
If both come back clean, treat nonce-attacks as closed and pivot to finding downloadable source
— a sound black-box ECDSA with no bias is usually a verifier/logic bug, not a math one.
See `ctf-crypto/SKILL.md` → "ECDSA biased-nonce".
