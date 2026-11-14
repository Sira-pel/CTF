# Nagas Weave (Crypto, 500 pts) — IN PROGRESS / STUCK

- Target: `nc 47.131.225.172 15646` (service only; no handout found for this challenge).
- The `Lancang_Mekong_CTF_comp/solved/rev_naga_custom/x/naga` binary is a *different* challenge ("Naga chart room", decoy `FLAG{the_naga_remembers_every_chart}`), not this one.

## Protocol
- Per connection: fresh session id, 7 RSA lanes (`n` ~1534-1536 bits, `e=65537`), `REPAIR_THRESHOLD 2`, `RECORD_BUDGET 4200`.
- `RECOVERY_JOB` (base64) = `{"op":"vault-rebuild","session":"NW-...","target":"NAGA-WEAVE-REPAIR:NW-..."}`.
- Commands: `harmonics`, `pulse <lane>` (1 rec), `siphon <lane>` (12 recs), `weld <lane>:<seal> <lane>:<seal>`, `bye`.
- Each record: `trace`(5B), `seal`(~1535b), `rail_mv`, `echo`(~1535b), `temp_c`, `latency_us`, `neutron_hits`, `harmonic`(A3/B5/C7), `tamper_latch`.
- `weld` closes the connection after one attempt (one-shot per connection) -> solve must be deterministic/offline.
- Goal: commit two valid "repair seals" (RSA sigs over the recovery-job target) for 2 lanes -> vault/flag.

## Ruled out (with evidence, offline on captured data)
- Shared primes within session and across 126 moduli (batch GCD): none.
- Fermat / close primes: none. ROCA fingerprint: negative.
- Small factors, Pollard p-1 (B=1e6), rho, ECM (default bounds): none -> balanced strong primes.
- seal/echo are statistically uniform random residues mod n:
  - printable% ~0.4, no DER/ASCII structure.
  - pairwise Hamming ~half (767/1534) even for same (lane,trace) and same (lane,trace,harmonic) -> not noisy copies.
- All RSA/Bellcore relations give no factor:
  - gcd(seal-echo), gcd(seal+echo), gcd(seal^e-echo), gcd(echo^e-seal), gcd(seal^e-echo^e),
    cross-record gcd(seal_i^e - seal_j^e) and (echo), within lane / same-trace / same-trace+harmonic.
- messages m=seal^e not smooth (no multiplicative forgery over small primes).
- Telemetry (rail_mv/temp/latency/neutron) is non-deterministic random per (trace,harmonic) -> not a lookup-table leak.
- Raw seals (clean neutron=0 and dirty) submitted to `weld` -> `ERR weld rejected`.
- Fault attack with computable FDH message = MGF1/sha/sha512 over many (target,trace,session,lane-name) encodings: no factor.

## naga_custom/x/naga binary = DIFFERENT challenge ("Naga chart room")
- Static C + OpenSSL + Lua 5.1 "chartroom" toolbox. Commands: `bulletin FILE.xml | pack zlib|zstd|xz | seal FILE | script FILE.lua`.
- `seal` = HMAC keyed with literal `naga-chartroom-public-seal` (dispatcher fcn.000a3d50 @ ~0xa416d), NOT RSA.
- Embedded decoy flag at 0x69a781: `FLAG{the_naga_remembers_every_chart}` ("the strongbox is not in here").
- Binary contains ZERO Nagas-Weave vocab (pulse/siphon/weld/harmonic/lanes/floodplain/monsoon/quorum) -> it is not the weave server and shares no scheme (HMAC vs per-lane RSA-CRT).

## Local runs (no network)
- `naga` → usage, exit 2. `naga chartroom` → decoy banner only.
- `naga -l -f decl` on 72 canonical lines → fingerprint and 13 ledger numbers, exit 0. No flag text.
- `naga -t RECEIPT decl`: every parsed receipt line must match the table. A bad line prints `SEALED`. An empty receipt matches vacuously and prints `OPEN` (no flag follows; exit 0).
- `naga seal FILE` → sha256 and HMAC under the literal key `naga-chartroom-public-seal`.
- `naga script` is Lua 5.1 without io/os/debug. `banner()` returns the same decoy string. `now()` returns time.

## Runtime of the chart-room binary (2026-11-11)
- `naga` with no args prints `usage: naga [-k KEY] [-t TARGET] [-l] [-f] DECLARATION` and exits 2.
- `naga chartroom` prints the decoy banner and the four toolbox commands. No other flag string in the file (`LMC{` absent).
- A 72-line zero-padded declaration (`%02d %04d %03d %03d %04x`) is accepted. `-l` prints six TREASURY totals plus LEVY, FEES, FINES, HIGH-WATER, SEAL, AUDIT, STAMP. `-f` adds a 12-bit fingerprint. Exit 0. Nothing flag-shaped.
- `-t` checks a receipt (`a b count` then `count` triples of `lane mask expected`) against a table built from the declaration and prints OPEN or SEALED. That is a local ledger check, not the 7-lane RSA service.
- `player.zip` is the same binary (sha256 `1eb8050a…6412e`). No extra zip payload.

## Additional checks (2026-11-11, still no flag)

Service grammar, one session at a time:
- `harmonics` → `HARMONICS A3 B5 C7` only.
- Exact verbs only. `pulse 0 <anything>` and `harmonics A3` are `ERR unknown verb`.
- `weld <lane>:<int> <lane>:<int>` parses hex integers. Same lane → `ERR bad weld packet` (connection stays up). Two different lanes → crypto check, then the socket closes.
- `weld 0:0 1:0`, `weld 0:1 1:1`, and `weld 0:1 2:1` are all `ERR weld rejected`. Identical trivial residues are not enough.

Offline on the saved 84-record capture (`NW-7JYR-M6VB`):
- Moduli are composite (Miller-Rabin), not prime powers, not squares. Pairwise and near-list GCD of 126 saved moduli is 1. `gcd` of all `(n-1)` is 2. Pollard p-1 (`B=1e5`) on lane 0 returned nothing.
- `seal^e`, `echo^e`, `seal/echo`, and `seal^e/echo^e` are full-size and unique per record. No PSS trailer `0xbc`, no PKCS `0001ff`, no trace bytes inside the residue.
- Cross-record `gcd(seal_i^e - seal_j^e, n)` is 1 on every lane, including clean `neutron_hits=0` vs dirty. Not a repeated-message single-prime CRT fault on this sample.
- `gcd(seal^e - H, n)` is 1 for SHA-256/SHA-1/MD5 of the trace, the recovery target, the lane name, and the joined telemetry string. AES-PSS rebuilds of those messages do not equal `seal^e` or `echo^e`.
- Textbook encryption the other way (`trace^e`, `sha256(trace)^e`) is not the seal or the echo.
- Seals are not `g^{trace}` for a per-harmonic base (`s1^{tr2} ≠ s2^{tr1}`).
- Raw seal/echo are not degree-1 or degree-2 polynomials of the trace mod n.
- Byte-reversal, nibble-swap, and Montgomery unscale by `2^k` leave a full-size integer.
- Telemetry looks like independent noise (latency stdev ~450–500 inside a lane). Trace pool per lane is small (~8–12 values in 12 draws) but the values are not SHA-256 prefixes of small counters.

## Try-harder checks (2026-11-11, still no flag)

Live, one weld per connection, after reading until `NW$ `:
- Hidden verbs (`source`, `debug`, `scheme`, `help`, `flag`, `vault`, …) are all `ERR unknown verb`.
- Locally correct e=3 Bleichenbacher PKCS forgeries (hash bytes survive in `sig^3`, `sig^3 < n`, `0001ff00 || DigestInfo`) were rejected for SHA-256 and SHA-1 of `NAGA-WEAVE-REPAIR:<session>`, SHA-256 of the recovery JSON, and SHA-256 of `smug`.

Offline on `NW-7JYR-M6VB` (84 records):
- Exact blinding checks are all false: `seal/echo` is not the trace, not `trace^e`, and `(seal/echo)^e` is not the trace or `sha256(trace)`. Harmonic-as-exponent (`seal == echo^h`, `h` in `{0xA3,0xB5,0xC7}`) is false.
- Franklin-Reiter for exponent 3, seal vs echo, small deltas and delta = trace: no factor.
- `gcd(seal_i - seal_j, n)` over all 462 pairs in a lane, including 15 same trace+harmonic pairs, is 1. Same for echo and seal-vs-echo.
- Trace is not SHA-256/SHA-1/MD5/BLAKE2s/CRC32 of the seal or the echo.
- Session-seeded primes do not reproduce the moduli: SHA-512 expand + `nextprime`, and `random.Random` version 1 and 2 on the session id / lane name (14 primes of 767 and of 768 bits), and `random.Random(sha256(session))`. No pair product equals any lane `n`.
- Trace bytes and the low 40 bits of the seals are not printable and do not contain the flag.

## Open questions / next steps
- Still no handout in the CTF tree. The captured residues behave like independent random elements mod `n`.
- Do not spend the 4200-record budget until a light test shows a non-random relationship. The missing piece is the signing implementation (what a repair seal is a signature of, and how `seal`/`echo` are derived).

## 2026-11-11 later pass (still no flag)

Sessions `NW-Z9DE-B2HY`, `NW-CDAE-QT52`, `NW-PKRY-MY9J` (lane 0 × 360 records), plus one 12-record siphon of all 7 lanes.

- Each lane draws traces from a **session-local pool of exactly 10** 5-byte values (360/360 draws, 10 unique). Pools are disjoint across lanes and change every connection. Not `random.Random(session)` `getrandbits(40)` / `randbytes(5)`, and not SHA-256/SHA-1/MD5 prefixes of `session:i`.
- All 360 seals were unique. Within a trace, 6504 pairs: `gcd(seal_i-seal_j, n)=1`. Same-harmonic `gcd(seal_i^e-seal_j^e, n)=1`. Not a repeated-message CRT fault, including neutron 0 vs neutron > 0.
- `seal^e mod n` for 94 neutron-0 records does not contain the trace, the recovery JSON, `NAGA-WEAVE-REPAIR:<session>`, or SHA-256/SHA-1/MD5 of those.
- `rail_mv`, `temp_c`, `latency_us`, `neutron_hits` are uncorrelated with each other and with the low/high byte of `seal` (|r|<0.1). `tamper_latch` stayed `clear`.
- Lane 0 `n`: not prime, not a perfect power, Wiener convergents of `e/n` do not factor it, MSB and LSB bit-deinterleave are not a prime pair.
- Parser: `weld` / `weld 0:1` → `ERR unknown verb` (the two-seal regex did not match). `weld 0:1 0:2` and `weld 0:zz 1:1` → `ERR bad weld packet` (connection stays up). `weld 0:1 1:1` → `ERR weld rejected` and the socket closes.

## 2026-11-11 evening (still no flag)

On the saved `NW-PKRY-MY9J` lane-0 capture (360 records, 10 traces):

- Blinding rearrangements are not constant per trace or per trace+harmonic: `seal^e/echo`, `seal/echo^e`, `seal^e*echo`, `seal*echo^e`.
- The 10 traces are not one full period of an LCG modulo `2^40` (odd steps). The sample stream matches uniform draws with replacement, not a cycle.
- `seal XOR/+/−/* echo` is a different value on every record.
- No small period in `seal XOR echo`. `gcd(seal^e−seal, n)=1`.
- Montgomery unscale by `2^k` (k up to 4000, and common word sizes) never shrinks a seal below ~1524 bits.
- `next_prime(trace<<k)` does not divide `n`. Seeded `random.Random` / SHA-512 `next_prime` from the session and lane name does not rebuild `n`.
- Fermat on `k*n` for k in the harmonic set `{0xA3,0xB5,0xC7}` and small integers, 5000 steps, does not hit.
- No prime factor below 1e5. `weld 0:-1 1:1` is a real crypto reject (socket closes). Same-lane `0`, `n`, and `n+1` stay `ERR bad weld packet`.
