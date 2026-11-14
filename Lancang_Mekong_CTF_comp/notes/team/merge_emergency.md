# Merge Emergency (in progress)

Team_Work 033, 700 pts. Service: `nc 47.131.225.172 33105`. Files: `Lancang_Mekong_CTF_comp/unsolved/team_merge_emergency/`.

## Protocol

Line REPL. Verbs that exist: `HELLO` -> `OK`, `OPEN` -> `OK <sid16> <token32>`, `INFO` (needs a session) -> `OK 0 `, `ATTACH <token>` joins that session from another socket (and from the opener), `TX <arg>` -> `ERR auth` for every encoding tried, `QUIT` -> `BYE`. Anything else, including a raw engine hex line, is `ERR cmd`. `TX` with no argument is `ERR cmd`. `INFO` stays `OK 0 ` until a TX authenticates. No second verb showed up; do not resume wordlists.

## Crypto

Evidence is AES-GCM. AAD is 57 bytes: `LMC-MERGE-v1\x00\x00\x00\x00` || team `0x06` || `key_epoch` (16) || mid (16) || seq uint64be. `key_epoch` is not the AES key (`AES(epoch, 0)` != H).

rec-16, rec-17, rec-18, rec-19 share nonce `cbf286722316e96425547d37`. GHASH key recovered from that cluster:

- H = `d409216d588e9282b3bc995a771c369e`
- S = `tag XOR GHASH(H, aad, ct)` = `5c9c1d40fd23768e43665a201a7fd168` (same for all four)
- Recompute of rec-19's tag matches. Forgery works for this nonce only.
- Script: `work/ghash_h.py`.

rec-17 ciphertext is 4010 bytes, the same length as the encoded north-station recipe (`work/recipe.bin`: BEGIN, ALLOC 4000, WRITE the `MERGE-STATION-RECIPE-v1|north-station|flood-gate-7|` ramp, COMMIT). Using that wire as known plaintext makes the sibling plaintexts high-entropy, and no 16/24/32-byte window of them satisfies `AES(key, 0) == H`. Crib is not confirmed. Mid field is not a standard hash of the public fields.

Forged tags under likely server AADs (empty, sid, token, epoch, file AAD, session-bound AAD) in layouts `nonce||ct||tag` and `nonce||tag||ct` still return `ERR auth`.

## VM

`libdelta.so` and the in-process client VM match. Opcode wire: 01 BEGIN, 02 ALLOC, 03 ALIAS, 04 WRITE, 05 SCHEDULE_READ, 06 SCHEDULE_PATCH, 07 PROMOTE, 08 COMMIT, 09 ROLLBACK, 0a VIEW_CREATE, 0b VIEW_READ, 0c VIEW_WRITE. Engine prints `DATA <hex>` on VIEW_READ and on a promoted SCHEDULE_READ at COMMIT, then `RESULT OK/ERR`.

Confirmed bug: nested BEGIN, schedule a read or patch, PROMOTE (retags the op to epoch-1 and snapshots pointers), ROLLBACK (frees the epoch-2 objects, leaves the promoted op), COMMIT applies the snapshot. Freed tcache chunk leaks through DATA. On glibc 2.42 the first qword is the safe-linked fd; with one free chunk that is `chunk_addr >> 12`. VIEW_WRITE is unreachable (flag bit 2 is never set). libdelta has no file IO, so the local dummy flag is not readable without a further arbitrary-read / ROP chain. The real flag is on the service, which does not run these blobs until TX authenticates.

## Local harness (fixed this session)

`merge-engine` was "crashing" (`*** stack smashing detected ***`) on every run — not a bug, a loader mismatch: the system `ld.so` was mixing in the bundled `libc.so.6` incorrectly. Fix: invoke through the bundled loader explicitly:

```
./ld-linux-x86-64.so.2 --library-path . ./merge-engine < input.hex
```

With that fix confirmed:
- `merge-engine` reads **one hex-encoded wire line per stdin line** (the binary wire format `merge-client encode` produces), *not* the text recipe DSL directly. Feeding the text DSL gives a bogus `RESULT ERR` per line (looked like per-line failure before, was actually "wrong input format").
- `work/samples/sample1_basic.wire.hex` and `sample2_alias.wire.hex` both now reproduce their documented `RESULT OK`.
- `merge-client encode recipe.txt out.bin` reproduces `work/recipe.bin` byte-for-byte (`cmp` clean) — **the recipe crib for rec-17 is now independently confirmed** at the encoder level (not just length match): this is genuinely what the official tool emits for that program, 4010 bytes, matching rec-17's ciphertext length exactly.
- Re-ran the `r.txt` nested-BEGIN/PROMOTE/ROLLBACK/COMMIT leak end-to-end through the fixed engine: still leaks a freed tcache chunk via `DATA` (first qword `140e565505000000` = safe-linked fd), matching the bug writeup in `## VM` above. Good local oracle now works for iterating on the heap-leak program before spending any TX attempts against the real service.

## AAD fields, re-examined (live, 2 light sessions: HELLO/OPEN/INFO/QUIT, then one length-probe sweep)

- `mid` (16 bytes) is exactly the same length as the `sid` `OPEN` returns (confirmed live: `OPEN` -> `OK <sid:16B-hex> <token:32B-hex>`). Strong hypothesis: `mid == sid` of whatever session produced that record — consistent with every evidence record having a distinct `mid` (20 records likely = ~20 separate historical `OPEN`s, not one session sending 20 messages).
- `seq` is a **global**, strictly-incrementing counter 1..20 across *all* 20 evidence records (not per-session) — so it's a server-wide message count, not something we choose or can derive for our own session without knowing where the real counter is now.
- Ran a length-discrimination probe: sent `TX <n bytes of junk hex>` for n = 0,12,16,24,28,44,57,60,69,73,85,89 bytes, fresh session. **Every single length — including 0 bytes — returns `ERR auth`, never `ERR cmd`.** So the server does not reject on argument length/shape before reaching the crypto check (or it silently treats anything parseable-as-hex as a candidate and always falls through to the same generic auth failure). This closes off "find the right length by error-message shape" as a technique — the oracle is flat.

Net effect: the GHASH forgery (H, S) only tells us we can produce a valid tag for **any aad/ciphertext under the exact reused nonce `cbf28672...`**, without the AES key. That part is solid and doesn't need re-deriving. What's still unknown and blocking is *what AAD the server will actually check against* for a TX on a freshly opened session — specifically whether `seq` must match the server's real live counter (unknown value, almost certainly >20 by now) and whether `mid` truly equals our session's `sid`. Guessing `seq` blindly is a brute-force-shaped problem (unknown offset, no feedback to narrow it) and is explicitly out of bounds per comp rules without a smarter angle — this needs either an information leak that reveals the current seq/mid (e.g. from the VM-side heap leak, ironically — INFO stays `OK 0` pre-auth so no help there), or a design reason to believe seq doesn't matter (e.g. the server accepts a window/any seq ≥ last-used, or doesn't bind seq to validity at all and only mid+epoch+team matter).

## Forgery attempt #1 (live, disproved)

Built a concrete forged TX from the recovered (H, S) and the confirmed rec-17 crib, rather than guessing blind:

- `new_pt` = `merge-client encode t1.txt` = `01021008` (trivial BEGIN/ALLOC 16/COMMIT, just to test auth acceptance, not a real payload yet).
- `keystream` = `recipe.bin XOR ct(rec-17)` (both confirmed-identical plaintext, so this is a real keystream, not a guess), `new_ct = new_pt XOR keystream[:4]` = `a276641c`.
- `aad = "LMC-MERGE-v1\x00\x00\x00\x00" || 0x06 || epoch(=rec-17's, edcd87ab...) || mid=our_session_sid || seq`, `tag = GHASH(H, aad, new_ct) XOR S` — all computed, no guessing in the crypto itself.
- Opened one fresh session (`sid=50460ac1...`), tried `seq` 21..30 (just past evidence's last seq=20, on the theory this instance has 0 solves and evidence.json is this team's whole history with the service) in both `nonce‖ct‖tag` and `nonce‖tag‖ct` layouts — 20 TXs total, one connection. **Every one: `ERR auth`.**

This disproves (or at least doesn't confirm) `mid == sid` + `seq` in a small range past 20, for these two layouts. It does **not** disprove the GHASH forgery itself (that's independently verified against all 4 same-nonce evidence records). What's still unknown: whether `mid` really is the session id at all, whether `seq` is far from 20 (if some other process/team also increments the same global counter), or whether the TX argument isn't a flat `nonce‖ct‖tag`/`nonce‖tag‖ct` concatenation at all (extra field, different order, server-chosen nonce, etc.). Roughly 30 live TX attempts made total across this investigation so far (12 length-probe + ~ this batch) — getting into territory where further blind layout/field guessing starts to look like fuzzing rather than a light test, so the next move should be a sharper hypothesis, not a wider seq/layout sweep.

## Forgery attempts #2-5 (live, all disproved) — content-hash mid, historical mids, explicit-AAD framings, no-crypto, two-socket ATTACH

- **Content-derived `mid`?** Hypothesis: since the brief is about two conflicting station journals, `mid` might be a hash of the plaintext payload (station name / recipe content) rather than anything session-bound. Checked **locally, no network**: md5/sha1/sha256 (first and last 16 bytes) of the recipe's ASCII header (`MERGE-STATION-RECIPE-v1|north-station|flood-gate-7|`) and of the full recipe buffer, against rec-17's real `mid` (`c1eba8bf...`). No match on any variant. Hypothesis not confirmed (cheap, zero network cost).
- **Historical mids + new seq**: tried each of rec-16/17/18/19's own real `mid` values (not our session's `sid`) with `seq=21`, forged tag, one connection, 4 TXs. All `ERR auth`.
- **Explicit-AAD framing**: tried `nonce‖aad‖ct‖tag`, `aad‖nonce‖ct‖tag`, `nonce‖ct‖aad‖tag`, `nonce‖aad‖tag‖ct` — each with rec-19's **unmodified, byte-for-byte real** nonce/aad/ct/tag (a record that would legitimately authenticate if the server had the real key and used this framing). All `ERR auth`. This is the most telling result: a verbatim, genuinely-valid historical record fails under every concatenation order tried, which means either none of these TX framings are right, or the server has replay protection that rejects already-used (nonce, seq) pairs outright regardless of crypto validity — we can't currently tell these apart.
- **No-crypto plain wire**: sent a bare VM wire blob (`sample1_basic.wire.hex` content) as the entire `TX` argument, no nonce/tag at all. `ERR auth` — rules out "TX just takes a raw program, no AEAD layer."
- **Token/sid as a prefix field**: tried `token‖blob`, `sid‖blob`, and both as a *separate space-delimited* first argument before the nonce/ct/tag blob. All `ERR auth`.
- **Two-socket ATTACH ("merge" theme)**: opened session on socket A, `ATTACH`ed socket B to the same token (confirmed: `ATTACH` replies `OK <sid>`, and both sockets' `INFO` read `OK 0`), then sent *different* historical records (rec-16 from A, rec-18 from B) as if the two "stations" were each submitting their own journal into the shared session. Both still `ERR auth` with no behavior change from being attached together.

**Running total: ~45 live `TX` attempts across this investigation, with zero differentiated server responses** — every single combination of framing/AAD/field tried, including a byte-perfect real historical record, returns the exact same generic `ERR auth`. That flat an oracle, after this much structurally-distinct probing, is itself worth flagging: either the real format needs information we have no way to derive from what we've been given (plausible but would be an unusually opaque design even for a hard challenge), or something about the service/instance is broken. Per comp rules this is the point to stop live probing and check in rather than keep permuting fields, which would cross into fuzzing.

## Session 2 (offline re-verification + 1 principled live test)

- **Crypto re-verified, independent of the note.** `ghash_h.py` gives a *unique* H (gcd deg 1, single root). Rebuilt the forge from scratch: `tag = GHASH(H,aad,ct) XOR S` with `H=d409216d…`, `S=5c9c1d40…` reproduces the **real tag of all four** rec-16/17/18/19 byte-for-byte. So the forgery is 100% correct; every live `ERR auth` is a *protocol/AAD/freshness* failure, not a crypto one.
- **New principled live test (seq on a fresh session).** Prior attempts only used seq 21..30. Opened one fresh session (`sid=580521cf…`), forged TX under nonce `cbf28672…`, mid=our sid, and tried **seq = 1, 0, 2, 21** (hypothesis: `INFO -> OK 0` means a per-connection counter, so first valid seq is 1). **All `ERR auth`.** Per-session-counter hypothesis disproved. (~4 live TX; running total ~49.)
- **The recipe crib is DEFINITIVELY WRONG — and there is no known plaintext anywhere.** The four cluster records share one keystream (proven: identical S). So `ct_i XOR ct_j = pt_i XOR pt_j`. Decrypting rec-16/18/19 with `KS = ct17 XOR recipe.bin` gives **high-entropy garbage**, and **all pairwise ciphertext XORs have no zero-run prefix** — if these were VM programs they'd all begin `01` (BEGIN) and the XORs would start `00…`. They don't. Therefore: (a) rec-17 ≠ recipe (the 4010-byte match was coincidence/decoy), (b) the cluster plaintexts are **not** plain VM wire, (c) **we have zero known plaintext → no real keystream → the "run a chosen VM exploit via known keystream" forgery path is blocked even setting AAD aside.** Tag-forgery works; *meaningful* ciphertext-forgery does not, without recovering a plaintext first.
- **Server protocol binary is not in dist** (`merge-client`=encoder, `merge-engine`=VM, `libdelta.so`=VM lib; none contain HELLO/OPEN/TX/auth strings). The TX/auth construction is server-only and cannot be reversed offline.

## Session 2b — crib-drag attempted, conclusively negative

Followed the only remaining offline lead (recover a cluster plaintext, since all four share one keystream → `ct_i XOR ct_j = pt_i XOR pt_j`).

- `recipe.bin` is a **user-built test fixture** (BEGIN / ALLOC 4000 / WRITE a literal `00..ff` ramp / COMMIT), not challenge-provided plaintext. So there is genuinely **no known plaintext** to seed a drag.
- Crib-dragged all 6 pairwise XORs with themed cribs (`MERGE-STATION-RECIPE-v1|`, `north/south/...-station`, `flood-gate-`, `LMC{`, `RECIPE`, `JOURNAL`, `valve`, `commit`, …) and generic English. **Zero readable recoveries** — every printable "hit" is a 3–4 byte random window passing by chance; no crib yields words on the other side.
- **Index of coincidence of every pairwise XOR ≈ 0.003–0.005, i.e. the random baseline (0.00391).** ASCII⊕ASCII would give IC ≳ 0.012. Therefore the cluster plaintexts are **high-entropy binary with no linguistic redundancy** — not journal text, not sparse VM wire. Crib-drag / known-plaintext recovery is fundamentally inapplicable here.

**Net:** the cluster plaintexts cannot be recovered offline without an actual known fragment or the server binary (neither exists). Tag-forgery remains valid, but we can never craft a *meaningful* chosen ciphertext (e.g. a VM exploit program) because the keystream is unknowable. The forgery path is dead on crypto grounds too, not just AAD/freshness.

**Assessment:** three independent walls now confirmed — (1) unknown live AAD/freshness (seq), and (2) no known plaintext to build a real payload. A verbatim valid rec-19 still fails. This is either underspecified from the provided materials or a broken instance (0 solves). Recommend an organizer check before any further live attempts; the only remaining *offline* lead is to recover a cluster plaintext by modelling the real record/payload framing (not plain VM wire) and crib-dragging — large effort, uncertain.

## Next

1. **Flag for possible "broken challenge" check with the user/organizers**, given 0 solves + a completely flat oracle even for verbatim real records, before any further live attempts.
2. **Stop guessing AAD fields blindly.** Instead, treat "what makes a TX's AAD valid" as itself the open question and look for a non-guessing way to learn it — e.g., whether multiple TXs in one session are allowed (would reveal if seq resets per-session or is global), or whether there's a lower-cost oracle (do ATTACH from a second socket, see if INFO or any response differs once a TX is in flight).
2. Once the AAD shape is known: `ct = program_wire XOR keystream(recipe.bin, rec-17)[:len(program_wire)]` plus a forged tag (via the already-recovered H/S) runs a **chosen VM program** under nonce `cbf28672...`. The payload to run is the heap-leak chain from `r.txt`/notes `## VM`, extended into an actual arbitrary-read/flag-read chain.
3. The local engine fix (loader + hex-wire-per-line input) means step 2's program can be fully built and verified offline before it ever needs to touch the network — only the final forged TX needs to go over the wire.
