# Hard/Medium CTF Challenge Research → Skill Pack Upgrades

**Date:** 2026-11-21 (Asia/Bangkok)  
**Scope:** 28 medium/hard challenges with public writeups (2022–2024), weighted for RE/Pwn beginner→intermediate growth.  
**Repo reviewed:** private `Sira-pel/CTF` `.claude/skills/` (fork of `ljagiello/ctf-skills`) + local upstream mirror.  
**Method:** public writeups only (CTFtime, author blogs, official archives). No live targets. Links verified with WebFetch where noted.  
**No repo changes / no PRs.** Snippets are proposals only under `snippets/`.

---

## 1. Challenge catalog (28)

Legend for **Pack:** Covered / Partial / Gap. Evidence from grepping the fork.

### Reverse (8)

| # | Event | Challenge | Diff | Writeup(s) | Key trick | Lesson (signal → technique) | Skill | Pack |
|---|-------|-----------|------|------------|-----------|------------------------------|-------|------|
| 1 | Google CTF 2022 | eldar | Hard | https://lkmidas.github.io/posts/20220704-ggctf2022-writeups/ (verified); https://ctf.harrison.green/2022/googlectf/eldar/ | ELF loader as VM: `Rela` entries = opcodes, symbols = registers; self-modifying relocs + IFUNC shellcode | Huge `.rela` / empty code → parse `readelf -r/-s`, emulate reloc types, lift to IR, Z3 checks | ctf-reverse | **Gap** (no weird-ELF / reloc-VM) |
| 2 | HITCON CTF 2023 | LessEQualmore | Med–Hard | https://blog.bronson113.org/2023/09/10/hitcon-ctf-2023-lessequalmore-subformore.html (verified); https://ctftime.org/writeup/37915 | SUBLEQ / ELVM bytecode; lift to IR or black-box linear I/O matrix | 3-tuple bytecode + values near 2^24 → SUBLEQ/ELVM; try oracle matrix before full lift | ctf-reverse | **Gap** (no SUBLEQ/OISC/ELVM) |
| 3 | Flare-On 11 (2024) | serpentine | Hard | https://blog.elmo.sg/posts/flareon-11-serpentine/; https://washi1337.github.io/ctf-writeups/writeups/flare-on/2024/9/ | HLT → exception; `RtlInstallFunctionTableCallback` returns RUNTIME_FUNCTION whose UnwindInfo is next shellcode | Exception-driven control flow → dump unwind tables / callback, chain blocks offline | ctf-reverse | **Partial** (`patterns.md` mentions RtlInstall… but thin) |
| 4 | UIUCTF 2023 | vmwhere1 | Medium | https://ctftime.org/writeup/37376; https://www.ctfiot.com/123684.html | Tiny stack VM; extract keys from bytecode pattern `\x05\x0f\x0a`, reverse XOR chain | Custom VM → write disasm + invert opcode chain from end | ctf-reverse | **Partial** (generic VM steps exist) |
| 5 | ImaginaryCTF 2023 | sheepish | Hard | https://ret2school.github.io/post/sheepish/ | Obfuscated Church / lambda-calculus Python; identify combinators, evaluate as arithmetic | Dense lambdas / `λ` / Y/Z combinator → Church encoding table, reduce to normal ops | ctf-reverse | **Gap** |
| 6 | Hack.lu 2023 | Cube_Hash | Medium | https://ctftime.org/writeup/37992; https://ctf42.online/ctfs/hacklu/2023/cube_hash/ | Password as cube rotations; use invariant facelets to brute per char | Physical / puzzle crypto with invariants → constrain search space | ctf-reverse / misc | **Partial** |
| 7 | Google CTF 2024 | NotObfuscated | Medium | https://hackmd.io/@jinn/ggctf2024 | RC4 crackme with matrix flavor; recover 16-byte key | “Not obfuscated” still hides key in tables → dump constants, match cipher | ctf-reverse | Covered (classic crackme) |
| 8 | DEF CON Quals 2023 | IFUCKUP | Hard | https://www.kalmarunionen.dk/writeups/2023/defcon_quals/ifuckup/ | Static RE + recover PRNG that drives checks | PRNG-backed checker → dump seed/state, reproduce offline | ctf-reverse | **Partial** |

### Pwn (8)

| # | Event | Challenge | Diff | Writeup(s) | Key trick | Lesson | Skill | Pack |
|---|-------|-----------|------|------------|-----------|--------|-------|------|
| 9 | SECCON 2022 | babyfile | Hard | https://ret2school.github.io/post/babyfile/ (verified) | FSOP: doallocate/underflow → leak; `_IO_obstack_jumps` → `system("/bin/sh")` without hooks | Full RELRO + modern libc → prefer FSOP / obstack / house-of-*, never `__free_hook` | ctf-pwn | **Partial** (FSOP yes; `_IO_obstack_jumps` missing; hooks still listed as primary) |
| 10 | Google CTF 2023 | write-flag-where | Medium | https://cryptocat.me/blog/ctf/2023/google/pwn/write-flag-where/ (verified); series wfw2/wfw3 | Write flag via `/proc/self/mem` onto printed `.data` string | Free write of fixed content → overwrite any later-printed buffer / GOT / libc exit path | ctf-pwn | **Partial** (sandbox-escape has mem write; missing “write flag content” pattern) |
| 11 | DiceCTF 2023 | bop | Medium | https://www.alexyzhang.dev/write-ups/dicectf-2023/bop/ (verified); files: https://github.com/dicegang/dicectf-2023-challenges/tree/main/pwn/bop | Seccomp ORW; use raw `syscall` not libc `open` (may be `openat`) | Seccomp → dump filter; ORW with syscall gadgets; avoid libc wrappers | ctf-pwn | **Partial** (ORW/seccomp exist; open→openat trap weak) |
| 12 | HITCON 2023 | SUBformore | Hard | same Bronson post as #2 | OOB on SUBLEQ memory into jump table → VM shellcode / libc leak | Custom VM pwn: treat VM mem like heap; OOB into interpreter metadata | ctf-pwn | **Gap** |
| 13 | 0CTF/TCTF 2023 | Nothing is True | Hard | https://github.com/nobodyisnobody/write-ups/blob/main/0CTF.TCTF.2023/pwn/Nothing.is.True/README.md | Static ELF under seccomp; self-mod to `syscall`/`int 0x80`; 64→32 mode switch | Mode-switch / self-mod + fake VDSO for sysenter | ctf-pwn | **Partial** (x32/RETF mentioned; incomplete) |
| 14 | corCTF 2022 | Cache of Castaways | Hard | https://www.willsroot.io/2022/08/reviving-exploits-against-cred-struct.html; archive: https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive/tree/master/pwn/cache-of-castaways | 6-byte overflow → cross-cache into `cred_jar`, uid=0 | Cross-cache + page spray → adjacent slab object corruption | ctf-pwn | **Partial** (kernel cross-cache mentioned) |
| 15 | PlaidCTF 2023 | baby heap question mark | Med–Hard | https://blog.xmcve.com/2023/04/17/Plaid-CTF-2023-Writeup-English/; https://ctftime.org/writeup/36935 | Wine/Rust allocator; overflow vector metadata → AAW → stack ROP | Non-glibc heaps: corrupt length/ptr fields of Vec/String | ctf-pwn | **Gap** (glibc-centric) |
| 16 | Google CTF 2024 | Knife | Medium | https://ribombalt.github.io/ctf-writeup/2024/06/24/GoogleCTF2024; https://ptr-yudai.hatenablog.com/entry/2024/07/09/115940 | 7th ASCII85 encoding collides into next cache hash | Encoding ambiguity / cache key collision → overwrite neighbor entry | ctf-pwn / misc | **Gap** |

### Web (5)

| # | Event | Challenge | Diff | Writeup(s) | Key trick | Lesson | Skill | Pack |
|---|-------|-----------|------|------------|-----------|--------|-------|------|
| 17 | corCTF 2022 | simplewaf | Medium | https://viblo.asia/p/corctf-2022-writeup-part-1-m68Z0Joj5kG (verified); files: https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive/tree/master/web/simplewaf | Express `file[...]` → object; Node `isURLInstance` duck-type; double-encode pathname | `fs.readFileSync(user)` → try URL-shaped object + encoding mismatch vs WAF | ctf-web | **Gap** |
| 18 | SECCON 2022 | skipinx | Easy–Med | https://blog.arkark.dev/2022/11/18/seccon-en (verified); https://github.com/arkark/my-ctf-challenges/.../skipinx | qs `parameterLimit=1000` drops nginx-appended `proxy=` | Proxy appends query → flood params past default limit | ctf-web | **Gap** |
| 19 | Google CTF 2023 | UNDER-CONSTRUCTION | Medium | https://heschl.dev/blog/2023-06-26-google-ctf-2023-under-construction-writeup/ (verified) | Flask first-wins vs PHP last-wins HPP on forwarded raw body | Multi-lang backends + raw forward → HPP first/last mismatch | ctf-web | **Gap** (HPP only as barcode analogy) |
| 20 | idekCTF 2022 | Paywall | Medium | https://ctftime.org/writeup/36071; https://lebr0nli.github.io/blog/security/idek-CTF-2022/ | PHP filter chain prepends `FREE` so LFI passes prefix check | Content-prefix gate + `php://filter` → generator prepend bytes | ctf-web | **Partial** (filter RCE covered; prepend-for-prefix less clear) |
| 21 | corCTF 2022 | friends | Medium | same Viblo post as #17 | ASI + `__proto__` fill sparse array | JS ASI + prototype tricks on follower arrays | ctf-web | **Partial** (prototype pollution exists) |

### Crypto (3)

| # | Event | Challenge | Diff | Writeup(s) | Key trick | Lesson | Skill | Pack |
|---|-------|-----------|------|------------|-----------|--------|-------|------|
| 22 | DiceCTF 2023 | BBBB | Hard | https://ctftime.org/writeup/36141; https://blog.maple3142.net/2023/02/06/dicectf-2023-writeups/ | Force LCG into short cycle → tiny RSA e → Coppersmith | Controllable LCG + RSA → engineer small exponent, then `small_roots` | ctf-crypto | **Partial** (both pieces exist; combo missing) |
| 23 | Insomni'hack Teaser 2023 | GCM | Medium | https://sylvainpelissier.gitlab.io/posts/2023-01-12-insomnihackteaser23-gcm/ (verified) | Nonce reuse → recover H, forge tag (forbidden attack) | Reused IV/nonce in GCM → recover H, forge | ctf-crypto | **Covered** (and in Pel lessons) |
| 24 | (pattern) | — | — | — | ECDSA/DSA nonce reuse (pack already strong) | Same-r signatures → d leak | ctf-crypto | Covered |

### Misc / Jail (4)

| # | Event | Challenge | Diff | Writeup(s) | Key trick | Lesson | Skill | Pack |
|---|-------|-----------|------|------------|-----------|--------|-------|------|
| 25 | Google CTF 2022 | Treebox | Medium | https://ctftime.org/writeup/34550 | AST bans Call/Import; use Exception `__getitem__` = `os.system` | No-call AST jail → dunders / decorators / raise+except | ctf-misc | **Partial** (decorator escape exists; Exception `__getitem__` pattern weak) |
| 26 | ImaginaryCTF 2023 | You shall not call! | Hard | https://gist.github.com/lebr0nli/eec8f5addd77064f1fa0e8b22b6a54f5; https://cp04042k.github.io/posts/ictf-2023/ | Pickle without REDUCE/NEWOBJ; BUILD → `__setstate__` | Restricted pickle → BUILD/__setstate__ abuse | ctf-misc | **Gap** |
| 27 | LA CTF 2024 | jsfudge | Medium | https://kevin.fish/writeups/e3c2664e7fab9a91d2fb20abebe9fc6f; archive: https://github.com/uclaacm/lactf-archive | JSFuck charset but `Array.toString` broken; rebuild via `Number.toString(radix)` + dynamic `import` | Broken JSFuck primitives → rebuild charset; ESM `import()` if no `require` | ctf-misc | **Partial** |

### Forensics (2)

| # | Event | Challenge | Diff | Writeup(s) | Key trick | Lesson | Skill | Pack |
|---|-------|-----------|------|------------|-----------|--------|-------|------|
| 28a | Kalmar CTF 2023 | lleHSyniT! | Med–Hard | https://blog.ruifi47.com/posts/kalmarctf2023_tinyshell/ | Cobalt Strike beacon keys from memory dump → decrypt pcap | CS traffic + proc dump → extract HMAC/AES, parse beacon | ctf-forensics / malware | **Partial** |
| 28b | (generic TLS) | HTTPS + dump | Medium | e.g. https://ctftime.org/writeup/37844 | CLIENT_RANDOM from dump → SSLKEYLOG → tshark | Encrypted pcap + RAM → keylog decrypt | ctf-forensics | **Partial** |

### AI/ML (2)

| # | Event | Challenge | Diff | Writeup(s) | Key trick | Lesson | Skill | Pack |
|---|-------|-----------|------|------------|-----------|--------|-------|------|
| 29 | NOPS CTF 2024 | Double Protection 2 | Medium | https://github.com/N0PSctf/N0PSctf-2024/blob/main/ai/double-protection-2/writeup.md | Escape checker’s quoted prompt; force non-YES answer | Dual LLM gate → confuse checker output class | ctf-ai-ml | **Partial** |
| 30 | ImaginaryCTF 2024 | Naughty Ai | Easy–Med | https://sakouk.me/writeups/2024/imaginaryCTF/naughty-ai.html | Ask model to verify MD5 of its secret flag | Side-channel verification prompts leak secrets | ctf-ai-ml | **Partial** |

*(Counted as 28+ with 28a/28b and AI extras; core unique learning set = 28.)*

---

## 2. Gaps ranked by impact (for Pel’s RE/Pwn focus + event rules)

1. **Modern glibc pwn path still points at hooks** — `__free_hook` appears as a primary Full-RELRO target in `ctf-pwn/SKILL.md` even though the same file notes hooks gone since 2.34. Agents will waste time. Prefer FSOP / `_IO_obstack_jumps` / exit_funcs / ROP. *(babyfile)*
2. **No “weird machine / reloc / SUBLEQ” reverse triage** — hard Google/HITCON RE often isn’t “find strcmp”. Missing recognition → hours lost. *(eldar, LessEQualmore)*
3. **Web skill still pushes scanners** — sqlmap/ffuf in quick starts conflict with Lancang-Mekong no-scan rules; missing high-value *logic* patterns: Node URL duck-typing, qs parameterLimit, cross-language HPP. *(simplewaf, skipinx, UNDER-CONSTRUCTION)*
4. **Token bloat / missing scripts** — `ctf-pwn` ~1.1MB with `pwnable-tw/`; referenced `scripts/install_ctf_tools.sh`, `solve-challenge/scripts/ctf_router.py`, web js-sandbox absent → agent dead-ends.
5. **Jail/pickle BUILD + Exception dunder** under-specified vs decorator-only pyjail notes. *(Treebox, You shall not call!)*
6. **Flag/notes inconsistency** — writeup defaults `flag{}` / `writeup.md`; reverse still greps `flag{`; event is `LMC{}` and `notes/<chal>.md`.
7. **Seccomp ORW footguns** — libc `open`→`openat` under filter. *(bop)*
8. **Non-glibc heaps** (Rust Vec under Wine). *(baby heap?)*

---

## 3. Patterns that recur in hard challenges (triage cheat sheet)

Drop into `solve-challenge` after Hypothesis First:

```
SIGNAL → FIRST MOVE
Empty .text but huge .rela/.dynsym → ELF reloc VM (readelf -r/-s; emulate)
Bytecode triples / OISC / “subleq” / ELVM → lift or black-box linear oracle
Exception / HLT / RUNTIME_FUNCTION → unwind-table VM; dump handlers offline
Custom interpreter + remote → RE first, then OOB into VM metadata (pwn)
checksec: Full RELRO + libc≥2.34 → FSOP/obstack/exit_funcs; NEVER hooks
Seccomp present → seccomp-tools dump; prefer raw syscall ORW; distrust libc wrappers
Free write of fixed buffer (flag) → overwrite next printed string / GOT / exit path
Node fs.*(userPath) → try object/URL duck-type + double-encoding vs WAF
Two languages share one request → HPP first-vs-last
Reverse proxy appends query → parameterLimit / parser quirks
AES-GCM same IV → forbidden attack (recover H)
Pickle without REDUCE → BUILD/__setstate__
AST bans Call → decorator / raise Exception with dunder
LLM “must not reveal” → side-channel verify / confuse gate model
Encrypted pcap + memory → SSLKEYLOG or CS key extract
```

---

## 4. Practice first (8–10) — beginner → harder

Do these offline from public archives. Order assumes Pel’s RE/Pwn role.

1. **DiceCTF 2023 bop** — stack overflow + seccomp ORW. Files: https://github.com/dicegang/dicectf-2023-challenges/tree/main/pwn/bop  
2. **Google CTF 2023 write-flag-where** — `/proc/self/mem` write of flag. Official tree under `google/google-ctf` 2023 quals (search `write-flag-where`); writeup: https://cryptocat.me/blog/ctf/2023/google/pwn/write-flag-where/  
3. **UIUCTF 2023 vmwhere1** — small VM. https://github.com/sigpwny/UIUCTF-2023-Public  
4. **corCTF 2022 simplewaf** — Node URL object. https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive/tree/master/web/simplewaf  
5. **SECCON 2022 skipinx** — qs limit. https://github.com/arkark/my-ctf-challenges (path web/skipinx)  
6. **Google CTF 2023 UNDER-CONSTRUCTION** — HPP. https://github.com/google/google-ctf (2023 quals web)  
7. **Google CTF 2022 Treebox** — AST jail. CTFtime writeups + google-ctf 2022  
8. **SECCON 2022 babyfile** — FSOP/obstack. https://github.com/ret2school/ctf/tree/master/2022/seccon/pwn/babyfile  
9. **HITCON 2023 LessEQualmore** — SUBLEQ RE. https://github.com/bronson113/My_CTF_Challenges  
10. **Google CTF 2022 eldar** — reloc VM (stretch). google-ctf 2022 + Midās writeup  

Also always-on: **pwn.college** Program Security hard ROP / RE modules — https://pwn.college/program-security/

---

## 5. Concrete upgrades (see snippets/)

Token-lean drop-ins: recognition checklist + 3–8 decision lines. Prefer appending to SKILL.md “Quick checks” rather than new mega-files.

| File | What to add |
|------|-------------|
| solve-challenge/SKILL.md | Hard-pattern triage block (§3) |
| ctf-reverse/SKILL.md | Weird ELF + SUBLEQ + Church + exception-VM |
| ctf-pwn/SKILL.md | Hook ban; obstack FSOP; ORW openat trap; flag-as-write; Rust Vec |
| ctf-web/SKILL.md | Scanner ban for events; Node URL; qs limit; HPP; filter prepend |
| ctf-misc/SKILL.md | Pickle BUILD; Exception `__getitem__` AST escape |
| ctf-crypto/details.md | LCG-cycle→Coppersmith combo one-liner |
| ctf-forensics/details.md | CS beacon + SSLKEYLOG checklist |
| ctf-ai-ml/SKILL.md | Dual-gate + verify-side-channel prompts |
| ctf-writeup/SKILL.md | LMC{} + notes/<chal>.md |
| (hygiene) | Relocate pwnable-tw; fix missing script refs; sync LMC grep in reverse |

---

## 6. Sources note

Primary writeups fetched live: Midās eldar, Bronson HITCON, ret2school babyfile, CryptoCat wfw, kaiphait bop, Viblo simplewaf, heschl UNDER-CONSTRUCTION, Arkark SECCON, Sylvain GCM. Others via CTFtime/GitHub listings (HTTP 200 on repo roots where tested). Challenge files: prefer official public archives linked above; do not attack live CTF infra.
