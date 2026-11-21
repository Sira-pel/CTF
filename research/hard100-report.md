# Hard-100 CTF study — report (21 Nov 2026)

**Scope:** 100 challenges rated Hard/Insane by ctf42 (a heuristic — see Caveats; roughly 55–70 of the combined 128 are truly hard) from 2021–2026 (pwn 30, rev 24, web 15, crypto 12, forensics 8, misc/jail 6, AI/LLM 5). No overlap with the earlier 28-challenge study.
**Sources:** HITCON, SECCON, Google CTF, DiceCTF, PlaidCTF, 0CTF, corCTF, hxp, TSG, DEF CON Quals, UIUCTF, ImaginaryCTF, DownUnderCTF, SekaiCTF, plus HTB Global Benchmark (AI).
**Picking method:** I started from the ctf42.online index, which aggregates CTFtime. It has 1,754 challenges from 74 top events, and 734 of them have writeups. I took the ones rated Hard or Insane (plus a few strong Medium web and forensics ones) and checked each against the pack on the PR #3 branch.
**Links:** All 62 non-CTFtime links returned HTTP 200. All 38 CTFtime links loaded with a browser user-agent, and their titles match the challenges. Full list: `SOURCES.md`.
**Data:** `challenges.csv` has one row per challenge: trick, tools, tags, signal, and coverage.

## 1. Tool frequency (tools named in the 100 per-challenge notes)
| Category | Tools (count) | Pel's laptop lacks |
|---|---|---|
| pwn (30) | gdb/pwndbg 31, pwntools 19, **qemu-system 9**, d8/js shell 3, ROPgadget 2, clang (static exploit build) 2, bpftool 1 | qemu-system + kernel helpers (extract-vmlinux, vmlinux-to-elf), seccomp-tools, one_gadget, ROPgadget (unverified), patchelf/pwninit, libc-database |
| rev (24) | Ghidra 18, Python 7, z3 4, qemu/qemu-user 3, IDA/WinDbg 2 (Windows drivers), emulators (MAME, mGBA) 3, pyelftools 1, Unicorn 1, angr 1 | qemu-user-static, gdb-multiarch, emulators as needed |
| web (15) | Burp 15, real browser + DevTools 5, ysoserial/Java 2, php_filter_chain_generator 1 | Chromium/Playwright for local admin-bot testing (optional) |
| crypto (12) | **Sage 7**, Python 6, **fpylll 4**, randcrack 2, z3, sympy, pycryptodome | **Sage, fpylll**, (flatter optional) |
| forensics (8) | Wireshark 4, **tshark 2**, python-evtx/chainsaw, impacket-secretsdump, hashcat/john, gpp-decrypt, olevba, sox/numpy | **tshark, hashcat, python-evtx, oletools, impacket, sox** |
| misc/AI (11) | Python 8, pickletools/dis, browser 5 | — |

Across all 100: gdb 31, Python 25, Ghidra 19, pwntools 19, Burp 15, browser 12, **QEMU 11**, Sage 7, z3 5, fpylll 4, Wireshark 4.

## 2. Technique frequency and trends
**In our 100** (hand-bucketed from CSV tags; see `challenges.csv`): kernel (incl. eBPF/race/cross-cache) 9, VM/emulator escape or interpreter pwn ~5, browser engine 3, glibc heap (tcache/safe-linking/FSOP/TLS dtors) ~5–8, non-glibc runtimes (Rust, Lua, musl, OCaml, Nim) ~4, custom VM rev ~8, exotic architecture ~5, driver/kernel-module rev 3, shader/media/DWARF "logic elsewhere" 5, XSS/CSP/client-side chains ~5, parser/smuggling/type confusion 6, deserialization 2, lattices (CVP/HNP/LLL) 5, PRNG prediction ~5, oracle attacks 3, isogeny 1, Windows artifacts ~4, network decrypt 3, pickle/jail 5, LLM 5.

**Across the 734 tagged writeups (CTFtime-derived tags; counts are by period 2021–22 / 2023–24 / 2025–26):**
- **pwn:** rop 8/7/1, UAF 7/7/2, heap 4/5/1, shellcode 6/2/0, kernel 2/0/1. Classic glibc heap keeps fading, and VM escape went from 2 to 3. Most of the hard points now come from kernel, VM escape, and V8.
- **rev:** custom VM 1/4/3. Custom VMs are now the main hard-RE pattern. Rust is steady (3/3/2), z3 is up (4/7), and angr is down (2/0).
- **web:** xss 8/19/1, csp-bypass 3/10, sqli 3/6, prototype pollution 6/3/1. Hard web is now mostly **client-side chains** (CSP, bfcache, service workers, XS-leaks).
- **crypto:** rsa 19/8/3 (falling), lattice 9/8 (steady), isogeny 1/3/1, zero-knowledge 0/1/1. Lattices are the one crypto skill that keeps paying off.
- **misc:** pickle 0/3/1, pyjail, prompt-injection 0/1/2. LLM challenges went from none to common in 2025.
- 2025–26 has less writeup data so far (53 tagged), so treat the last column as a hint, not a measurement.

## 3. Triage cheat sheet: recognition signal → technique
| Signal in the handout | Likely technique |
|---|---|
| `run.sh` + `bzImage` + `.ko` | Kernel heap/race → spray (msg_msg / pipe_buffer / seq_ops) → modprobe_path / cred |
| Verifier patch / BPF syscall allowed | eBPF verifier range mismatch → OOB map R/W |
| `qemu-system` with custom `-device` | Device MMIO bug → host escape (reverse the QEMU binary) |
| `d8` + `.diff` | V8 addrOf/fakeObj; 2024+ also needs a sandbox escape |
| Bytecode blob + dispatch loop + `nc` | Custom VM: disassemble, then OOB into interpreter state |
| CET/IBT enabled (`endbr64` everywhere) | endbr64-gated ROP/JOP; check the CET flavor (software endbr check ≠ shadow stack; SROP only sometimes applies) |
| glibc ≥ 2.32 heap | safe-linking: leak heap, `(pos>>12)^ptr`; ≥2.34 no hooks → TLS dtors / FSOP |
| Links musl / is Rust / Lua / OCaml | Allocator- or runtime-specific: unchecked index, tag confusion, fake objects |
| Odd `e_machine` / ROM file | Emulator + Ghidra processor first |
| `.sys`/`.ko` as checker | IOCTL dispatch → input path |
| WebGL shaders / DVD image / DWARF-heavy ELF | Logic hidden in non-CPU code: extract and port to Python |
| Admin bot + strict CSP | bfcache, service worker, header-too-large, DOM clobbering, mXSS |
| Two servers / proxy in front | Smuggling, Content-Length mismatch, response splitting, HPP |
| Java endpoint (RMI/Hessian) | Deserialization; JDK-only gadget chains |
| ECDSA + odd nonce source | HNP / related-nonce lattice |
| Shamir/LWE with too few equations | CVP / embedding |
| `Math.random` / Python `random` | Predict state (z3 xorshift128+, MT19937 untemper) |
| `.evtx`, SAM/SYSTEM, Groups.xml | chainsaw/evtx_dump, secretsdump, gpp-decrypt |
| Encrypted pcap + provided/recovered keys or dump | SSLKEYLOG → tshark |
| `addaudithook`, code objects, pickle scanner | Jail via parser differential / CodeType / memo |
| LLM with secret | Prompt leak in another language/format; boundary spoof; tool abuse |

## 4. Gaps in the pack (PR #3 branch), ranked by impact for Pel
Coverage across the 100: **Covered 16, Partial 64, Gap 20** (CSV-derived). The pack is broad, so most misses are "mentioned but no quick path."
1. **Kernel + QEMU quick path in pwn (high).** Kernel material exists (`kernel*.md`), but there is no 5-line "unpack → debug → primitive ladder" entry, and **QEMU device escape is missing** (0 hits). Kernel challenges are the most common hard pwn.
2. **Browser/V8 exploitation (high for hard events, low for Pel now).** There's no addrOf/fakeObj path, no V8 sandbox (0 hits), and no SpiderMonkey (0 hits).
3. **Exotic-arch and "logic elsewhere" RE (high for RE).** DWARF VM (0 hits), DVD VM (0 hits), TILE-Gx, and Markov machines are missing. Shaders and printf-VMs are only partly covered.
4. **Client-side web chains (medium).** bfcache (0 hits), service workers (0 hits), response splitting (0 hits), and Popover/DOM clobbering (thin).
5. **Windows forensics artifacts (medium, cheap to fix).** GPP cpassword (0 hits); EVTX and SAM hives are thin.
6. Smaller gaps: Java Hessian (0 hits), `/proc/self/map_files` jail trick (0 hits), LLM agent/tool abuse (thin), CET/SROP pointer in the SKILL.md quick start.
Fixes for all of these are in `snippets/`. They total about 9 KB, have no source tags, and don't repeat PR #3.

## 5. Snippets
`snippets/solve-challenge.md`, `ctf-pwn.md`, `ctf-reverse.md`, `ctf-web.md`, `ctf-crypto.md`, `ctf-forensics.md`, `ctf-misc.md`, `ctf-ai-ml.md`. There's no osint, malware, or writeup snippet, because nothing new turned up for those.

## 6. Recommended laptop installs (Ubuntu; confirm with Pel before running)
```bash
# pwn / kernel
sudo apt install -y qemu-system-x86 qemu-user-static gdb-multiarch patchelf cpio
pipx install ropgadget && sudo gem install one_gadget seccomp-tools
pipx install git+https://github.com/marin-m/vmlinux-to-elf   # vmlinux from bzImage
git clone https://github.com/niklasb/libc-database ~/tools/libc-database
# crypto
sudo apt install -y python3-fpylll        # LLL/BKZ/CVP in Python
# Sage: easiest is docker:  docker pull sagemath/sagemath   (or: conda/mamba install -c conda-forge sage)
pip install --user randcrack
# forensics
sudo apt install -y tshark hashcat pngcheck sox
pipx install volatility3 && pipx install oletools && pipx install impacket && pip install --user python-evtx
sudo gem install zsteg
# stegseek: .deb from https://github.com/RickdeJager/stegseek/releases
pipx install name-that-hash
```
**Priority if time is short:** qemu-system-x86, patchelf, ROPgadget, one_gadget, seccomp-tools, and libc-database for RE/Pwn. After that, Sage (docker) and fpylll, then tshark and hashcat.

## 7. Practice queue: 14 challenges with public files, easiest first (RE/Pwn heavy)

*(babycmp dropped: easy XOR warmup, ~176 solves — ctf42 Hard label wrong; optional angr demo at most.)*

| # | Challenge | Diff (evidence) | Why | Files |
|---|---|---|---|---|
| 1 | UIUCTF 2022 odd_shell (pwn) | medium | Restricted-byte shellcode | github.com/sigpwny/UIUCTF-2022-Public |
| 2 | SECCON 2023 jumpout (rev) | easy–med (~154 solves) | Jump-table obfuscation + xor | github.com/SECCON/SECCON2023_online_CTF |
| 3 | SECCON 2021 kasu_bof (pwn) | medium | ret2dlresolve with no leak | github.com/SECCON/SECCON2021_online_CTF |
| 4 | SECCON 2022 eguite (rev) | easy (author: relatively easy Rust rev) | Rust reversing + constraint cleanup | SECCON2022_online_CTF |
| 5 | SECCON 2023 xuyao (rev) | medium | Pointer-struct obfuscation; clean decomp then invert xor chain (no z3) | SECCON2023_online_CTF |
| 6 | DiceCTF 2024 baby-talk (pwn) | hard | Off-by-null → House of Einherjar → tcache | github.com/dicegang/dicectf-quals-2024-challenges |
| 7 | PlaidCTF 2021 Plaidflix (pwn) | hard/insane | UAF + safe-linking | github.com/sajjadium/ctf-archives/tree/main/ctfs/PlaidCTF/2021/pwn/Plaidflix |
| 8 | SECCON 2023 selfcet (pwn) | hard | Software CET (`endbr64` gate): partial overwrite + constrained ROP (not SROP) | SECCON2023_online_CTF |
| 9 | corCTF 2021 vmquack (rev) | unverified | Write your first full VM disassembler | github.com/Crusaders-of-Rust/corCTF-2021-public-challenge-archive |
| 10 | 0CTF 2022 ezvm (pwn) | unverified | Same VM skill turned into an exploit | github.com/sajjadium/ctf-archives/tree/main/ctfs/0CTF/2022/pwn/ezvm |
| 11 | SECCON 2023 DataStore1 (pwn) | hard | Heap type confusion + feng shui | SECCON2023_online_CTF |
| 12 | TSG 2021 lkgit (pwn) | hard (unverified) | First kernel race (userfaultfd) | github.com/tsg-ut/tsgctf2021 |
| 13 | HITCON 2022 kernel / Wall Rose 2023 (pwn) | hard | UAF → modprobe_path; cross-cache | perfectblue writeup + HITCON repos |
| 14 | SECCON 2022 babypf (pwn) | hard/insane | eBPF verifier bug (stretch goal) | SECCON2022_online_CTF |

## Caveats
- The ctf42 Hard/Insane label is a heuristic (solve-rank + organizer label + agent judgment + event weight), not ground truth — it mislabeled SECCON babycmp as Hard (actually a 176-solve XOR warmup). Of the combined 128, roughly 55–70 are truly hard; ≥5 easy/beginner rows slipped into this set. Prefer solve counts / author tags when practicing.
- The tool counts come from the tools each writeup or solve uses. They undercount tools that are always present, like pwntools in pwn.
- The CTFtime/ctf42 tags are community-entered and sparse, so read the trends as direction only.
- "Covered" means the PR #3 branch has a usable path for the technique. "Partial" means it's mentioned but there's no quick recipe.
- Nothing was pushed or changed on GitHub or on Pel's laptop.
