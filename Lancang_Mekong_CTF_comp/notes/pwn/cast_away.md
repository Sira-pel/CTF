# Cast Away (challenge 028, PWN, 456 pts, author Cyrus)

**Target:** `nc 47.131.225.172 19606` (official challenge host)
**Binary:** `Lancang_Mekong_CTF_comp/solved/pwn_cast_away/cast_away` — x86-64 PIE, stripped, C++ (libstdc++), dynamically linked. sha256 `6481977c2b4bf5090e4262a25b6f651b47073fe739186ed299567e1730e485a4`
**Flag:** `LMC{paperwork_was_fine_the_cast_was_not}`

## Status

Solved. The exports directory only contains the three public documents. The
flag is the file `/run/challenge/flag` (the service's working directory is
`/run/challenge`). Reading it required code execution: the menu never lists
that directory.

Guessed (all "not present", 18 names total): `restricted_survey.csv`, `survey_restricted.csv`,
`restricted.csv`, `survey.csv`, `flag.txt`, `survey_full.csv`, `restricted_sample.csv`,
`private_sample.csv`, `full_survey.csv`, `private.csv`, `secret.csv`, `restricted_export.csv`,
`internal.csv`, `confidential.csv`, `restricted_data.csv`, `survey_private.csv`,
`classified.csv`, `flag.csv`. Stopped guessing here: further name probing is dictionary
probing against the live host, which the CTF rules discourage.

Documents that are readable and contain nothing useful: `readme.txt`
("Mekong River Survey Office - export service readme."), `manifest.csv`
(2 river rows), `public_sample.csv` (3 numeric rows).

## Program model (from disassembly)

Menu commands dispatch in `main` (`0x3bbf`):

| Command | Handler | Notes |
|---|---|---|
| `UNLOCK <hex16>` | `0x26d6` | Binary-search oracle: prints `higher`/`lower`/`equal`, budget 100 per connection. Sets `0x80e0`. |
| `SURVEY` / `SWITCH` | `0x288d` / `0x29c5` | Needs unlock. Create survey (0x58) / export (0x48) object, mode 1/2. |
| `EDIT <idx> <hex16>` | `0x2b85` | Writes qword `obj+8+8*idx` of the active object (`0x8178`). Prints previous value. **No mode check, no bounds besides idx 0..7.** |
| `PREPARE_EXPORT <doc>` | `0x2d0d` | Allowlist check (`0x257a`: readme.txt, manifest.csv, public_sample.csv). Name = `/srv/survey/exports/<doc>`, size = file size, hash at `obj+0x38`. |
| `RUN` | `0x31ff` | Recomputes hash (`0x24dc`, FNV-1a based, key `0x80d0`), fopen, fread `min(size,0x1000)`, then realpath check (`0x30e8`). Inside export dir: prints content. Outside: prints "redacted" and sets `0x8184`. |
| `NOTE_NEW/FREE/WRITE/WRITE3/READ` | `0x3488`, `0x35ad`, `0x3669`, `0x3839`, `0x3ab8` | Gated by `0x8184` (set only by RUN's redacted branch). 24 slots at `0x81a0`. `NOTE_FREE` does not clear the slot, so use-after-free read/write is possible. |
| `PROBE <hex16>` | `0x2f81` | Hamming similarity against `0x80d0`. Not needed (see below). |

Export object layout (`0x48` bytes, vtable at +0):
- `+0x08` std::string name (ptr, len, cap/SSO)
- `+0x28` size
- `+0x30` `counter ^ (base+0x8080)`
- `+0x38` hash
- `+0x40` counter

## Solve chain (verified remotely)

1. **UNLOCK** by binary search on the 64-bit target. About 63 queries. Budget 100 per connection. Unlock state is per-connection (verified: a new connection is locked again).
2. **SURVEY, SWITCH, PREPARE_EXPORT readme.txt** → export object with a legit hash.
3. **Leaks via EDIT** (write 0, read `previous`, restore):
   - `idx5 ^ counter = base+0x8080` gives the PIE base (page-aligned, verified).
   - The hash key `K = 0x80d0` is recoverable without PROBE: `K = H ^ FNV(name) ^ FNV8(size) ^ FNV8(counter)`. Verified: the same K comes out for readme.txt and manifest.csv.
4. **Ledger unlock:** EDIT the name ptr to `base+0x318` (the `.interp` string `/lib64/ld-linux-x86-64.so.2`, which exists and is outside the export dir), set len/hash, then RUN. Prints "redacted" and sets `0x8184`, which unlocks NOTE_*.
5. **Exact heap address of a note** via tcache safe-linking: NOTE_NEW ×2 (128), NOTE_FREE both, then `NOTE_READ(b,0) = (b>>12) ^ a` and `NOTE_READ(a,0) = a>>12`, so `a = v ^ pa` (self-consistency checked). Re-allocating twice gives id 3 = `a`.
6. **Arbitrary export name:** write the doc path into note 3, EDIT name ptr = `a`, len, size, and a recomputed hash, then RUN. Verified: readme.txt content printed from the heap-placed path.
7. Step 6 with a candidate name: "export path unreadable" means the file does not exist. Content means success.

Light tests that passed: hash-key consistency across two docs; PIE base alignment; the redacted branch unlocking notes; the heap-placed name reading readme.txt.

## Re-verification (2026-11-11, independent)

Re-derived and re-verified the whole chain from scratch with a Ghidra decompile +
a local replica (binary run under `unshare -rm` with `/srv/survey/exports` bind-mounted,
containing a fake non-allowlisted `restricted_survey.csv`). The exploit reads the
non-allowlisted file and prints its contents end-to-end, both locally (FLAG recovered
from the fake file) and remotely (readme/manifest/public_sample read via the arbitrary
heap-placed path; delta self-calibrates against readme each run).

- Working solver: `Lancang_Mekong_CTF_comp/solved/pwn_cast_away/solve.py` (pwntools).
  - `python3 solve.py 47.131.225.172:19606 <name-or-file>` — tries the given filename(s)
    under `/srv/survey/exports/`, prints contents on a hit, `unreadable` = not present.
  - With no 3rd arg it parses manifest + a small default candidate list.
- Cleaner ledger-unlock than /etc/hostname: point the name at the in-binary `.interp`
  string (`base+0x318`, `/lib64/ld-linux-x86-64.so.2`) — always present, outside exports.
- Existence oracle confirmed: INSIDE→content, OUTSIDE→`redacted` + byte count (so outside
  files are readable but the *content* is withheld by the realpath guard), MISSING→`unreadable`.
  Probed common flag paths (`/flag*`, `/root/flag*`, `/srv/**/flag*`, exports/`flag*`): all MISSING.
  `/srv/survey/exports` and `/srv/survey` exist (dirs). `/etc/debian_version`=6 bytes → Debian 12 → glibc 2.36.

## Why the export directory was a dead end

`/srv/survey/exports` really only contains `readme.txt`, `manifest.csv`, and
`public_sample.csv`. The flag is not an export. It is `/run/challenge/flag`,
which the menu cannot list. Code execution was required; the chain is below.

## RCE that read the flag

Remote libc is glibc with tcache safe-linking (stdout object at libc+`0x1d4760`,
`system` at `0x4c490`, `__environ` at `0x1db320`). Gadgets used, all relative to
libc: `pop rdi; ret` `0x277e5`, `pop rsi; ret` `0x28f99`, `pop rax; ret` `0x3f197`,
`pop rdx; pop rbx; ret` `0x85325`, `pop rsp; ret` `0x2746a`, `syscall; ret` `0x86172`.

1. Poison a fresh tcache bin onto the real stdout `FILE` (size 256, after the
   size-128 bin was already used). Set flags to `0xfbad1800` and point
   `write_base`/`write_ptr` at the target so the next printf flushes that range.
2. Walk the vtable to the ELF header, or just subtract `0x1d4760` from the
   leaked stdout pointer. Read `__environ`, then scan the stack for the saved
   return `pie+0x415e` (the instruction after `call NOTE_WRITE3`).
3. A 768-byte note allocated at that slot+8 covers the return address.
   `NOTE_WRITE3` at offset -8 overwrites it. The menu parser clobbers the
   caller's stack between commands, so the chain itself lives on a 1024-byte
   heap note and the return slot only does `pop rsp` to it.
4. Restore the original stdout `FILE` first. `puts` dies on the leak-mode flags.
   `system` at `0x4c490` is a wrapper that blocks in `do_system`; use raw
   syscalls instead. Open fds 3 and 4 are the socat sockets, so the next
   `open` is fd 5.
5. `readlink("/proc/self/cwd")` returned `/run/challenge`. `getdents` of that
   directory listed `flag`. `open` + `read` + `write` printed the flag.

## Scripts (scratchpad, not in repo)

- `/tmp/claude-1000/-home-sira--claude-spares-spare-NUmv5C/8fdb3009-3a48-4c68-9a8d-0234676a76d7/scratchpad/cast.py` — socket client, FNV helpers
- `.../scratchpad/chain.py` — phases 1–5 (unlock → leaks → ledger → note address → readme verification)
- `.../scratchpad/chain2.py` — phases 1–5 plus the candidate-name probe loop
- Logs: `.../scratchpad/chain_session.log`, `.../scratchpad/session.log`

## Tools note

The remote service drops idle connections, so the whole chain has to run in one script with no pauses. A dropped connection resets the unlock state.

## Independent re-verification (2026-11-11, second pass)

Rebuilt the same class of stack-pivot ROP chain from scratch in a separate pass (local
`debian:bookworm` Docker replica matching glibc `2.36-9+deb12u14` exactly, confirmed via
`_IO_2_1_stdout_`/`environ` symbol offsets) and validated a plain-syscall arbitrary-file-read
primitive (`open`+`read`+`write`, no ROP needed for `puts`) against known-content files
locally before touching the remote. Re-read `/run/challenge/flag` directly on the real host
with this independently-built chain and got the identical flag:
`LMC{paperwork_was_fine_the_cast_was_not}`. Also swept `/`, `/srv/survey/exports`,
`/srv/survey`, `/srv`, `/home`, `/root`, `/opt` via `getdents64` before finding the note
above already had the answer — confirms the export directory genuinely never contained it;
`/run/challenge` (the service's cwd) was the only place it lived.
Scripts: `readfile_template.py` (generic arbitrary-path reader), `listdir_*.py` (generic
directory lister), both proven against the local replica in `replica/` first.
