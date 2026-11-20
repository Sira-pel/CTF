# CTF skills — upstream drift check (2026-11-18)

## Objective

We maintain a locally tweaked copy of the CTF agent skills under
`.claude/skills/`. The originals come from
[ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills).

Goal of this check: confirm whether **our local improvements still "hold up"
(still gold)** against the author's **latest** push, i.e. that none of our
changes have been silently overwritten, duplicated, or made obsolete by
upstream — and to record where our copy now stands relative to the source.

## What we compared

- **Upstream ref:** `20d182d` (`git ls-remote HEAD`, authoritative latest),
  dated 2026-11-14, PR #125. Shallow-cloned to a scratch dir, verified the
  cloned HEAD equals the remote HEAD.
- **Local:** `.claude/skills/*` on branch `claude/hopeful-edison-2bju9s`.
- Method: `diff -rq` per skill dir, then per-file `diff`, header (`##`) set
  comparison, and keyword sweeps across all upstream `*.md`.

Upstream keeps skills at the repo root (`ctf-crypto/SKILL.md`); we keep them
under `.claude/skills/`. Every `SKILL.md` differs except `ctf-writeup`.

## Our three local improvements (what we changed)

1. **Tighter routing `description:` frontmatter** — rewrote the skill
   descriptions into a mutually-exclusive `"<area> only: … Use only when …
   Not for …"` form so the router picks one skill cleanly.
   Applied to: `ctf-ai-ml`, `ctf-crypto`, `ctf-forensics`, `ctf-malware`,
   `ctf-misc`, `ctf-osint`, `ctf-web`, `solve-challenge`.
   (`ctf-pwn`, `ctf-reverse`, `ctf-similar-search`, `ctf-writeup` already
   match upstream — upstream tightened those itself.)

2. **"Tool Availability Policy" section** — added to **every** skill: check
   whether a tool/pkg already exists before installing, and ask before
   installing anything new. Enforces the `CLAUDE.md` "ask before sudo,
   installs, or running unknown binaries" rule inside the skills themselves.

3. **"2026 refresh — techniques from the Lancang-Mekong retro" sections** —
   added to `ctf-crypto`, `ctf-forensics`, `ctf-pwn`, `ctf-reverse`,
   `ctf-web` (commit `294a70f`). General methodology only (House of Apple 2 /
   FSOP, version heap index, seccomp-tools, auto-ROP; emulate+symbolic-solve
   VMs, Go symbol recovery; flatter, Bleichenbacher/Minerva, GCM forbidden
   attack, black-box RSA meta; nested-stego autochain, KeePass CVE tooling,
   KDF/AEAD input-type checks; better-auth pre-account-hijacking CVEs).

## Verdict — do our improvements still hold up? YES (with one caveat)

All three are **additive and non-conflicting**. Upstream `20d182d` has adopted
**none** of them, so nothing we did was overwritten or lost:

| Improvement | Still gold? | Evidence |
|---|---|---|
| Tighter routing descriptions | ✅ Yes | Upstream still ships verbose `Provides… Use when…` descriptions for these skills. Our form is still unique and better for routing. |
| "Tool Availability Policy" | ✅ Yes, 100% unique | `grep -rl "Tool Availability Policy"` over upstream → **none**. No equivalent exists upstream. |
| "2026 refresh" sections | 🟡 Mostly | No section by that name upstream (no conflict), **but** upstream's #104 "Port content from 5 forks" now independently covers most of the underlying *techniques* (flatter, House of Apple 2/FSOP, seccomp-tools, garble Go, Bleichenbacher, GCM forbidden attack). Our concise "when to reach for it" framing + a few items (Minerva, better-auth, Lancang leads) are still not upstream. |

### Caveat: our copy sits on a stale base

Our skills predate upstream's big **#104 "Port content from 5 forks"**
expansion. Upstream `SKILL.md` files are now substantially larger and the old
`details.md` split (which we still carry in `ctf-crypto`, `ctf-forensics`,
`ctf-misc`) was consolidated into single files upstream:

| Skill | local `SKILL.md` | upstream `SKILL.md` |
|---|---|---|
| `ctf-misc` | 92 | 514 |
| `ctf-forensics` | 133 | 380 |
| `ctf-crypto` | 152 | 333 |
| `solve-challenge` | 72 | 230 |

(`ctf-pwn`, `ctf-reverse`, `ctf-web` are *larger* locally because that's where
our 2026-refresh + Tool Policy additions landed on a newer-ish base.)

So: our improvements are still valid and worth keeping, but they rest on an old
foundation — we're missing a lot of newer upstream content.

## Recommendation (not done in this PR)

Re-base onto latest upstream and re-apply the three improvements:
1. Pull `ljagiello/ctf-skills@20d182d` content into `.claude/skills/`.
2. Re-apply the tighter `description:` frontmatter.
3. Re-apply the "Tool Availability Policy" section to each skill.
4. Fold the still-unique bits of the 2026-refresh (Minerva, better-auth,
   Lancang-specific leads, the concise framing) into the expanded files;
   drop what upstream now covers to avoid duplication.

This PR only records the analysis — it does not change any skill content.
