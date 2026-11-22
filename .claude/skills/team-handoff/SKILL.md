---
name: team-handoff
description: Writes a continuation handoff for one CTF challenge so a teammate (human or their own AI agent) can resume without redoing work. Use when the user says "hand off", "handoff", "pass to teammate", is stuck on a challenge, or is running out of tokens/budget mid-challenge.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash and Python 3.
allowed-tools: Bash Read Write Edit Glob Grep Task
metadata:
  user-invocable: "true"
  argument-hint: "[challenge-name]"
  author: Lukasz Jagiello
---

# CTF Challenge Handoff

Write a handoff document that lets someone else continue the challenge without repeating your work. Trigger it when the user asks to hand off, pass to a teammate, is stuck, or is out of tokens/budget.

## Output

Write to `notes/<challenge-slug>-handoff.md`. If `notes/<challenge-slug>.md` already exists (from `/solve-challenge` or `/ctf-writeup`), read it first and extend/reference it — do not duplicate its content.

## Agent procedure

1. **Gather, don't invent.** Collect facts from this conversation, the challenge folder (scripts, notes, dumps), and shell history snippets. Every claim in the handoff must come from something actually observed. If you cannot verify a statement from artifacts or the transcript, mark it **UNVERIFIED** — never present a guess as a result.
2. **Strip secrets** unrelated to the challenge (API tokens, credentials, unrelated flags) — the handoff goes to a teammate.
3. **Keep it short**: aim for under one page plus code blocks. A teammate should reach your current state in under 5 minutes.
4. **End with a ready-to-pause prompt**: a short block the teammate can paste into their own AI agent to resume (see template's last section).

## Template

```markdown
# Handoff: <challenge-name>

## Challenge
Name, category, points, files (paths), remote host:port, flag format `LMC{...}`.

## Status
One line: solved / partial / stuck — time spent.

## Answer
Flag or candidate flags; whether each was submitted/verified.

## Key findings
Confirmed facts with evidence: offsets, addresses, keys, checksec output,
libc version, file types, endpoint behavior. One line each.

## Tried and failed
Each: what was tried, the exact command/payload, the result, and why it's
ruled out. The reader skips these unless a stated reason is wrong.

## Current hypothesis
What's being tested, why, how far it got, and the next command to run.

## Open questions
Unknowns worth checking (unverified assumptions, missing info).

## Reproduce
Env setup, tool versions, file paths, solve script path (`solve.py`), and the
exact commands to reach the current state in under 5 minutes.

## Next steps (ranked)
1. …

## Artifacts
Paths to scripts, dumps, decompiled snippets, pcaps, notes.

## Resume prompt (paste into your agent)
"Continue <challenge-name> (category). Read notes/<challenge>-handoff.md
first: key findings are confirmed, the tried-and-failed list is ruled out —
don't retry it unless a stated reason is wrong. Current hypothesis: …
Next step: … Flag format LMC{...}."
```

## Receiving a handoff

When continuing someone else's challenge from a handoff:

1. **Read the handoff first**, then the artifacts it lists — not the raw challenge files.
2. **Verify key findings quickly** (re-run one checksec/offset/leak check) before building on them; anything marked UNVERIFIED needs its own confirmation.
3. **Do not retry the tried-and-failed list** unless you believe a stated reason is wrong — and if you prove one wrong, update the handoff.
4. Follow the project rules in `CLAUDE.md` (they apply to the teammate's agent too).

## Example

See [example-handoff.md](example-handoff.md) for a filled-in sample (fictional challenge, clearly labeled).
