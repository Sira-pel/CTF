# CTF

Working repo for CTF competitions and practice.

## Layout

```
CLAUDE.md                     Competition rules and working guidelines
Lancang_Mekong_CTF_comp/      Lancang-Mekong CTF competition
  solved/<category>_<name>/   Solved challenges (files, exploit scripts, artifacts)
  unsolved/<category>_<name>/ Unsolved challenges (handout zips only)
  notes/<category>/           One note per challenge
    pwn/ rev/ crypto/ forensics/ web/ team/
ctf_practice/                 Practice challenges
  exercises/<category>/<challenge>/   pwn/ rev/ (+ _unsorted/)
  notes/<category>/<challenge>.md     pwn/ rev/
```

Category is whatever the note calls it (pwn, rev, crypto, forensics, web),
except the `Team_Work`-track challenges (intern, merge_emergency, moon_lover),
which are grouped under `team/`. Where both a raw working note and a cleaned-up
write-up exist, the raw one is suffixed `_raw`. Some unsolved challenges
(`naga_weave`, `treaty_of_six_gates`) have notes only, no files.

## Workflow

1. Create a folder named after the challenge (lowercase, underscores):
   `ctf_practice/exercises/pwn/heap_havoc/` or
   `Lancang_Mekong_CTF_comp/unsolved/rev_some_challenge/`.
2. Keep exploit scripts and solve artifacts in that folder.
3. After each solve (or when stopping on an unsolved one), write
   `ctf_practice/notes/<category>/<challenge>.md` or
   `Lancang_Mekong_CTF_comp/notes/<category>/<challenge>.md`: category,
   target, bug, steps, flag.
4. When a competition challenge is solved, move it from `unsolved/` to `solved/`.
5. Never commit flags, keys or tokens outside the notes folders, and never push
   them to a shared remote without team approval.

## Rules

See [CLAUDE.md](CLAUDE.md). Only attack official challenge targets.
