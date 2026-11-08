# CTF

Working repo for CTF competitions. One folder per challenge, plus notes.

## Layout

```
CLAUDE.md          Competition rules and working guidelines
notes/             Solve notes, one markdown file per solved challenge
  practice_challenge/  Notes for ctf_practice/ challenges: <challenge>.md
ctf_practice/      Practice challenges, one folder per challenge
  <challenge>/     Challenge files, exploit scripts and solve artifacts
```

## Workflow

1. Create a folder named after the challenge (lowercase, underscores), e.g. `ctf_practice/heap_havoc/`.
2. Keep exploit scripts and solve artifacts in that folder.
3. After each solve, write `notes/practice_challenge/<challenge>.md`: category, target, bug, steps, flag.
4. Never commit flags, keys or tokens outside `notes/`, and never push them to a shared remote without team approval.

## Rules

See [CLAUDE.md](CLAUDE.md). Only attack official challenge targets.
