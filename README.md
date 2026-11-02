# CTF

Working repo for CTF competitions. One folder per challenge, plus notes.

## Layout

```
CLAUDE.md          Competition rules and working guidelines
notes/             One markdown file per solved challenge: <challenge>.md
<challenge>/       Challenge files, exploit scripts and solve artifacts
```

## Workflow

1. Create a folder named after the challenge (lowercase, underscores), e.g. `heap_havoc/`.
2. Keep exploit scripts and solve artifacts in that folder.
3. After each solve, write `notes/<challenge>.md`: category, target, bug, steps, flag.
4. Never commit flags, keys or tokens outside `notes/`, and never push them to a shared remote without team approval.

## Rules

See [CLAUDE.md](CLAUDE.md). Only attack official challenge targets.
