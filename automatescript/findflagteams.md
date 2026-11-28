---
description: Solve multiple CTF challenges of the same category in parallel, reporting each as it finishes
argument-hint: [opus|sonnet|haiku] <category> <challenge-folder-1> <challenge-folder-2> [...]
---

Input: `$ARGUMENTS`

Parse arguments:
- If the first token is `opus`, `sonnet`, or `haiku`, use it as **model**; otherwise default **model** to `sonnet`.
- Next token is **category** (e.g., `web`, `pwn`, `crypto`, `reverse`, `forensics`, `misc`).
- Remaining tokens are **challenge subfolders**. If missing, ask for `[model] <category> <challenge-folders...>`.

1. **Quick Check:** Verify each challenge subfolder exists. Do not read challenge files or start solving in this main session.
2. **Launch Background Solvers:** Spawn **one background subagent per challenge subfolder** (`run_in_background: true`, `model: "<model>"`). Give each subagent only:
   - Its **category** (`<category>`) and exact **challenge subfolder** (`<subfolder>`).
   - **Isolation rule:** Work strictly inside `<subfolder>` (`cd <subfolder>`). Do **not** read or write files in the parent directory, sibling challenge folders, or shared `/tmp` names (prefix any temp files with the subfolder name).
   - **Goal:** Solve the challenge, verify the flag, and return: `Challenge`, `Status (SOLVED/UNSOLVED)`, `Flag`, `1-2 sentence summary`, and `solve script path` (or main blocker if unsolved).
3. **Report as They Finish:** Do **not** wait for all solvers to complete. As each background subagent finishes, immediately report its `Challenge | Status | Flag | Summary` to the user. Once the last one finishes, print a short final recap.
