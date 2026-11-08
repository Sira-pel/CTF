# babygame03 (picoCTF 2024, Binary Exploitation, Hard) — IN PROGRESS, blocked

Target: `nc chatelaine.cylabacademy.net 30624` (official instance, expires ~15 min)
Files: `ctf_practice/babygame/game` (32-bit, non-PIE, not stripped), `ctf_practice/babygame/flag.txt` (local dummy only)

## Static analysis (no execution yet)
- Map 30 rows x 90 cols, stored at `main` frame offset -0xa99. Player struct {row, col, lives} at -0xaa8, level at -0xaac, win counter at -0xc.
- Keys: `w/a/s/d` move, `l` + next byte sets the player glyph (written to current cell), `p` = solve_round (auto-walks to the end). Every key costs 1 life; lives reset to 50 per level. Moving onto `#` exits.
- Leaving a cell always writes `.` into it (no bounds checks on row/col, so out-of-map writes land in main's stack frame).
- `rand()` is unseeded and is used for obstacle placement (`rand() % level`).

## Win logic (main, after each key)
1. At (29,89): if `level != 4`, print "You win! Next level", counter++, level++, reset player and map.
2. Then, at (29,89): if `level == 5 && counter == 4`, call `win(&level)`, which prints `flag.txt`.

Check 1 and check 2 see the same values in the same iteration. Reaching the win branch needs level==5 at check 2, but that makes check 1 fire first, which resets the player. Level 4 is a dead end: at (29,89) the game skips advancing and never reaches level 5.
So the normal game can't reach `win()`. The only route found is memory corruption (writes to the frame, e.g. the return address at map offset 2717 = row 30, col 17). That needs 4 arbitrary bytes, and each move overwrites the cell you leave with `.`, so only the final cell keeps a chosen byte. Not solved.

## Status
Not solved. Possibly a broken challenge (win unreachable without memory corruption). Need to decide: report as a bug, or continue the memory-corruption route.

## Attempt 2 (offline reasoning, nothing run)
- `win(arg)` checks `*arg == 5`. If main's `print_map` return were redirected to `win`, the arg is the player pointer, so `player.row == 5` would print the flag.
- Problem: `print_map` re-pushes its return address on every call, so overwriting that slot doesn't stick. Main's own saved return slot and saved `ecx` (ebp-8 = map offset 2705, cell (30,5)) are stable, but writing them needs several arbitrary bytes. Each move writes `.` to the cell it leaves, so only the last written cell keeps a chosen byte.
- Idea under test: writes into the player struct itself (row/col slots at cells (-1,75..86)) can persist, because changing the struct redirects the next `.` write. Not verified.
- Needs empirical checking (local gdb/qemu run of the challenge binary, or remote). Not done yet.
