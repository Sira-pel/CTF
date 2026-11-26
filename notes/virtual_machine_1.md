# Virtual Machine 1 (picoCTF 2023, rev, hard) — SOLVED

Flag: `academy{m0r3_g34r5_3g4d_601f2760}`

## Challenge
COLLADA `.dae` (LeoCAD export) of a LEGO Technic gear machine. Red axle = input, blue axle = output.
Checker: "If the input is N, what is the output?" Wrong answer => 6 min cooldown.

## Solve
- Parse `<visual_scene>` nodes: part id (geometry url) + 4x4 matrix + material. One Red and one Blue part (axle 32073).
- Part ids: 3647=8T, 4019=16T, 3648b=24T, 3649=40T, 32270=12T double bevel, 6589=12T bevel,
  **6573 = differential** (housing 24T; 12T bevels inside: 2 suns on the diff axis + 1 planet). Axles 3704/4519/32073/44294/3707 (length 2/3/5/7/8).
- Gear axis = local Y; axle axis = local X. Rigid bodies = gears on an axle line (union-find). Some gears sit ~3.5 LDU past the axle end, so treat them as mounted. Gears with no axle are idlers (supporting structure was removed).
- Spur mesh: parallel, coplanar, centre distance ≈ 1.25·(Ta+Tb) LDU. Overlap is fine (hint), but a gap of +4.9 (40T 53 ↔ 24T 56) is NOT a mesh, and including it makes the system inconsistent.
- Bevel mesh: perpendicular axes, d≈25. Ratio ±1; take the sign from geometry (velocity at the contact point).
- Differential: housing = (sun1 + sun2)/2, with each sun projected onto the diff axis.
- Solve the linear system: 4 diffs give ×7, ×133, ×1337, then ×7·1337 = **9359**.
- Geometry gave −9359 (output reversed relative to the same world axis), but the checker wanted **+9359·input**.
  Lesson: the checker ignores direction; if the sign is ambiguous, check the magnitude pattern first.
