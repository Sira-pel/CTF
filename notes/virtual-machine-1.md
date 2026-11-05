# Virtual Machine 1 (picoCTF 2023, Reverse Engineering, Hard)

**Flag:** `academy{m0r3_g34r5_3g4d_601f2760}`

## Challenge
- `vm/Virtual-Machine-1.zip` contains `VirtualMachine1.dae`, a LeoCAD (LEGO Technic) COLLADA model. It has 127 parts and the supporting structure is removed.
- Red axle is the input, blue axle is the output. The server (`nc xebec.cylabacademy.net 26645`) asks: "If the input to the machine is N, what is the output?"

## Solution
1. Parsed the DAE (scene nodes = part type + 4x4 transform, in LDU).
   - Part IDs: 3647=8T, 4019=16T, 3648b=24T, 3649=40T, 6589=12T bevel, 32270=12T double bevel, 6573=differential (24T casing gear), plus axles (32073, 44294, 3704, 4519, 3707).
2. Built the kinematic graph.
   - Rigid shafts: gears on the same axis within an axle's span.
   - Spur mesh: parallel axes, same plane, centre distance ≈ 1.25·(n1+n2) LDU. Within tolerance, tooth-overlap meshes count as meshed.
   - Bevel mesh: perpendicular axes that intersect, both at ~18 LDU from the apex. The two rotate oppositely about their outward axes.
   - Differential: ω_casing = (ω_L + ω_R) / 2.
3. One pair, G40 (53) and G24 (56), sits tip-to-tip at 84.9 vs 80 pitch distance. Treating it as meshed makes the system over-constrained, so the whole machine locks. Treating it as not meshed gives a consistent system.
4. Solved the linear system exactly with Fractions.
   - Differential casing speeds: 7, 133, 1337, 9359 (× input).
   - **output = 9359 × input**, opposite rotation direction.
5. Answer for input 12352 was 12352 × 9359 = 115602368, which the server accepted as positive.

## Re-check (2026-11-05)
- Screenshot shows the instance at `xebec.cylabacademy.net 11546` (notes above say 26645; the instance changed).
- The zip's 127 parts and part IDs match the notes.
- One probe sent `12352` before reading the prompt. The server replied "That's not correct" and set a 360 s lockout. Read the question first, then answer.
- The question is random per session. Last seen: input 10310, so the expected answer is 10310 × 9359 = 96491290. This is not yet verified against the server.

## Lessons
- Use exact rational arithmetic. Floating-point `lstsq` was ill-conditioned and gave ~9362 instead of 9359.
- Differentials are linear constraints; free spider gears are expected nullspace.
- Sanity check: a solution that is forced to 0 means a bad mesh assumption.
