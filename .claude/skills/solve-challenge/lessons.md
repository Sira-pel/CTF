# Lessons from our own solves

Process lessons distilled from past solved and stuck challenges. General only: no flags, hosts or event-specific details.

## Stop-loss and pivoting
- **Re-run recon after about 30 minutes without progress.** Re-read the description, list what you assumed, and test the assumption that is cheapest to check. Stalls usually come from a wrong assumption, not a missing exploit.
- **Do not re-verify what is already proven.** Several long stalls were repeated sessions re-checking the same ruled-out ideas. Keep a short "ruled out, with evidence" list in the note and read it before each new session.
- **After two sessions with no new lead, change surface** (another category, another artifact, another file) or hand the challenge to a teammate.
- **The description often names the intended weakness** (a "mistake" or "leak" in the text). Re-read it before building tooling.
- **Decoy flags exist.** If several flag-like strings turn up, do not submit them all. Work out which one the intended workflow produces. A platform rejection means the real check lives elsewhere (often a remote validator).

## Testing discipline
- **Validate any emulator, decoder or solver against real program output before trusting it for search.** A wrong opcode table or wrong buffering model wastes hours.
- **Use exact arithmetic** (fractions, integers, `sympy`/`Fraction`) for linear systems. Floating-point least squares gave answers that were off by a few units.
- **Check the negative control.** If a solution is forced to zero, or every input gives the same output, the model is wrong, not the data.
- **Test locally first** (patched copy, replica, debugger), then run the proven chain once against the official target.

## Remote services
- Many services reset state on disconnect or drop idle connections. Run the whole chain in one script with no pauses, or hold the socket open from a detached process.
- Pipes can hide buffered output locally (a write appears only after the process exits). Read directly from the socket on the remote.
- Per-connection state (keys, work orders, desks) changes each time. Log what each session produced before you reconnect.
- Stay inside the request budget. Plan probes offline, then spend as few as possible.

## Notes hygiene
- Record per attempt: hypothesis, one cheap test, result, and what it rules out.
- Write a solve note immediately, even for partial progress, so the next session starts from facts.
