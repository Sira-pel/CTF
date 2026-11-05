# solfire (picoCTF-style Solana challenge, binary exploitation, hard)

Target: `nc chatelaine.cylabacademy.net 14318` (official challenge target only).
Files: `solfire/solfire.tar.gz` (src/main.rs harness, solfire.so BPF vault program, Dockerfile).

Status: NOT SOLVED. Analysis done offline; no exploit sent yet.

## How the harness works
1. Client sends `len` + ELF of our solve program (BPF `.so`).
2. Server deploys solfire.so (vault) and solve.so with random program IDs, prints pubkeys.
3. Server funds user with 10 lamports and the vault PDA `find_program_address(["vault"])` with 1,000,000.
4. Client sends account metas + instruction data; server runs solve program with them.
5. If `user_bal > 50000`, server prints the flag.

## solfire.so (reverse-engineered from eBPF)
Dispatcher: first 4 bytes of instruction data = op (0 create, 1 deposit, 2 withdraw). ka[0] must be the Clock sysvar (base58 contains "C1ock"); ka[1] must be the system program (all-zero key); ka[2] must be owned by solfire (the "table"); ka[3] must be a signer (user); ka[4] is the vault/pool account.

Table entries are 16 bytes at `table.data + idx*16` (idx = u32 @ data[4], must be < 641); amount = u32 @ data[8] (must be nonzero).
- `deposit`: system transfer ka[3] -> ka[4] of amount, then `entry.B (+8) += amount`.
- `withdraw`: system transfer ka[4] -> ka[3] of amount (ka[4] signed with PDA seeds `"vault" || data[12]`), then `entry.A (+0) += amount` and assert `B >= A`.
- `create`: create_account for ka[2] (10240 bytes, owner solfire) signed by PDA seed `[data[4]]`.

Key observation: the withdraw PDA seed is the 6-byte string `"vault" || data[12]`. The bump-seed version of `find_program_address(["vault"])` hashes the same bytes, so `data[12]` = the vault's bump makes ka[4] the real 1,000,000-lamport vault.

## Exploit idea (not yet verified against the server)
- Single instruction is not enough: deposit must raise `B` before withdraw can pay out.
- Self-deposit (ka[3] == ka[4] == user) raises `B` without losing lamports.
- Doubling loop: deposit U, withdraw U, U -> 2U. Starting at 10 lamports, 13 rounds gives 81,920 > 50,000.
- Needs a custom solve program (BPF) that performs these CPIs in one transaction, since the server runs only one solve instruction. Table must be created in the same transaction.

## Blockers / to do
- No BPF toolchain here (no clang; rustc has no bpfel-unknown-none std installed). Need to install one (`rustup target add bpfel-unknown-none` or apt clang/lld). Not yet approved.
- Program and PDA pubkeys are random per connection, so bump values must be computed after the server prints them.
