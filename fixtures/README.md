# Fixtures — real artifacts, and where each one came from

Every fixture here is a chain (or a sealed set) that exists in an owner repo,
at the commit named below. None of them was invented here. Where an owner
commits no chain file at all, that is said plainly, and the fixture was
produced by RUNNING THAT OWNER'S OWN CODE — which is a weaker guarantee than a
committed artifact and is labelled as such rather than dressed up as one.

A synthetic fixture proves only that this implementation agrees with itself.
That is the defect the 2026-10 census exists to stop.

| fixture | dialect | owner | path in the owner repo | commit | kind |
|---|---|---|---|---|---|
| `chrono-organ-seal-chain.jsonl` | `chrono-organ/1` | quilt-chrono | `examples/tide/outputs/ledger.jsonl` (the 4-entry sheet in `examples/ed25519-cross-repo-proof.mjs`) | `d7492d0672ecc8d08f8128e4055102f3d624222a` | derived — see below |
| `chrono-ed25519-checkpoint.json` | — | quilt-chrono | `examples/receipts/ed25519-cross-repo-proof.json` | `d7492d0672ecc8d08f8128e4055102f3d624222a` | **committed verbatim** |
| `quilt-gpu-lab-probes.jsonl` | `sha256-pyjson-probe` | quilt-gpu-lab | `probes.jsonl` (215 rows) | main | **committed verbatim** |
| `quilt-rust-compat-golden.json` | `quilt-cell-ledger/1` | quilt-rust | `compat/golden.json` | `ef3c3799047ca19d7046eeecd8c4754f69a697eb` | **committed verbatim** |
| `quilt-rust-go-golden.json` | `quilt-edge/1` | quilt-rust | `bindings/go/golden.json` | `ef3c3799047ca19d7046eeecd8c4754f69a697eb` | **committed verbatim** |
| `quilt-rust-edge-fahrenheit.jsonl` | `quilt-edge/1` | quilt-rust | `bindings/go/golden.json` → `edges.fahrenheit` | `ef3c3799047ca19d7046eeecd8c4754f69a697eb` | extracted, byte-identical |
| `moth-ledger-chain.jsonl` | `moth-ledger/1` | moth-ledger | (none — see below) | main | derived by running the owner |
| `pong-quilt-doctor-wal.jsonl` | `quilt-doctor-wal` | pong-quilt | (none — see below) | main | derived by running the owner |
| `jev-quilt-signed-receipt-vectors.json` | envelope | jev-quilt | `vectors/signed_receipt_vectors.json` | main | **committed verbatim** |

## The two derived-from-running-the-owner cases

**chrono-organ-seal-chain.jsonl** — quilt-chrono commits no `.chain.jsonl`
sidecar (it writes them beside a ledger at runtime and the tide example keeps
only the ledger). The fixture is the output of quilt-chrono's OWN
`buildChain()` over the 4-entry sheet hard-coded in its committed
`examples/ed25519-cross-repo-proof.mjs`. It is not merely "what that code
produced": its tip is
`cf0fbce20e02e7404943c7a59961969f5e8cd9c8fa50a610b7271890b7a42f6d`, which is
the `hash` field of the Ed25519 **signed checkpoint** in
`chrono-ed25519-checkpoint.json`. That signature verifies under the public
key published in the same receipt. So this chain is pinned by cryptography,
not by trust: if a byte of it were wrong, the tip would not match a signature
somebody made.

**moth-ledger-chain.jsonl** — moth-ledger commits no ledger file; its own tests
build one in a tmpdir. This fixture was written by calling moth-ledger's own
`Ledger.append_finding/append_verdict/append_refusal`, and moth-ledger's own
`verify_chain()` returns `true` on it. It is therefore two independent
implementations agreeing, not one implementation agreeing with itself.

**pong-quilt-doctor-wal.jsonl** — pong-quilt commits only stone-v1
checkpoints; the quilt-doctor WAL is emitted by its committed demo driver
`node tools/wal-export.js` (fixed inputs, no RNG). The fixture is that
command's stdout, verified byte-identical across repeated runs.

## What is deliberately NOT here

`quilt-rust/compat/golden.json` ships its `op_e_chain.entries` as an
**abridgement** — `seq`, `prev_hash`, `hash` and nothing else. The rule
(`hash = sha256(ryū canonical_json(entry minus hash))`) seals the WHOLE
`LedgerEntry`, and the repo commits no full entry anywhere. So the cell-ledger
**row seal cannot be re-derived from committed artifacts** and this module does
not claim to. What IS pinned, and is, is the canonical form (the committed
genesis commit `470bc527…` and all three committed edge-provenance vectors
reproduce exactly), the per-cell genesis law, and the linkage chain. The test
suite asserts that limit explicitly instead of quietly passing.
