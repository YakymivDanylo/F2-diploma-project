# Changelog

All notable changes to this project, newest first. Entries are grouped by UTC date.

## 2026-11-13

### Protect validator addresses with signed registration — 15:28 UTC
**Summary:** Nobody can redirect another validator's network address anymore; only the validator itself can announce where it lives.
**Details:** Registering a validator node now requires a fresh registration signed with that validator's own key. Attempts to move a validator to a foreign address, replay an old registration or use a wrong key are rejected, and unsigned validator entries passed along by other nodes are ignored. Ordinary non-validator peers are unchanged and still carry no voting weight.

### Add chain synchronization and fork resolution — 15:28 UTC
**Summary:** Nodes now catch up with each other, choose the same winning chain after a fork, and repair a tampered local copy from their peers.
**Details:** A node checks with its peers before it starts serving (with a time limit, so nodes started together never wait forever), then keeps syncing. Only fully re-checked chains are adopted. Proof-of-Work forks resolve the same way on every node; conflicting finalized PBFT blocks are reported as a safety violation instead of being guessed. A tampered chain is replaced, never by a shorter one.

### Make one component the single owner of the chain — 15:28 UTC
**Summary:** All changes to a node's blockchain now go through one guarded place, so simultaneous updates can never corrupt it.
**Details:** Adding a new block and swapping in a whole chain from a peer can no longer interleave: each runs on its own, and the saved copy, the validity status and the document index always match the chain in memory. Blocks handed out to the rest of the system are read-only. Over a hundred randomized timing scenarios confirm no update is lost.

## 2026-10-20

### Complete the blockchain core (Epic 2) — 14:21 UTC
**Summary:** The blockchain core is finished: it checks consensus proofs, saves the chain to disk and reloads it safely, and is proven to detect tampering.
**Details:** Validation now enforces Proof-of-Work difficulty and the PBFT voting quorum, with votes signed separately from block proposals so they cannot be forged by replay. The chain is stored as JSON or SQLite and is fully re-checked at startup; a damaged, tampered or missing chain stops the node instead of being trusted. A tamper-detection test suite shows which defence catches each attack.

## 2026-10-10

### Add chain validation and harden the blockchain core — 17:27 UTC
**Summary:** The system can now check a whole chain for tampering, and the core was made safer against malformed or hostile data.
**Details:** Adds chain validation (hash, link, Merkle, signatures, structure) with full and incremental modes. After a review: strict data encoding, read-only blocks and records, one-form signatures, stronger key checks, atomic key files, atomic chain append, role-typed keys, and ~130 new tests.
