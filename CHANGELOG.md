# Changelog

All notable changes to this project, newest first. Entries are grouped by UTC date.

## 2026-10-20

### Complete the blockchain core (Epic 2) — 14:21 UTC
**Summary:** The blockchain core is finished: it checks consensus proofs, saves the chain to disk and reloads it safely, and is proven to detect tampering.
**Details:** Validation now enforces Proof-of-Work difficulty and the PBFT voting quorum, with votes signed separately from block proposals so they cannot be forged by replay. The chain is stored as JSON or SQLite and is fully re-checked at startup; a damaged, tampered or missing chain stops the node instead of being trusted. A tamper-detection test suite shows which defence catches each attack.

## 2026-10-10

### Add chain validation and harden the blockchain core — 17:27 UTC
**Summary:** The system can now check a whole chain for tampering, and the core was made safer against malformed or hostile data.
**Details:** Adds chain validation (hash, link, Merkle, signatures, structure) with full and incremental modes. After a review: strict data encoding, read-only blocks and records, one-form signatures, stronger key checks, atomic key files, atomic chain append, role-typed keys, and ~130 new tests.
