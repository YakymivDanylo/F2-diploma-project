# Changelog

All notable changes to this project, newest first. Entries are grouped by UTC date.

## 2026-10-10

### Add chain validation and harden the blockchain core — 17:27 UTC
**Summary:** The system can now check a whole chain for tampering, and the core was made safer against malformed or hostile data.
**Details:** Adds chain validation (hash, link, Merkle, signatures, structure) with full and incremental modes. After a review: strict data encoding, read-only blocks and records, one-form signatures, stronger key checks, atomic key files, atomic chain append, role-typed keys, and ~130 new tests.
