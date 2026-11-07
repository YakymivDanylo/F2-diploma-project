# Test Cases: Blockchain Core Engine (Epic 2)

> Based on [PRD](../PRD.md) and [Use Cases](../use-cases/blockchain_core_use_cases.md)

This document covers the in-process blockchain library: document records, block structure, Merkle trees, hash-chain validation, digital signatures, tamper detection, and persistence (PRD Epic 2).

> Updated 2026-10-20 (v1.4 implementation-alignment pass): Aligned with the committed Epic 2 code and use cases v1.4. Section 4: the per-block check order is hash, link, difficulty (PoW only), merkle, signature, structural, quorum (PBFT only), so precedence-dependent expectations changed (an unmined block with a bad signature reports `"difficulty"`; TC-4.19 middle-block tamper reports `"signature"` at the middle block); thresholds now use `ValidatorSet.quorum = floor((n+f)/2)+1` (= `2f+1` for `n = 3f+1`) instead of a hard-coded `2f+1`; PBFT commit votes are domain-separated `{node_id, signature}` entries; new rows TC-4.29 to TC-4.42 (exactly-one consensus parameter, fail-closed on missing parameter, PoW difficulty range, proposer-signature replay, member/key-once voting, oversize commit lists, `ValidatorSet` construction, check precedence, retired members). Section 7: expectations aligned with the tamper suite's scenario/layer/`failure_type` table (TC-7.1 `"merkle"`, TC-7.2 `"hash"`, TC-7.4 `"link"`, TC-7.5 `"hash"`, TC-7.6 split into `"signature"` at the middle block / `"link"` at the next block when the node key is compromised, TC-7.7 `"signature"` exclusively); new rows TC-7.11 to TC-7.13 (PBFT quorum tamper, untouched-chain control). Section 8: TC-8.3 now covers the explicit-initialization (`allow_fresh`) path; TC-8.4, 8.5, 8.7, 8.8 tightened; new rows TC-8.11 to TC-8.22 (missing chain file fails closed, deleted file not reset to genesis, strict decoding, SQLite schema check, atomic save, symlink/non-regular file, write errors, encrypted PEM, lock, rollback limitation).

Every UC scenario in `blockchain_core_use_cases.md` (v1.4) is mapped below. Given this thesis's central contribution, extra weight is given to: canonical serialization correctness (FR-4), Merkle domain separation / no duplicate-leaf collision (FR-5), genesis determinism across independently-started nodes (FR-1), `proposer_signature` covering block-level fields (catches tip-block tampering, not just record-level tampering — M-1), the time-aware key resolver (`resolve_node_key`/`resolve_issuer_key` with rotation via `retired_at`), duplicate-hash rejection scope (finalized blocks AND pending batch/mempool), PoW difficulty-target verification, PBFT `commit_signatures` quorum verification (proposal-time and chain-sync-time), and correctness of every `failure_type` value.

---

## 1. Create and Sign a Document Record (UC-1)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| TC-1.1 | UC-1 | Sign a well-formed `{document_hash, issuer_id, issued_at, metadata}` with a valid `IssuerKeyPair` | Returns a `DocumentRecord` with a `signature` field that verifies successfully against the `IssuerKeyPair` public key (UC-6) |
| TC-1.2 | UC-1-A | Supply raw document bytes instead of a pre-computed hash | System computes SHA-256 internally, then proceeds identically to TC-1.1 |
| TC-1.3 | UC-1-B | Supply an optional `ipfs_cid` value | Record stores the `ipfs_cid`; omitting it defaults to null/absent, never required |
| TC-1.4 | UC-1-E1 | Hash string of wrong length (e.g., 63 or 65 hex chars) | Rejected with a validation error; no record created |
| TC-1.5 | UC-1-E1 / UC-1-EC3 | Hash string of correct length (64 chars) but containing non-hex characters (e.g. uppercase `G`, punctuation) | Rejected with the same malformed-hash validation error as TC-1.4 |
| TC-1.6 | UC-1-E2 | `IssuerKeyPair` private key file missing/corrupted at signing time | Returns a signing error; no partially-signed record is returned |
| TC-1.7 | UC-1-E3 | Request missing `document_hash`, `issuer_id`, or `issued_at` (each tested independently) | Rejected with a validation error identifying the specific missing field |
| TC-1.8 | UC-1-EC1 | The same document hash is passed to this function twice (record-creation layer only, no chain-wide check here) | Both calls succeed independently at this layer — this function performs no duplicate check; chain-wide + pending-batch duplicate rejection is verified separately in `consensus_network_test_cases.md` (TC-4.10/TC-4.11) |
| TC-1.9 | UC-1-EC2 | Very large metadata payload (e.g., a long free-text title, no explicit size cap at this layer) | Accepted; no arbitrary size limit imposed here (bounded only by Epic 3's server-enforced cap, tested separately) |
| TC-1.10 | UC-1 (NFR) | Sign the same record twice with an ECDSA P-256 key and once with an RSA ≥2048-bit key | Both algorithms produce a signature that independently verifies via UC-6's auto-dispatch |

---

## 2. Build a Block from a Batch of Document Records — Merkle Construction (UC-2)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| TC-2.1 | UC-2 | Build a block from a batch of N ≥ 2 valid signed records | Returns a candidate `Block` with hashed preimage (`index`, `timestamp`, `previous_hash`, `merkle_root`, `proposer_id`, `algorithm`, `sealed_consensus`) populated, `document_records` stored separately (not part of the preimage bytes), and `block_hash` computed over the preimage only |
| TC-2.2 | UC-2 step 3 | Compute a leaf hash for a document record | Leaf hash equals `H(0x00 \|\| canonical_bytes(record))` exactly (RFC 6962-style leaf domain separation) |
| TC-2.3 | UC-2 step 4 | Compute an internal Merkle node from two child hashes | Internal hash equals `H(0x01 \|\| left_hash \|\| right_hash)` exactly (domain-separated internal-node hashing) |
| TC-2.4 | UC-2 step 4 | Build a tree with an odd number of nodes at some level | The unpaired node is promoted unchanged to the next level; it is never paired with a duplicate of itself |
| TC-2.5 | UC-2 (FR-5 collision resistance) | Construct a Merkle tree over a batch where a naive last-leaf-duplication scheme would produce a CVE-2012-2459-class collision (e.g., an odd-count batch crafted so duplicating the last leaf yields the same root as a different, extended batch) | The domain-separated construction produces a DIFFERENT root than the naive-duplication construction would, demonstrating the collision is structurally prevented |
| TC-2.6 | UC-2-A | Build a block from a single-document batch (N=1) | `merkle_root` equals the domain-separated leaf hash itself (`H(0x00 \|\| record_bytes)`); independently verifiable via UC-5 |
| TC-2.7 | UC-2-B | Build a tree where multiple levels each have an odd count | The promotion rule applies consistently at every level; the resulting root is still correctly and independently verifiable by a Merkle proof (cross-ref UC-5) |
| TC-2.8 | UC-2-E1 | Attempt to build a block from an empty batch (zero records) | Rejected; a block cannot be built with no data (genesis is a separate reserved case, not produced via this flow) |
| TC-2.9 | UC-2-E2 | Batch contains one record whose signature fails verification (UC-6) | Entire batch build is rejected; the response identifies which record/index failed rather than silently dropping it |
| TC-2.10 | UC-2-E3 | Batch contains two records with the identical `document_hash` | Batch build is rejected outright — never silently deduplicated or accepted |
| TC-2.11 | UC-2-EC1 | Build a block from a batch of several hundred documents | Build completes in better-than-O(n²) time and produces a correct, independently-verifiable root |
| TC-2.12 | UC-2-EC2 | Attempt to build a batch containing genuinely duplicate leaves (bypassing the normal caller, if reachable at all) | Rejected per TC-2.10's path; documents that this state is otherwise structurally unreachable in normal operation |
| TC-2.13 | UC-2-EC3 (FR-4) | Build the identical block preimage structure twice (or via two separate implementations of the canonical encoder) | Both produce byte-identical canonical serialization and therefore an identical `block_hash`/leaf hash |

---

## 3. Append Block to Chain — Hash-Chain Linking (UC-3)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| TC-3.1 | UC-3 | Append a valid candidate block whose `previous_hash` matches the current tip and whose `index` is `tip.index + 1` | Chain length increases by one; new block becomes the tip; persistence is triggered |
| TC-3.2 | UC-3-A | Construct the genesis block with no configuration beyond the shared constants | `index = 0`, `timestamp = GENESIS_TIMESTAMP_MS`, `previous_hash = "0"*64`, `merkle_root = GENESIS_MERKLE_ROOT`, `algorithm = "genesis"` (never `"pow"`/`"pbft"`), `sealed_consensus = {}`, `proposer_id = null`, `proposer_signature = null` |
| TC-3.3 | UC-3-E1 | Attempt to append a candidate whose `previous_hash` no longer matches the current tip (e.g., another block appended concurrently) | Append is rejected; caller must rebuild the candidate against the new tip |
| TC-3.4 | UC-3-E2 | Attempt to append a candidate whose `index` skips ahead of `tip.index + 1` | Append is rejected |
| TC-3.5 | UC-3-E2 | Attempt to append a candidate whose `index` duplicates an existing index | Append is rejected |
| TC-3.6 | UC-3-EC1 | Two append attempts race for the same next index concurrently | Atomic check-and-append semantics ensure only one succeeds; the loser is rejected per TC-3.3/TC-3.4 and must resync |
| TC-3.7 | UC-3-EC2 | Start two independent node processes with no shared network communication, using only the shared genesis constants | Both nodes independently construct byte-identical genesis blocks and compute an identical `block_hash` (directly verifies C-1 closure) |
| TC-3.8 | UC-3-EC2 | Start a node with a mismatched/customized genesis constant (deliberate misconfiguration) | Produces a different `block_hash` than the standard genesis; documented as an unsupported "per-node genesis policy," not a valid alternative configuration |

---

## 4. Validate Chain Integrity (UC-4)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| TC-4.1 | UC-4 primary | Validate a fully correct PoW chain of several blocks with a matching injected `expected_difficulty` and node/issuer resolver | Result is `{valid: true, first_invalid_index: null, failure_type: null}` |
| TC-4.2 | UC-4 primary | Validate a fully correct PBFT chain of several blocks with a matching injected `ValidatorSet` | Result is `{valid: true, first_invalid_index: null, failure_type: null}` |
| TC-4.3 | UC-4 step e (time-aware resolver) | Validate blocks proposed before and after a `NodeKeyPair` rotation, injecting a resolver whose `resolve_node_key(node_id, at_timestamp)` returns the OLD key for timestamps at/before rotation and the NEW key after | Both pre- and post-rotation blocks validate successfully against their respective resolver-returned keys |
| TC-4.4 | UC-4 step f (NEW v1.3 explicit checklist step) | Tamper a `DocumentRecord.signature` inside an otherwise-valid block | Chain reported invalid at that block's index with `failure_type = "signature"` — verifying this is now an explicit, always-performed check |
| TC-4.5 | UC-4 step g | Validate a chain where every block's `timestamp` is ≥ its predecessor's | Monotonicity check passes for all blocks |
| TC-4.6 | UC-4 step c (genuine PoW check) | Construct a block whose `block_hash` has the correct leading-zero-bit COUNT for its declared difficulty by coincidence of format but does NOT numerically satisfy the derived target when treated as an unsigned integer (target = `2^(256-d)`; valid iff `int(block_hash, 16) < target`; boundary: a hash exactly equal to the target is rejected, one below it is accepted; difficulty is resolved in single bits, not 4-bit hex-character steps) | Rejected — proves the check is a genuine numeric target comparison, not merely a superficial hash-format check |
| TC-4.7 | UC-4 step c (FR-24) | Construct a PoW block whose `block_hash` genuinely satisfies its own self-declared (arbitrarily low) `sealed_consensus.difficulty`, but that declared difficulty does not equal the injected `expected_difficulty` | Rejected with `failure_type = "difficulty"`, even though the block is internally self-consistent |
| TC-4.8 | UC-4 step h | Construct a PBFT block whose `commit_signatures[]` contains fewer than `ValidatorSet.quorum` (`floor((n+f)/2)+1`, which equals `2f+1` for `n = 3f+1`) distinct, validly-signing `ValidatorSet` members; also assert exactly `quorum` votes passes and `quorum - 1` fails, for `n = 3f+1` and for a larger `n` (e.g. `n = 5, f = 1` gives quorum 4, not 3) | Rejected with `failure_type = "quorum"` |
| TC-4.9 | UC-4 step h | Construct a PBFT block whose `commit_signatures[]` contains the SAME validator's signature repeated multiple times to pad the count toward the quorum | Duplicate signer is counted once; if the resulting distinct count is still below `ValidatorSet.quorum`, rejected with `failure_type = "quorum"` |
| TC-4.10 | UC-4 step h | Run the identical PBFT-quorum-deficient block through validation via three trigger paths: a live proposal, a chain-sync response, and a `GET /node/info` validity-cache refresh | All three paths reject with the identical `failure_type = "quorum"` result (same single checklist, no lighter check anywhere) |
| TC-4.11 | UC-4 (Genesis exemption) | Validate a chain whose genesis block has `algorithm = "genesis"` and sentinel `proposer_id`/`proposer_signature = null` | Genesis passes despite the sentinel values and is skipped by both the PoW difficulty check and the PBFT quorum check |
| TC-4.12 | UC-4-A | Validate only the new blocks appended since a trusted, already-validated tip (incremental mode), for a simple non-diverging extension | Result matches what a full from-genesis validation of the same chain would produce |
| TC-4.13 | UC-4-E1 | Tamper a block's `merkle_root` field directly (leaving `block_hash` stale/unrecomputed) | Reported invalid at that block's index with `failure_type = "hash"` |
| TC-4.14 | UC-4-E2 | Tamper a block's `previous_hash` field so it no longer matches the prior block's recomputed hash | Reported invalid at that block's index with `failure_type = "link"` |
| TC-4.15 | UC-4-E3 | Alter a block's document records without correspondingly updating `block_hash` in a self-consistent way | Reported invalid at that block's index with `failure_type = "merkle"` |
| TC-4.16 | UC-4-E4 | Chain contains a duplicate index | Reported invalid at that block's index with `failure_type = "structural"` |
| TC-4.17 | UC-4-E4 | Chain contains non-contiguous indices (a gap) | Reported invalid at that block's index with `failure_type = "structural"` |
| TC-4.18 | UC-4-E5 (M-1 closure, tip block) | Tamper the TIP block's `timestamp`, `index`, `previous_hash`, or `proposer_id`, and recompute `block_hash` (and, for PoW, re-mine) to stay self-consistent (no downstream block to contradict it) | Reported invalid at the tip index with `failure_type = "signature"` — `proposer_signature` verification fails because the attacker cannot re-sign with the legitimate `NodeKeyPair` |
| TC-4.19 | UC-4-E5 (M-1 closure, middle block) | Repeat TC-4.18 for a MIDDLE block instead of the tip (for PoW, with the edited block re-mined) | Reported invalid at that middle block's index with `failure_type = "signature"` — the tampered block's own signature is checked before the next block's link, so `"link"` is reported (at the NEXT block's index) only when the attacker holds the node key and re-signs — detection is position-independent |
| TC-4.20 | UC-4-E5 (document-level) | Tamper a `DocumentRecord`'s signature without touching any block-preimage field | Reported invalid at that block's index with `failure_type = "signature"`, distinct cause (document-level, not block-level) from TC-4.18/TC-4.19 but the same `failure_type` value |
| TC-4.21 | UC-4-E6 | Chain contains a block whose `timestamp` is strictly less than its predecessor's | Reported invalid at that block's index with `failure_type = "structural"` |
| TC-4.22 | UC-4-E7 | Construct a PoW block whose `block_hash` fails to satisfy the target derived from its own declared `sealed_consensus.difficulty` | Reported invalid at that block's index with `failure_type = "difficulty"` |
| TC-4.23 | UC-4-E8 | Construct a PBFT block whose `commit_signatures[]` never reaches `ValidatorSet.quorum` regardless of trigger path (mirrors TC-4.10 with an explicit negative assertion on all three paths) | All three paths (proposal, chain-sync, `GET /node/info` cache refresh) report `failure_type = "quorum"` |
| TC-4.24 | UC-4-EC1 | Pass a chain that is genuinely zero-length (no genesis at all) into the validation function | Rejected/fails closed as an invalid input state — "zero blocks" is never a valid chain to validate |
| TC-4.25 | UC-4-EC2 | Validate a single-block chain consisting only of genesis | Passes; only the block-hash/monotonicity checks are meaningfully applied; `proposer_id`/`proposer_signature` sentinel values are exempt |
| TC-4.26 | UC-4-EC3 | Validate a chain of several hundred blocks | Completes in better-than-O(n²) time without timing out |
| TC-4.27 | UC-4-EC4 | Corrupt only the FIRST block after genesis in an otherwise-valid long chain | `first_invalid_index` correctly reports that early block's index, not a later one |
| TC-4.27b | UC-4-EC4 | Corrupt only the TIP block in an otherwise-valid long chain | `first_invalid_index` correctly reports the tip's index |
| TC-4.28 | UC-4-EC5 | Inject a resolver that returns "not found" for a `proposer_id`/`issuer_id` that is genuinely unknown to it (never registered, not merely retired); repeat with a resolver that raises an exception | Verification fails closed with `failure_type = "signature"`; no unhandled exception, no default-to-valid |
| TC-4.29 | UC-4-E9 | Call validation with BOTH `expected_difficulty` and `validator_set` | Raises `InvalidChainInputError`; no `ValidationResult` is returned |
| TC-4.30 | UC-4-E9 | Call validation with a malformed `expected_difficulty` (0, 257, negative, `True`, non-int) or a `validator_set` that is not a `ValidatorSet` | Raises `InvalidChainInputError` |
| TC-4.31 | UC-4-EC6 | Validate a PoW block with neither parameter supplied; validate a PBFT block with neither parameter supplied | PoW block: `failure_type = "difficulty"`; PBFT block: `failure_type = "quorum"` — omitting a parameter never skips verification |
| TC-4.32 | UC-4-EC6 | Validate a chain mixing a `"pow"` block and a `"pbft"` block (one parameter supplied) | Invalid: the block of the other algorithm fails closed (`"difficulty"` or `"quorum"`) |
| TC-4.33 | UC-4 step c | Boundary of the difficulty range: `sealed_consensus.difficulty` of 1 and 256 as injected `expected_difficulty`; a declared difficulty that is not an `int` (e.g. a float or string) | Range `[1, 256]` accepted for the injected value; a non-integer declared difficulty is rejected with `"difficulty"`; `pow_target(d) = 2^(256-d)` for every `d` in range and raises `ValueError` outside it |
| TC-4.34 | UC-4 step h (replay) | PBFT block where `commit_signatures[]` includes an entry made from the block's `proposer_signature` (replayed as a vote) | The replayed signature does not count (it signs the preimage, not the domain-separated commit payload); the block is rejected with `"quorum"` if the remaining valid votes are below the quorum |
| TC-4.35 | UC-4 step h (domain separation) | Sign commit votes with `sign_commit` over `{"domain": "blockchain_core/pbft-commit/v1", "block_hash": ...}`; separately sign the bare `block_hash` / bare preimage and a different domain tag | Only votes over the exact commit payload count; votes under any other payload or domain are ignored |
| TC-4.36 | UC-4 step h (membership) | Commit votes from a `node_id` that is not in `ValidatorSet.members`, even with a valid signature from a resolvable key | Vote is not counted; `"quorum"` if the quorum is not otherwise reached |
| TC-4.37 | UC-4 step h (once per member / per key) | (a) the same member votes twice; (b) two different member ids whose resolver returns the SAME public key (misconfiguration) | Counted once per member and once per public key; neither case adds weight beyond a single vote |
| TC-4.38 | UC-4 step h (bounds) | (a) `commit_signatures[]` longer than `len(members)` while containing enough valid votes; (b) a PBFT block whose `proposer_id` is not a `ValidatorSet` member although it has a full quorum of valid votes | Both rejected with `"quorum"`; (a) also bounds the verification work an attacker can force |
| TC-4.39 | UC-4 step h (retired members) | A retired member listed in `members`, with the resolver returning its key for the block's timestamp vs. returning nothing for it | Its vote counts only while the resolver returns its key at `block.timestamp`; with no key the vote is dropped (fail closed) |
| TC-4.40 | UC-4-E9 (`ValidatorSet` construction) | Construct `ValidatorSet(members, n, f)` with: empty or non-`frozenset` members, a blank member id, negative `f`, `n < 3f+1`, `len(members) < n`; and valid sets with `len(members) > n` (accumulated retired members) | Invalid combinations raise `ValueError`; valid sets construct, and `quorum` is `floor((n+f)/2)+1` independent of how many members are listed |
| TC-4.41 | UC-4-EC7 (check precedence) | Blocks carrying two simultaneous defects, one per adjacent pair of layers: bad `block_hash` + bad link; bad link + unmined PoW; unmined PoW + bad Merkle root; bad Merkle root + bad signature; bad signature + bad structure (e.g. decreasing timestamp); bad structure + insufficient commits (PBFT) | Each case reports the EARLIER layer in the order hash, link, difficulty, merkle, signature, structural, quorum; an unmined block with a bad signature reports `"difficulty"` |
| TC-4.42 | UC-4 genesis / well-formedness | Genesis that differs from the frozen genesis in any field (including an attestation or batch field); a non-genesis block with wrongly-typed fields or an `algorithm` other than `"pow"`/`"pbft"`; a block with two records sharing a `document_hash` | Genesis mismatch: `"hash"` at position 0; wrongly-typed block / unknown algorithm / duplicate `document_hash` in a block: `"structural"` |

---

## 5. Generate and Verify a Merkle Inclusion Proof (UC-5)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| TC-5.1 | UC-5 | Generate a proof for a document hash present in an N-document block (N ≥ 2), then verify it against the block's stored `merkle_root` | Proof verifies as valid |
| TC-5.2 | UC-5-A | Verify a previously generated proof using only the leaf hash, proof path, and claimed `merkle_root` (no full block object available) | Verification succeeds identically to TC-5.1, without requiring the original block |
| TC-5.3 | UC-5-E1 | Request a proof for a document hash that is not among the block's records | Fails with a clear "not found" result — no crash, no false proof produced |
| TC-5.4 | UC-5-E2 | Alter one sibling hash in a valid proof's path before verification | Recomputed root does not match the claimed `merkle_root`; result is invalid |
| TC-5.5 | UC-5-E3 | Verify a proof generated for block A against block B's stored `merkle_root` | Result is invalid |
| TC-5.6 | UC-5-EC1 | Generate and verify a proof for a single-document block (N=1) | Proof path is empty; verification is a direct equality check against the leaf hash itself |
| TC-5.7 | UC-5-EC2 | Attempt to construct a proof scenario involving genuinely duplicate leaves within one batch | Documented as unreachable under normal operation since UC-2-E3 rejects such a batch at build time; test asserts the batch-build step itself already failed |
| TC-5.8 | UC-5-EC3 | Generate and verify a proof for a leaf/node that was the unpaired node promoted unchanged at an odd tree level | Verification correctly accounts for the promotion (no domain-separation hashing applied at that level for that node) and produces a valid result |

---

## 6. Verify a Document Record's Signature (UC-6)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| TC-6.1 | UC-6 | Verify a correctly signed `DocumentRecord` against the matching `IssuerKeyPair` public key | Returns `valid` |
| TC-6.2 | UC-6-A | Verify signatures produced with an ECDSA P-256 key and, separately, with an RSA key, without the caller specifying the algorithm | The function auto-dispatches based on the supplied public key's type and verifies both correctly |
| TC-6.3 | UC-6-E1 | Alter a single byte of an otherwise-valid signature | Verification fails (`invalid`) |
| TC-6.4 | UC-6-E2 | Alter each of `document_hash`, `issuer_id`, `issued_at`, and `metadata` individually, one at a time, post-signing | Verification fails (`invalid`) for each altered field independently |
| TC-6.5 | UC-6-E3 | Verify a record's signature using a public key belonging to a different issuer | Verification fails (`invalid`) |
| TC-6.6 | UC-6-E4 | Supply a malformed signature blob (wrong length/encoding) | Returns a handled `invalid` result; no unhandled exception raised |
| TC-6.7 | UC-6-EC1 | Verify a signature made with an old/superseded `IssuerKeyPair` against that old public key | Verification succeeds (no revocation/CRL mechanism exists — explicit documented scope limitation) |

---

## 7. Detect Tampering — Composite Defense-in-Depth (UC-7)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| TC-7.1 | UC-7 primary | Mutate a `DocumentRecord`'s metadata directly in persisted storage (JSON file and SQLite database), nothing recomputed, reload the chain with a NEW store instance, run validation | `valid = false`, no extendable chain; reported at the affected block's index with `failure_type = "merkle"` (detecting layer: Merkle root) |
| TC-7.2 | UC-7 primary | Mutate a block-level preimage field (`timestamp`/`index`/`previous_hash`) directly in storage, no rehash, reload, run validation | Reported at the affected block's index with `failure_type = "hash"` (detecting layer: block hash over the preimage) |
| TC-7.3 | UC-7 primary | For the same tampered document in TC-7.1, independently run Merkle-proof verification (UC-5) and `DocumentRecord` signature verification (UC-6) | Both independently report failure, demonstrating the dual-layer detection |
| TC-7.4 | UC-7-A | Tamper a middle block's `previous_hash` directly in storage and recompute that block's `block_hash` (so it stays self-consistent) | Caught via `failure_type = "link"` (UC-4-E2); without recomputing `block_hash` it is `"hash"` instead |
| TC-7.5 | UC-7-B | Plain edit (no recomputation) of a middle block and, separately, of the tip block, each with an otherwise-untouched chain | Both cases correctly identify the actual tampered block's index with `failure_type = "hash"` (see also TC-4.27/TC-4.27b) |
| TC-7.6 | UC-7-E1/EC1 (middle-block, sophisticated) | (a) Attacker mutates a MIDDLE block's content, recomputes its `block_hash` (and re-mines it, for PoW) without the node key; (b) same, but the attacker holds the compromised node key and re-signs the middle block | (a) `failure_type = "signature"` at the MIDDLE block's index (its own `proposer_signature` no longer verifies); (b) `failure_type = "link"` at the NEXT block's index (its `previous_hash` was computed against the original hash) — independent of the signature layer |
| TC-7.7 | UC-7-E1/EC1 (tip-block, sophisticated — central M-1 test) | Attacker mutates the TIP block's content and recomputes that block's own `block_hash` to match (re-mined for PoW; no downstream block exists to contradict it) | Caught exclusively via `proposer_signature` verification failing (`failure_type = "signature"`) — the attacker does not hold the legitimate `NodeKeyPair` private key, so the recomputed hash cannot carry a valid signature. Control: with a compromised node key and a re-signed tip, this layer cannot detect the edit (documented) |
| TC-7.8 | UC-7-E1/EC1 (document-record field) | Attacker mutates only a `DocumentRecord` field (not any block-preimage field), with the Merkle root, block hash, PoW and block signature all redone using a compromised node key | The record's `IssuerKeyPair` signature (UC-6) independently catches the tamper as a second, orthogonal layer: `failure_type = "signature"` |
| TC-7.9 | UC-7-E1/EC1 (attacker re-signs with own key) | Attacker mutates content and re-signs the block/record with the ATTACKER's OWN key pair(s) (not the legitimate node's/issuer's) | Verification still fails against the original, known public keys (`failure_type = "signature"`) — the trust anchor is the known key, never anything derivable from the tampered data |
| TC-7.10 | UC-7-EC2 (direct M-1 acceptance criterion) | Tamper ONLY the tip block's `Block.timestamp`, with a self-consistently recomputed `block_hash` (re-mined for PoW), and no document-record change | Hash-chain checks (`"hash"`/`"link"`) pass; `proposer_signature` verification fails with `failure_type = "signature"`, demonstrating block-level tamper detection independent of any document-record signature |
| TC-7.11 | UC-7 (PBFT) | PBFT chain: reduce a block's `commit_signatures[]` below `ValidatorSet.quorum` in persisted storage, reload | `failure_type = "quorum"` at that block's index |
| TC-7.12 | UC-7 (PBFT) | PBFT tip edited, `block_hash` recomputed and `proposer_signature` re-made with a valid key, commits left unchanged (stale) | `failure_type = "quorum"` — each commit vote signs `{domain, block_hash}`, so a rehashed block leaves stale commits; the proposer signature cannot be replayed as a vote |
| TC-7.13 | UC-7 (control) | Reload an untouched chain (both backends) through the same save/tamper-harness path | Restores valid; confirms the harness itself does not cause failures |

---

## 8. Persist and Reload Chain and Keys — Restart Durability (UC-8)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| TC-8.1 | UC-8 primary | Save a chain, `IssuerKeyPair`, and `NodeKeyPair`, then restart the process and reload | Reloaded state is identical and verifiable (chain passes validation, keys sign/verify identically to before) |
| TC-8.2 | UC-8-A | Repeat TC-8.1 against both a JSON backend and a SQLite backend (one store contract; same canonical per-block encoding, format `blockchain_core.chain` version 2) | Both backends produce byte-for-byte equivalent verifiable state after reload; restoring from either yields an identical chain |
| TC-8.3 | UC-8-E1 (CHANGED v1.4) | Start a node with no prior chain-store file present, with EXPLICIT initialization (`allow_fresh=True`) — both backends, and via the full node-state restore | Chain starts as the single deterministic, shared genesis block (a fixed constant), not a crash or undefined state; the restore itself creates no file on disk; the returned chain can be extended |
| TC-8.4 | UC-8-E2 | Start a node whose chain-store file is truncated, empty, random bytes, or contains invalid JSON/SQLite structure (both backends) | Startup fails with `ChainStoreCorruptedError` (a clear, specific message); system does NOT silently proceed with a partial/corrupt chain, and an empty/garbage file is never treated as "fresh"; the error is both a `ChainStoreError` and a `ValueError` |
| TC-8.5 | UC-8-E3 | Start a node whose chain file exists but whose `IssuerKeyPair` key file is missing | Fails fast with `IssuerKeyUnavailableError` and an explicit "issuer key material unavailable" message (typed issuer-key loader); does not silently generate a new key pair or create any file |
| TC-8.6 | UC-8-E4 | Load a chain that was externally tampered with while the process was down | Chain is reported invalid (via UC-4's result, with failing index + `failure_type`) at startup; node refuses to extend the broken chain until acknowledged/resolved |
| TC-8.7 | UC-8-E5 | Start a node whose chain file exists but whose `NodeKeyPair` key file is missing | Fails fast with `NodeKeyUnavailableError` and an explicit "node key material unavailable" message, distinct wording from TC-8.5's issuer-key error; with both keys missing the issuer error is reported first; nothing is regenerated |
| TC-8.8 | UC-8-EC1 / UC-8-E8 | Open a second store on the same chain path while the first is open (same process; both backends), then after `close()` / context-manager exit; and a store on a different path | Second store raises `ChainStoreLockedError` (exclusive lock on `<path>.lock`); succeeds after the first is closed; the lock is per path; the single-writer requirement is documented in the module |
| TC-8.9 | UC-8-EC2 | Inspect filesystem permissions of generated `IssuerKeyPair`/`NodeKeyPair` key files | Key files are not world-readable (best-effort operational check: private key `0600`, public key `.pub` `0644`, directory `0700`; on Windows POSIX mode bits do not restrict access, so the key directory must be protected with an ACL instead) |
| TC-8.10 | UC-8-EC3 (NEW v1.3) | Restart a node with a changed `expected_difficulty` against its OLD persisted chain (mined at the previous difficulty) | Startup validation correctly FAILS with `failure_type = "difficulty"` — documented as expected/by-design behavior (also stated in the chain-store module documentation), not a bug |
| TC-8.11 | UC-8-E1 (CHANGED v1.4) | Restore with no persisted chain and WITHOUT `allow_fresh` (default), both backends | Raises `ChainStoreMissingError`; no chain is returned and no file is created |
| TC-8.12 | UC-8-E1 (NEW v1.4) | Save a chain, delete the chain file, restart without `allow_fresh` | Raises `ChainStoreMissingError` — a deleted chain file is NOT silently reset to genesis |
| TC-8.13 | UC-8-E2 (strict decoding) | Decode documents with: wrong `format`, unsupported/non-int `version` (e.g. 1 or 3), missing/extra keys at document, block, record or commit level, wrong types, empty `blocks`, a float anywhere (including record metadata), `NaN`/`Infinity`, duplicate object keys, nesting deeper than the limit, a non-object commit entry (version 1 style plain-string vote) | Every case raises `ChainStoreCorruptedError` (never `RecursionError`/`TypeError`); decoding checks shape only — a well-formed but tampered block decodes fine and is judged later by validation (TC-8.6) |
| TC-8.14 | UC-8-E2 (SQLite schema) | Open a SQLite store whose database has a planted trigger, view, index or extra table (e.g. a trigger that deletes rows on save), wrong metadata, non-contiguous block positions, a non-blob row, or no blocks | `ChainStoreCorruptedError`; `save` always rebuilds a fresh database in a temporary file and moves it into place, never reusing the old file's schema |
| TC-8.15 | UC-8 primary (atomic save) | (a) JSON save leaves no temporary files behind; (b) a failing save keeps the previous file intact; (c) save overwrites previous content; (d) a block that cannot be encoded never touches the file | All hold for both backends; a crash or failure never leaves a half-written store |
| TC-8.16 | UC-8-E2 (non-regular file) | Place a directory, a dangling symlink, or a symlink to a valid store at the chain path (both backends) | `ChainStoreCorruptedError` — never followed, never mistaken for "no chain yet" (so not a fresh start) |
| TC-8.17 | UC-8-E6 (NEW v1.4) | Make a save fail for I/O reasons (e.g. unwritable target or injected `OSError`/SQLite error), both backends | Raises `ChainStoreWriteError` (not a corruption error); the previously persisted chain is intact and temporary files are removed |
| TC-8.18 | UC-8-E7 (NEW v1.4) | Load an `IssuerKeyPair`/`NodeKeyPair` from a file that is garbage, a passphrase-encrypted PEM, or an unsupported key type | Raises `KeyStoreCorruptedError` (not a raw `TypeError`/library exception); no key is regenerated |
| TC-8.19 | UC-8 primary (PBFT) | Save and restore a PBFT chain with `commit_signatures` (entries `{node_id, signature}`), both backends; tamper the persisted commit set and restore | Commit votes round-trip with their `node_id`s; the tampered commit set restores as invalid with `failure_type = "quorum"` and no extendable chain |
| TC-8.20 | UC-8 primary (restore contract) | Restore a valid PoW chain and extend it; restore a chain with a failing validation | Valid: extendable `Chain`; invalid: `chain` is `None` and the result carries the failing index and `failure_type`; `RestoredChain`/`NodeState` are immutable |
| TC-8.21 | UC-8-EC4 (NEW v1.4, documented limitation) | Replace the persisted chain with a valid older prefix of the same chain (truncation at a block boundary) | Restores as VALID — rolled-back/truncated chains are not detectable locally; the test documents the limitation and Epic 3's chain sync before serving is the mitigation (cross-ref Epic 3 sync test cases) |
| TC-8.22 | UC-8-E7 (key-file safety) | Save a key pair where the target already exists, without and with `force`; plant a symlink at the key path | Without `force`: `KeyStoreExistsError` and no overwrite; with `force`: atomically replaced; a planted symlink is never followed; files are created with restrictive permissions |

---

## 9. Generate and Manage Key Pairs — IssuerKeyPair and NodeKeyPair (UC-9)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| TC-9.1 | UC-9 primary | Generate a new `IssuerKeyPair` with the default algorithm (ECDSA P-256) | Key pair is generated, private key persisted to its dedicated store file, public key returned |
| TC-9.2 | UC-9-A | Generate a key pair explicitly requesting RSA (≥2048-bit) | Key pair generated using RSA as requested |
| TC-9.3 | UC-9-B | Generate a `NodeKeyPair` for the same node that already has an `IssuerKeyPair` | Persisted to a separate dedicated store file; public key exposed for `ValidatorSet`/`PeerInfo` use; never identical key material to the `IssuerKeyPair` |
| TC-9.4 | UC-9-E1 | Attempt to generate a key pair (either type) when a key file already exists at the target path, without a force flag | Existing key is NOT overwritten; an explicit confirmation/force flag is required |
| TC-9.5 | UC-9-E2 | Request RSA key generation with an insufficient size (e.g., 1024-bit) | Rejected; the 2048-bit minimum floor is enforced for both key-pair types |
| TC-9.6 | UC-9-E3 | Request a `NodeKeyPair` with an algorithm/parameter combination the chain-validation layer cannot dispatch for signature verification | Rejected rather than persisting an unusable node identity |
| TC-9.7 | UC-9-EC1 | Regenerate an `IssuerKeyPair` after prior issuances exist under the old key | Old signatures remain verifiable against the old (superseded) public key; new issuances use the new key; no built-in rotation-linking mechanism (documented limitation) |
| TC-9.8 | UC-9-EC2 | Rotate a `NodeKeyPair` after prior blocks were proposed/signed under the old key, with the old `ValidatorSet` entry marked `retired_at` | Old `proposer_signature`s remain verifiable via the time-aware resolver resolving to the OLD key for old block timestamps; a stale ACTIVE entry still pointing at the old key would cause new proposals to fail signature verification (negative check) |

---

## 10. Canonical Serialization & Cross-Implementation Determinism (FR-4, cross-cutting)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| TC-CS.1 | FR-4 (test vectors) | Run the fixed set of test vectors (input struct → expected canonical bytes → expected SHA-256 hash) through the canonical encoder | Every vector's canonical bytes and resulting hash match the documented expected values exactly |
| TC-CS.2 | FR-4 (cross-implementation) | Canonicalize the same block preimage / `DocumentRecord` / Merkle leaf structure via two independent code paths (or two separate runs) | Byte-identical canonical serialization and identical SHA-256 hash in both cases |
| TC-CS.3 | FR-4 (single shared utility) | Inspect every hashing/signing call site (block preimage, `DocumentRecord`, Merkle leaves) | All call sites use the single shared canonical-encoding utility; no parallel/duplicated encoding logic exists |
| TC-CS.4 | FR-4 (timestamp encoding) | Attempt to canonicalize a structure whose timestamp is an ISO string or a float instead of an integer epoch-ms value | Rejected or normalized per spec — canonical bytes never contain a non-integer-epoch-ms timestamp representation |
| TC-CS.5 | FR-4 (hex casing) | Attempt to canonicalize a structure containing an uppercase-hex hash/signature/public-key field | Rejected or normalized to lowercase hex per spec — canonical bytes never contain uppercase hex |
